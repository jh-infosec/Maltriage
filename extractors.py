"""
maltriage extraction engine.

Evaluates one file against the active config and returns the data extracted
plus any findings that should be raised.

Every extractor implements the same interface: take a path, a shared context
and the config, return a dict of data. Findings are derived from that data in
a separate step, so adding a heuristic never changes what gets extracted.

All thresholds are read from the config with `config.get(key, default)` rather
than hard-coded, so behaviour is tunable without editing this module.
"""

from __future__ import annotations
import hashlib
import math
from abc import ABC, abstractmethod
from collections import Counter
from pathlib import Path
from typing import Any

from models import mk_finding

HASH_CHUNK_BYTES = 1024 * 1024

try:  # optional, needs a C library, so not a hard requirement
    import ssdeep

    HAVE_SSDEEP = True
except ImportError:
    HAVE_SSDEEP = False


class Extractor(ABC):
    """One analysis capability.

    Unlike the Shadowfax detectors, which share a single ordered pass over an
    actor's history, extractors are independent of each other. That is what
    lets the pipeline isolate a failure in one without losing the rest.
    """

    name: str = "unnamed"

    def applies_to(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> bool:
        """Return False to skip this extractor for this file."""
        return True

    @abstractmethod
    def extract(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
        """Return raw analysis data. Prefer partial data over raising."""

    def findings(self, data: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        """Turn raw data into analyst-facing observations. Optional."""
        return []


# file type

class FileTypeExtractor(Extractor):
    """Identify the format from magic bytes.

    Deliberately dependency-free. `python-magic` needs libmagic installed,
    which is friction for anyone cloning the repo, and a small signature table
    covers the formats that matter for triage.

    Publishes `family` to the context so format-specific extractors can gate
    on it.
    """

    name = "filetype"

    def extract(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
        with path.open("rb") as fh:
            header = fh.read(64)

        label, family = "unknown", "unknown"
        for sig in config.get("signatures", []):
            offset, magic_hex, lbl, fam = sig
            magic = bytes.fromhex(magic_hex)
            if header[offset : offset + len(magic)] == magic:
                label, family = lbl, fam
                break

        ctx["family"] = family
        return {
            "magic_label": label,
            "family": family,
            "extension": path.suffix.lower(),
            "header_hex": header[:16].hex(),
        }

    def findings(self, data: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        if data["family"] == "unknown":
            out.append(mk_finding(self.name, "unrecognised_format",
                f"no signature match, first bytes {data['header_hex']}", "info"))
        executable = data["family"] in config.get("executable_families", [])
        masquerading = data["extension"] in config.get("document_extensions", [])
        if executable and masquerading:
            out.append(mk_finding(self.name, "extension_mismatch",
                f"content is {data['magic_label']} but the extension is "
                f"'{data['extension']}', masquerading as a document", "high"))
        return out


# hashes

class HashExtractor(Extractor):
    """Cryptographic and fuzzy hashes.

    Streams the file rather than loading it whole, so this behaves the same on
    a 400 MB installer as on a 12 KB dropper.
    """

    name = "hashes"

    def extract(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
        digests = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
        chunk_size = config.get("hash_chunk_bytes", HASH_CHUNK_BYTES)
        with path.open("rb") as fh:
            while chunk := fh.read(chunk_size):
                for d in digests.values():
                    d.update(chunk)

        result: dict[str, Any] = {k: v.hexdigest() for k, v in digests.items()}
        result["ssdeep"] = ssdeep.hash_from_file(str(path)) if HAVE_SSDEEP else None

        # sha256 is the lookup key for enrichment in v0.5
        ctx["sha256"] = result["sha256"]
        return result


# entropy

def shannon(data: bytes) -> float:
    """Shannon entropy in bits per byte. Range 0.0 (uniform) to 8.0 (random)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class EntropyExtractor(Extractor):
    """Whole-file and windowed Shannon entropy.

    High entropy alone proves nothing. A ZIP scores high and so does a
    legitimate installer. The useful signal is shape: a mostly-low-entropy
    file containing one high-entropy region is the classic packed-stub layout,
    which is why `entropy_hotspot` scores higher than `high_file_entropy`.

    Thresholds are heuristics tuned for recall over precision. Triage exists
    to decide what deserves a human, not to give verdicts.
    """

    name = "entropy"

    def extract(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
        window = config.get("entropy_window_bytes", 8192)
        threshold = config.get("entropy_window_threshold", 7.5)
        blob = path.read_bytes()

        windows: list[float] = []
        for offset in range(0, len(blob), window):
            chunk = blob[offset : offset + window]
            if len(chunk) < window // 2:  # ignore a stubby tail window
                continue
            windows.append(shannon(chunk))

        return {
            "overall": round(shannon(blob), 4),
            "window_size": window,
            "window_count": len(windows),
            "window_max": round(max(windows), 4) if windows else None,
            "window_mean": round(sum(windows) / len(windows), 4) if windows else None,
            "high_entropy_windows": sum(1 for w in windows if w >= threshold),
        }

    def findings(self, data: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        file_threshold = config.get("entropy_file_threshold", 7.2)
        window_threshold = config.get("entropy_window_threshold", 7.5)

        if data["overall"] >= file_threshold:
            out.append(mk_finding(self.name, "high_file_entropy",
                f"whole-file entropy {data['overall']} at or above {file_threshold}, "
                "consistent with packing, compression or encryption", "low"))

        # the interesting case: low overall, but a hot region inside
        if data["overall"] < file_threshold and data["high_entropy_windows"] > 0:
            out.append(mk_finding(self.name, "entropy_hotspot",
                f"{data['high_entropy_windows']} window(s) at or above {window_threshold} "
                "in an otherwise low-entropy file, possible embedded packed or "
                "encrypted payload", "medium"))
        return out


def default_extractors() -> list[Extractor]:
    """Order matters: file type first so later extractors can gate on it."""
    return [FileTypeExtractor(), HashExtractor(), EntropyExtractor()]
