"""
maltriage extraction engine.

Evaluates one file against the active config and returns the data extracted
plus any findings that should be raised.

Every extractor implements the same interface: take a path, a shared context
and the config, return a dict of data. Findings are derived from that data in
a separate step, so adding a heuristic never changes what gets extracted.

Config is read through the validated accessors in sample_data, never with a
bare `.get`, so a bad value falls back to a default instead of silently
producing a wrong answer.
"""

from __future__ import annotations
import hashlib
import math
from abc import ABC, abstractmethod
from collections import Counter
from pathlib import Path
from typing import Any

from models import mk_finding
from sample_data import config_int, config_list, config_ratio

HASH_CHUNK_BYTES = 1024 * 1024
BYTE_VALUES = 256


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
        for signature in config_list(config, "signatures", []):
            # A malformed entry is skipped rather than aborting the extractor,
            # so one bad signature cannot cost every later one. validate_config
            # reports it separately.
            if not isinstance(signature, (list, tuple)) or len(signature) != 4:
                continue
            offset, magic_hex, lbl, fam = signature
            if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
                continue
            try:
                magic = bytes.fromhex(str(magic_hex))
            except ValueError:
                continue
            if magic and header[offset : offset + len(magic)] == magic:
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
            detail = (f"no signature match, first bytes {data['header_hex']}"
                      if data["header_hex"] else "file is empty, nothing to identify")
            out.append(mk_finding(self.name, "unrecognised_format", detail, "info"))
        executable = data["family"] in config_list(config, "executable_families", [])
        masquerading = data["extension"] in config_list(config, "document_extensions", [])
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
        # Validated, because a chunk size of 0 makes read() return empty
        # immediately and every digest becomes the hash of an empty file.
        chunk_size = config_int(config, "hash_chunk_bytes", HASH_CHUNK_BYTES)
        with path.open("rb") as fh:
            while chunk := fh.read(chunk_size):
                for d in digests.values():
                    d.update(chunk)

        result: dict[str, Any] = {k: v.hexdigest() for k, v in digests.items()}
        result["ssdeep"] = _ssdeep_hash(path)

        # sha256 is the lookup key for enrichment in v0.5
        ctx["sha256"] = result["sha256"]
        return result


try:  # optional, needs a C library, so not a hard requirement
    import ssdeep

    def _ssdeep_hash(path: Path) -> str | None:
        return ssdeep.hash_from_file(str(path))
except ImportError:
    def _ssdeep_hash(path: Path) -> str | None:
        return None


# entropy

def shannon(data: bytes) -> float:
    """Shannon entropy in bits per byte. Range 0.0 (uniform) to 8.0 (random)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def expected_random_entropy(n: int) -> float:
    """What uniformly random data of length `n` actually scores.

    The plug-in entropy estimator is biased low on short samples: 375 random
    bytes cannot fill 256 buckets evenly, so they measure about 7.42 rather
    than 8.0. A fixed threshold of 7.5 is therefore unreachable at that size,
    which is exactly why v0.1.0 never flagged a small packed file.

    This is the Miller bias correction, log2(K) - (K-1)/(2n ln2), floored by
    log2(n) since n samples cannot express more than log2(n) bits. Measured
    against random data it predicts within 1.5% from 128 bytes upward.

    Scoring entropy as a ratio of this reference makes one threshold correct
    at every window size.
    """
    if n <= 1:
        return 0.0
    corrected = math.log2(BYTE_VALUES) - (BYTE_VALUES - 1) / (2 * n * math.log(2))
    return max(0.0, min(math.log2(n), corrected))


def _ratio(observed: float, n: int) -> float:
    reference = expected_random_entropy(n)
    return round(observed / reference, 4) if reference > 0 else 0.0


class EntropyExtractor(Extractor):
    """Whole-file and windowed Shannon entropy.

    High entropy alone proves nothing. A ZIP scores high and so does a
    legitimate installer. The useful signal is shape: a mostly-low-entropy
    file containing one high-entropy region is the classic packed-stub layout,
    which is why `entropy_hotspot` scores higher than `high_file_entropy`.

    The window shrinks for small files. At the fixed 8192 bytes of v0.1.0 a
    3 KB dropper produced no windows at all and was scored `info`, so the
    hotspot check was blind in the size range where it matters most.

    Thresholds are heuristics tuned for recall over precision. Triage exists
    to decide what deserves a human, not to give verdicts.
    """

    name = "entropy"

    def _window_size(self, size: int, config: dict[str, Any]) -> int:
        configured = config_int(config, "entropy_window_bytes", 8192)
        minimum = config_int(config, "entropy_min_window_bytes", 256)
        target = config_int(config, "entropy_target_windows", 8)
        # Aim for `target` windows, never below `minimum`, never above the
        # configured size.
        return max(minimum, min(configured, size // target if size else configured))

    def extract(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
        blob = path.read_bytes()
        size = len(blob)
        window = self._window_size(size, config)

        windows: list[float] = []
        for offset in range(0, size, window):
            chunk = blob[offset : offset + window]
            if len(chunk) < window // 2:  # ignore a stubby tail window
                continue
            windows.append(shannon(chunk))

        overall = shannon(blob)
        window_max = max(windows) if windows else None
        window_ratio_threshold = config_ratio(config, "entropy_window_ratio", 0.94)
        hot = sum(1 for w in windows if _ratio(w, window) >= window_ratio_threshold)

        return {
            "overall": round(overall, 4),
            "overall_ratio": _ratio(overall, size),
            "window_size": window,
            "window_size_configured": config_int(config, "entropy_window_bytes", 8192),
            "window_count": len(windows),
            "window_max": round(window_max, 4) if window_max is not None else None,
            "window_max_ratio": _ratio(window_max, window) if window_max is not None else None,
            "window_mean": round(sum(windows) / len(windows), 4) if windows else None,
            "high_entropy_windows": hot,
        }

    def findings(self, data: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        file_ratio = config_ratio(config, "entropy_file_ratio", 0.90)
        window_ratio = config_ratio(config, "entropy_window_ratio", 0.94)

        if data["overall_ratio"] >= file_ratio:
            out.append(mk_finding(self.name, "high_file_entropy",
                f"whole-file entropy {data['overall']} is {data['overall_ratio']} of what "
                "random data of this length reaches, consistent with packing, "
                "compression or encryption", "low"))

        # the interesting case: low overall, but a hot region inside
        if data["overall_ratio"] < file_ratio and data["high_entropy_windows"] > 0:
            out.append(mk_finding(self.name, "entropy_hotspot",
                f"{data['high_entropy_windows']} of {data['window_count']} window(s) at or "
                f"above {window_ratio} of random, in an otherwise low-entropy file, "
                "possible embedded packed or encrypted payload", "medium"))
        return out


def default_extractors() -> list[Extractor]:
    """Order matters: file type first so later extractors can gate on it."""
    return [FileTypeExtractor(), HashExtractor(), EntropyExtractor()]
