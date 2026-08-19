"""
maltriage extraction engine.

Evaluates one file against the active config and returns the data extracted
plus any findings that should be raised.

Extractors come in three kinds, and the difference is where their bytes come
from rather than what they do:

  Header extractors implement `read_header` and are handed the first few
  kilobytes, which the pipeline has already read. They run first and publish
  to `ctx`, so anything after them can gate on what they found.

  Stream extractors implement `begin`, `feed` and `finish`. The pipeline reads
  the file once and hands every chunk to all of them, including the bytes that
  were used as the header, so a 400 MB sample is read one time and never held
  whole in memory.

  Random-access extractors implement `parse` and open the sample themselves.
  They exist because structure like a PE import table sits at an offset that
  is not known until earlier structure has been read, which no forward pass
  can reach. They still may not hold the sample whole.

v0.1.1 gave every extractor the path and let it read for itself. That cost
three opens and two full reads of every sample, and made peak memory track
sample size because entropy called `read_bytes()`. The single pass exists to
make corpus-scale work possible in v0.6.

A stream extractor must keep its own memory bounded. Buffering the chunks it
is handed would reintroduce exactly the problem this design removes.

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

BYTE_VALUES = 256


class Extractor(ABC):
    """Base for every analysis capability.

    Unlike the Shadowfax detectors, which share a single ordered pass over an
    actor's history, extractors do not see each other's work except through
    `ctx`. That is what lets the pipeline isolate a failure in one without
    losing the rest.
    """

    #: Key this extractor's output is filed under in `report.data`.
    name: str = "unnamed"

    def applies_to(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> bool:
        """Return False to skip this extractor for this file."""
        return True

    def findings(self, data: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        """Turn raw data into analyst-facing observations. Optional."""
        return []


class HeaderExtractor(Extractor):
    """An extractor that needs only the start of the file.

    Runs before the stream phase, so whatever it writes to `ctx` is available
    to `applies_to` on every stream extractor.
    """

    @abstractmethod
    def read_header(self, header: bytes, path: Path, ctx: dict[str, Any],
                    config: dict[str, Any]) -> dict[str, Any]:
        """Return raw analysis data. Prefer partial data over raising."""


class StreamExtractor(Extractor):
    """An extractor fed the file in chunks rather than reading it itself.

    Contract: `begin` prepares per-file state, `feed` is called with every
    chunk in order, `finish` returns the data and must not touch the disk.

    `begin` must reset everything `feed` accumulates. Reusing one instance
    across a directory scan is the normal case, not the exception.
    """

    def begin(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> None:
        """Prepare per-file state. Called once before the first chunk."""

    @abstractmethod
    def feed(self, chunk: bytes) -> None:
        """Accept one chunk of the file, in order."""

    @abstractmethod
    def finish(self, path: Path, ctx: dict[str, Any],
               config: dict[str, Any]) -> dict[str, Any]:
        """Return the accumulated data. Never reads from disk."""


class RandomAccessExtractor(Extractor):
    """An extractor that addresses the file rather than streaming it.

    Some structure cannot be reached in one forward pass. A PE import table
    lives at a relative virtual address that resolves, through the section
    table, to a file offset that is not known until the section table has been
    read. Neither a fixed-size header nor a stream that may not buffer can get
    there.

    So this kind may open the sample for itself, read-only, and seek within
    it. What it may not do is read it whole: memory must stay bounded by what
    is actually parsed, either by mapping the file or by bounded reads.
    Bounded memory is the invariant v0.1.2 established. Reading the sample
    exactly once was only ever a proxy for it, and this is where the proxy
    stops being useful and the real rule is stated instead.

    Runs in the third phase, after the stream phase has finished, so `ctx`
    carries `family` from the header phase and `sha256` and `size` from the
    stream phase. Gate with `applies_to` as usual: a PE parser returns False
    for anything that is not a PE rather than discovering that for itself.

    The pipeline declines to run this phase on a sample larger than
    `max_parse_bytes` and records the refusal, because a parser handed hostile
    input is the one place in this tool where work is not bounded by the
    configured read sizes.
    """

    @abstractmethod
    def parse(self, path: Path, ctx: dict[str, Any],
              config: dict[str, Any]) -> dict[str, Any]:
        """Return raw analysis data. Prefer partial data over raising."""


# byte counting

try:  # optional accelerator, not a hard requirement
    import numpy as _np

    def byte_counts(data: bytes) -> list[int]:
        """Histogram of the 256 byte values, as a fixed-length list."""
        if not data:
            return [0] * BYTE_VALUES
        return _np.bincount(
            _np.frombuffer(data, dtype=_np.uint8), minlength=BYTE_VALUES
        ).tolist()

    HAVE_NUMPY = True
except ImportError:
    def byte_counts(data: bytes) -> list[int]:
        """Histogram of the 256 byte values, as a fixed-length list."""
        counts = [0] * BYTE_VALUES
        for value, count in Counter(data).items():
            counts[value] = count
        return counts

    HAVE_NUMPY = False


# file type

class FileTypeExtractor(HeaderExtractor):
    """Identify the format from magic bytes.

    Deliberately dependency-free. `python-magic` needs libmagic installed,
    which is friction for anyone cloning the repo, and a small signature table
    covers the formats that matter for triage.

    Costs no I/O of its own. Publishes `family` to the context, which is what
    lets the format-specific parsers arriving in v0.2 gate themselves.
    """

    name = "filetype"

    def read_header(self, header: bytes, path: Path, ctx: dict[str, Any],
                    config: dict[str, Any]) -> dict[str, Any]:
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

class HashExtractor(StreamExtractor):
    """Cryptographic and fuzzy hashes.

    Hashing was already streaming in v0.1.1. It now streams off the shared
    pass instead of opening the file for itself, so it costs no I/O.

    ssdeep is the exception: its API takes a path, so when the optional
    library is present it does read the file again. That is stated here rather
    than hidden, and it is one reason ssdeep stays optional.
    """

    name = "hashes"

    def begin(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> None:
        self._digests = {
            "md5": hashlib.md5(),
            "sha1": hashlib.sha1(),
            "sha256": hashlib.sha256(),
        }

    def feed(self, chunk: bytes) -> None:
        for digest in self._digests.values():
            digest.update(chunk)

    def finish(self, path: Path, ctx: dict[str, Any],
               config: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {k: v.hexdigest() for k, v in self._digests.items()}
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

def entropy_from_counts(counts, total: int) -> float:
    """Shannon entropy in bits per byte, from a byte histogram.

    Taking counts rather than bytes is what makes the streaming refactor
    possible: the histogram of a file is the sum of the histograms of its
    parts, so the whole-file figure needs nothing held in memory.
    """
    if total <= 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def shannon(data: bytes) -> float:
    """Shannon entropy in bits per byte. Range 0.0 (uniform) to 8.0 (random)."""
    return entropy_from_counts(byte_counts(data), len(data))


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


def entropy_window_size(size: int, config: dict[str, Any]) -> int:
    """Window size for a file of `size` bytes.

    Aims for `entropy_target_windows`, never below `entropy_min_window_bytes`,
    never above the configured size. At the fixed 8192 bytes of v0.1.0 a 3 KB
    dropper produced no windows at all and was scored `info`.
    """
    configured = config_int(config, "entropy_window_bytes", 8192)
    minimum = config_int(config, "entropy_min_window_bytes", 256)
    target = config_int(config, "entropy_target_windows", 8)
    return max(minimum, min(configured, size // target if size else configured))


class EntropyExtractor(StreamExtractor):
    """Whole-file and windowed Shannon entropy, computed in one pass.

    High entropy alone proves nothing. A ZIP scores high and so does a
    legitimate installer. The useful signal is shape: a mostly-low-entropy
    file containing one high-entropy region is the classic packed-stub layout,
    which is why `entropy_hotspot` scores higher than `high_file_entropy`.

    Memory is bounded by one window plus one chunk, not by the sample. Windows
    are scored as they complete and only the resulting float is kept, and the
    whole-file histogram is a fixed 256-entry list. Read chunk boundaries and
    window boundaries are unrelated, so windows are cut from a pending buffer
    rather than assumed to align with the reads.

    Thresholds are heuristics tuned for recall over precision. Triage exists
    to decide what deserves a human, not to give verdicts.
    """

    name = "entropy"

    def begin(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> None:
        self._window = entropy_window_size(ctx["size"], config)
        self._threshold = config_ratio(config, "entropy_window_ratio", 0.94)
        self._pending = bytearray()
        self._totals = [0] * BYTE_VALUES
        self._entropies: list[float] = []
        self._hot = 0
        self._size = 0

    def _add_to_totals(self, data: bytes) -> None:
        for value, count in enumerate(byte_counts(data)):
            if count:
                self._totals[value] += count

    def _score_window(self, window: bytes) -> None:
        counts = byte_counts(window)
        for value, count in enumerate(counts):
            if count:
                self._totals[value] += count
        entropy = entropy_from_counts(counts, len(window))
        self._entropies.append(entropy)
        if _ratio(entropy, self._window) >= self._threshold:
            self._hot += 1

    def feed(self, chunk: bytes) -> None:
        self._size += len(chunk)
        self._pending += chunk
        while len(self._pending) >= self._window:
            self._score_window(bytes(self._pending[: self._window]))
            del self._pending[: self._window]

    def finish(self, path: Path, ctx: dict[str, Any],
               config: dict[str, Any]) -> dict[str, Any]:
        tail = bytes(self._pending)
        if tail:
            if len(tail) >= self._window // 2:
                self._score_window(tail)
            else:
                # Too short to score as a window, but its bytes still belong
                # in the whole-file histogram.
                self._add_to_totals(tail)
        self._pending = bytearray()

        overall = entropy_from_counts(self._totals, self._size)
        window_max = max(self._entropies) if self._entropies else None

        return {
            "overall": round(overall, 4),
            "overall_ratio": _ratio(overall, self._size),
            "window_size": self._window,
            "window_size_configured": config_int(config, "entropy_window_bytes", 8192),
            "window_count": len(self._entropies),
            "window_max": round(window_max, 4) if window_max is not None else None,
            "window_max_ratio": (
                _ratio(window_max, self._window) if window_max is not None else None
            ),
            "window_mean": (
                round(sum(self._entropies) / len(self._entropies), 4)
                if self._entropies else None
            ),
            "high_entropy_windows": self._hot,
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
    """Order matters for the header phase: file type runs first so the stream
    phase can gate on the family it publishes."""
    return [FileTypeExtractor(), HashExtractor(), EntropyExtractor()]
