"""
Whole-file and windowed entropy, computed in one streaming pass.

The arithmetic lives in `entropy.py`, which the secret engine shares. This is
the extractor that applies it to a sample: the window sizing, the running
aggregates, and the two findings that come out of them.
"""

from __future__ import annotations
from pathlib import Path
from typing import Any

from .base import StreamExtractor
from .config import config_int, config_ratio
from .entropy import BYTE_VALUES, byte_counts, entropy_from_counts, ratio as _ratio
from .models import mk_finding


# entropy

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
        # Running aggregates, not a list. Every figure this extractor
        # reports about its windows -- the maximum, the mean and the count --
        # is computable in constant space, and keeping one float per window
        # instead made peak memory linear in sample size. It went unnoticed
        # from v0.1.2 because a float is small: 2441 of them for a 20 MB
        # sample is 80 KB, invisible next to a 1 MB read chunk. The stream
        # phase has no size ceiling -- `max_parse_bytes` bounds the parse
        # phase, not this one -- so at 100 GB the same list is 400 MB.
        self._window_max: float | None = None
        self._window_total = 0.0
        self._hot = 0
        self._window_count = 0
        self._size = 0
        self._fed = 0
        # A PE's signature is not the PE's content. `FileTypeExtractor`
        # publishes the range in phase 1; the bytes are dropped before they
        # reach a window or the histogram, and `finish` reports what was
        # skipped -- an entropy figure over a different set of bytes than the
        # file has must say so, or it is a number nobody can reproduce.
        self._exclude: tuple[int, int] | None = None
        found = ctx.get("certificate_range")
        if found:
            # Validated by `certificate_range` against the section table and
            # the end of the file before it reaches here, because an exclusion
            # a sample can aim is an evasion rather than a refinement.
            start, length = found
            self._exclude = (start, start + length)

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
        self._window_max = (entropy if self._window_max is None
                            else max(self._window_max, entropy))
        self._window_total += entropy
        self._window_count += 1
        if _ratio(entropy, self._window) >= self._threshold:
            self._hot += 1

    def feed(self, chunk: bytes) -> None:
        start = self._fed
        self._fed += len(chunk)
        if self._exclude is not None:
            low, high = self._exclude
            end = start + len(chunk)
            if start < high and end > low:
                # Cut the excluded span out of this chunk. Windows are cut
                # from the remainder, so they no longer align with file
                # offsets across the gap -- which costs nothing, because a
                # window boundary was never a meaningful position in the file.
                chunk = chunk[:max(0, low - start)] + (
                    chunk[max(0, high - start):] if end > high else b"")
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
        window_max = self._window_max

        return {
            "overall": round(overall, 4),
            "overall_ratio": _ratio(overall, self._size),
            "window_size": self._window,
            "window_size_configured": config_int(config, "entropy_window_bytes", 8192),
            "window_count": self._window_count,
            "window_max": round(window_max, 4) if window_max is not None else None,
            "window_max_ratio": (
                _ratio(window_max, self._window) if window_max is not None else None
            ),
            "window_mean": (
                round(self._window_total / self._window_count, 4)
                if self._window_count else None
            ),
            "high_entropy_windows": self._hot,
            "bytes_scanned": self._size,
            "excluded": (
                {"reason": "authenticode_certificate",
                 "offset": self._exclude[0],
                 "size": self._exclude[1] - self._exclude[0]}
                if self._exclude is not None else None
            ),
        }

    def findings(self, data: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        file_ratio = config_ratio(config, "entropy_file_ratio", 0.90)
        window_ratio = config_ratio(config, "entropy_window_ratio", 0.94)

        if data["overall_ratio"] >= file_ratio:
            out.append(mk_finding(self.name, "high_file_entropy",
                f"whole-file entropy {data['overall']} is {data['overall_ratio']} of what "
                "random data of this length reaches, consistent with packing, "
                "compression or encryption", "low",
                evidence=[{"name": "entropy", "value": data["overall"]},
                          {"name": "ratio_of_random", "value": data["overall_ratio"]},
                          {"name": "threshold", "value": file_ratio}]))

        # the interesting case: low overall, but a hot region inside
        if data["overall_ratio"] < file_ratio and data["high_entropy_windows"] > 0:
            out.append(mk_finding(self.name, "entropy_hotspot",
                f"{data['high_entropy_windows']} of {data['window_count']} window(s) at or "
                f"above {window_ratio} of random, in an otherwise low-entropy file, "
                "possible embedded packed or encrypted payload", "medium",
                evidence=[{"name": "high_entropy_windows",
                           "value": data["high_entropy_windows"]},
                          {"name": "window_count", "value": data["window_count"]},
                          {"name": "window_bytes", "value": data.get("window_bytes")},
                          {"name": "threshold", "value": window_ratio}]))
        return out
