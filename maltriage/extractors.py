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
make corpus-scale work possible in v0.7.

A stream extractor must keep its own memory bounded. Buffering the chunks it
is handed would reintroduce exactly the problem this design removes.

Config is read through the validated accessors in `config`, never with a
bare `.get`, so a bad value falls back to a default instead of silently
producing a wrong answer.
"""

from __future__ import annotations
import hashlib
import logging
import math
import mmap
import re
import struct
import time
from abc import ABC, abstractmethod
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import SEVERITY_RANK, mk_finding
from .config import config_bool, config_int, config_list, config_ratio
from . import apis

log = logging.getLogger(__name__)

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
    """Cryptographic hashes, computed off the shared pass.

    Hashing was already streaming in v0.1.1. It now streams off the shared
    pass instead of opening the file for itself, so it costs no I/O at all.

    ssdeep used to live here and was the one exception: its API takes a path,
    so it read the file a second time from inside a phase whose whole promise
    was that nothing did. v0.2 moves it to `FuzzyHashExtractor` in the
    random-access phase, where reading the file for yourself is the declared
    contract rather than a documented violation of one.
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
        # sha256 is the lookup key for enrichment in v0.4
        ctx["sha256"] = result["sha256"]
        return result


# fuzzy hashing

try:  # optional, needs a C library, so not a hard requirement
    import ssdeep as _ssdeep

    HAVE_SSDEEP = True
except ImportError:
    _ssdeep = None
    HAVE_SSDEEP = False


class FuzzyHashExtractor(RandomAccessExtractor):
    """Context-triggered piecewise hashing, via the optional ssdeep library.

    Random-access rather than streaming because ssdeep's API takes a path and
    reads the file itself. That was true when it lived in `HashExtractor` too;
    the difference is that the third phase declares it instead of apologising
    for it, and the stream phase is now honestly free of disk I/O.

    Its absence is filed as data, not as an error, and the asymmetry with
    pefile is deliberate. A missing parser removes findings, so it has to be
    reported as a failure. A missing fuzzy hash removes a correlation key that
    nothing in this release consumes, so `available: false` says everything
    there is to say without teaching an analyst to ignore `report.errors`.
    """

    name = "fuzzy"

    def parse(self, path: Path, ctx: dict[str, Any],
              config: dict[str, Any]) -> dict[str, Any]:
        if not HAVE_SSDEEP:
            return {"ssdeep": None, "available": False}
        return {"ssdeep": _ssdeep.hash_from_file(str(path)), "available": True}


# entropy

def entropy_from_counts(counts, total: int) -> float:
    """Shannon entropy in bits per byte, from a byte histogram.

    Taking counts rather than bytes is what makes the streaming refactor
    possible: the histogram of a file is the sum of the histograms of its
    parts, so the whole-file figure needs nothing held in memory.
    """
    if total <= 0:
        return 0.0
    # The `+ 0.0` is not decoration. A region with all its mass in one bucket
    # negates to -0.0, which compares equal to zero and then serialises into
    # the report as "-0.0", so a flat section reads as though something odd
    # happened to it.
    return -sum((c / total) * math.log2(c / total) for c in counts if c) + 0.0


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


# strings

#: Printable ASCII, and deliberately nothing else. Excluding the control
#: range at extraction time is what makes these strings safe to put in a
#: report without sanitising: ESC is 0x1B and cannot appear in a run.
PRINTABLE = rb"\x20-\x7e"

ASCII_RUN = re.compile(rb"[" + PRINTABLE + rb"]{%d,}")
WIDE_RUN = re.compile(rb"(?:[" + PRINTABLE + rb"]\x00){%d,}")

# Indicators, matched against extracted strings rather than raw bytes, which
# bounds the work by `strings_max_retained` instead of by the sample.
# Every pattern here is linear: no nested quantifier, no backtracking trap.
IOC_PATTERNS = {
    "urls": re.compile(r"\b(?:https?|ftps?)://[^\s\"'<>\\)\]}]{4,}"),
    "emails": re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "registry_paths": re.compile(
        r"\b(?:HKEY_[A-Z_]{4,24}|HKLM|HKCU|HKCR|HKU)\\[^\s\"'<>|]{2,200}"),
    "mutexes": re.compile(r"\b(?:Global|Local)\\[^\s\"'<>|]{2,200}"),
    "windows_paths": re.compile(r"\b[A-Za-z]:\\\\?[^\s\"'<>|]{2,200}"),
    "unix_paths": re.compile(
        r"(?:^|[\s\"'=:])(/(?:usr|etc|tmp|var|opt|home|bin|sbin|lib|dev|proc)"
        r"/[^\s\"'<>|]{1,200})"),
}

# Registry locations that survive a reboot. Kept in config rather than here so
# the list can grow without a code change.
RUN_KEY_MARKERS = ("currentversion\\run", "currentversion\\runonce",
                   "currentversion\\policies\\explorer\\run",
                   "winlogon", "\\services\\", "image file execution options")


class StringsExtractor(StreamExtractor):
    """Printable ASCII and UTF-16LE strings, taken off the shared pass.

    A stream extractor rather than a random-access one, because strings are
    the one thing in this tool that genuinely wants every byte in order and
    nothing else. That makes bounded memory the whole problem: the naive
    version keeps every string it finds, and a 400 MB text file has tens of
    millions of them.

    So three ceilings, and each says when it bit. `strings_max_retained`
    caps how many are kept while the count keeps rising, so the report can
    still say how many there were. `strings_max_length` caps one string, and
    a run longer than it contributes its first that-many bytes and no more.
    `strings_max_iocs` caps each indicator list.

    Runs are found with one regex per chunk rather than a Python loop over
    bytes, because the loop costs about a minute on a 200 MB sample and the
    regex costs under a second. A run crossing a chunk boundary is carried
    forward, and the tests pin that the result does not depend on the chunk
    size -- which is the property that broke first when this was written.

    Extraction only. These strings are data; deciding that one looks like a
    credential is the v0.4 secret engine's job and deciding that one names a
    suspicious API is a heuristic that belongs in `findings`. Nothing here
    reaches medium: an installer writing a Run key is an installer, and
    `GATE_SEVERITY` is medium.
    """

    name = "strings"

    def begin(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> None:
        self._min = config_int(config, "strings_min_length", 6)
        self._max = config_int(config, "strings_max_length", 1024)
        self._keep = config_int(config, "strings_max_retained", 2048)
        self._ascii_re = re.compile(rb"[" + PRINTABLE + rb"]{%d,}" % self._min)
        self._wide_re = re.compile(rb"(?:[" + PRINTABLE + rb"]\x00){%d,}" % self._min)
        self._scanners = {
            "ascii": _RunScanner(self._ascii_re, self._max, step=1),
            "wide": _RunScanner(self._wide_re, self._max, step=2),
        }
        self._found = {"ascii": [], "wide": []}
        self._counts = {"ascii": 0, "wide": 0}
        self._long = 0
        self._tokens = config_int(config, "api_max_token_scan_bytes", 128)
        # Bounded by the registry, not by the sample: this can never hold more
        # than the vocabulary, whatever the file does. It is the only
        # accumulator in this extractor that needs no cap, and the reason is
        # worth stating -- what goes in comes from `apis`, not from the bytes.
        self._api: set[str] = set()

    def feed(self, chunk: bytes) -> None:
        for kind, scanner in self._scanners.items():
            for run, over_length in scanner.feed(chunk):
                self._record(kind, run, over_length)

    def _record(self, kind: str, run: bytes, over_length: bool) -> None:
        self._counts[kind] += 1
        if over_length:
            self._long += 1
        text = run.decode("ascii", "replace") if kind == "ascii" else \
            run[::2].decode("ascii", "replace")

        # API matching runs here rather than over the retained list, and that
        # placement is the whole point of doing it in the extractor. The
        # retained list stops at `strings_max_retained`, and `text` is off by
        # default, so a findings pass over `report.data` would see a truncated
        # subset on a verbose run and nothing at all on a normal one -- while
        # the packed sample this is meant to catch is exactly the one with
        # hundreds of thousands of strings. Every string is matched; only what
        # matched is kept.
        for canonical, _categories in apis.match_text(text, self._tokens):
            self._api.add(canonical)

        # The cap is shared across both kinds, not granted to each. Per-kind
        # it was a ceiling of twice what the config asked for, and the comment
        # beside the default claimed the product as the worst case.
        if len(self._found["ascii"]) + len(self._found["wide"]) < self._keep:
            self._found[kind].append(text)

    def finish(self, path: Path, ctx: dict[str, Any],
               config: dict[str, Any]) -> dict[str, Any]:
        for kind, scanner in self._scanners.items():
            for run, over_length in scanner.flush():
                self._record(kind, run, over_length)

        strings = self._found["ascii"] + self._found["wide"]
        data: dict[str, Any] = {
            "ascii_count": self._counts["ascii"],
            "wide_count": self._counts["wide"],
            "retained": len(strings),
            "retained_truncated": (self._counts["ascii"] + self._counts["wide"]
                                   > len(strings)),
            "over_length": self._long,
            "min_length": self._min,
        }
        indicators, truncated = self._indicators(strings, config)
        data.update(indicators)

        # Which known API names appeared, and under which capabilities. Not
        # the strings themselves, and not subject to the switch below: this
        # list is drawn from the registry's fixed vocabulary, so it is text
        # this project wrote about a file rather than text taken out of one.
        # That is what makes it safe to publish unconditionally, and it is
        # also why it needs no truncation flag -- unlike every other list in
        # this extractor, it cannot grow with the sample.
        data["api_names"] = sorted(apis.display(n) for n in self._api)
        data["api_capabilities"] = apis.categorise(self._api, view="string")

        # The strings themselves are off by default, and this is the one
        # switch in the extractor set. What it controls is a dump rather than
        # a finding: the indicators above are the triage value and are always
        # present, while the raw list is two megabytes of somebody else's file
        # in an artefact that gets stored, piped and shared. A sample that
        # harvests credentials has them among its strings.
        #
        # Unlike YARA's match bytes there is no argument for making this
        # unconditional, and unlike YARA's console output there is no way for
        # it to leak without being asked: the default is off and the caller
        # has to say otherwise.
        if config_bool(config, "strings_include_text", False):
            data["text"] = strings

        # Every cap says when it bit, through the channel the CLI already
        # renders. A capped list that reads as a total is the failure this
        # project has now made four times in four extractors.
        problems = []
        if data["retained_truncated"]:
            problems.append(
                f"strings: only the first {len(strings)} of "
                f"{data['ascii_count'] + data['wide_count']} strings were kept, so "
                "the indicators below were found in a subset")
        if truncated:
            problems.append(
                f"indicators: {', '.join(sorted(truncated))} reached "
                "strings_max_iocs, so those lists are partial")
        if self._long:
            problems.append(
                f"strings: {self._long} run(s) were longer than "
                "strings_max_length and contributed only their first bytes")
        if problems:
            data["parse_errors"] = problems
        return data

    def _indicators(self, strings: list[str], config: dict[str, Any]) -> dict[str, Any]:
        limit = config_int(config, "strings_max_iocs", 128)
        found = {name: [] for name in IOC_PATTERNS}
        truncated = set()
        for text in strings:
            for name, pattern in IOC_PATTERNS.items():
                for match in pattern.finditer(text):
                    value = match.group(match.lastindex or 0)
                    if name == "ipv4" and not _is_ipv4(value):
                        continue
                    bucket = found[name]
                    if value in bucket:
                        continue
                    if len(bucket) >= limit:
                        truncated.add(name)
                        continue
                    bucket.append(value)
        result: dict[str, Any] = dict(found)
        result["indicators_truncated"] = sorted(truncated)
        return result, truncated

    def findings(self, data: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        for key, label, severity in (
                ("urls", "URL", "info"),
                ("emails", "email address", "info"),
                ("ipv4", "hardcoded IPv4 address", "low"),
                ("mutexes", "named mutex", "low"),
                ("windows_paths", "absolute Windows path", "info"),
                ("unix_paths", "absolute Unix path", "info")):
            values = data.get(key) or []
            if not values:
                continue
            shown = ", ".join(values[:4])
            more = "" if len(values) <= 4 else f", and {len(values) - 4} more"
            # "at least", not a total, when the list hit its ceiling. The
            # count is of what was kept, and saying otherwise is a number
            # nobody measured.
            capped = key in (data.get("indicators_truncated") or [])
            how_many = f"at least {len(values)}" if capped else str(len(values))
            out.append(mk_finding(self.name, f"{key}_present",
                f"{how_many} {label}(s) in the sample's strings: "
                f"{shown}{more}", severity))

        markers = [m.lower() for m in config_list(config, "strings_run_keys",
                                                  list(RUN_KEY_MARKERS))]
        persistence = [p for p in data.get("registry_paths") or []
                       if any(m in p.lower() for m in markers)]
        others = [p for p in data.get("registry_paths") or [] if p not in persistence]
        capped = "registry_paths" in (data.get("indicators_truncated") or [])
        if persistence:
            # Low, not medium. An installer writing a Run key is an installer,
            # and `GATE_SEVERITY` is medium: a finding earns it only if a file
            # deserves a human because of that finding alone. Turning this
            # into evidence is the classifier's job, once v0.7 can measure
            # what it costs.
            out.append(mk_finding(self.name, "registry_persistence_path",
                f"{'at least ' if capped else ''}{len(persistence)} registry "
                f"path(s) that survive a reboot: "
                f"{', '.join(persistence[:3])}", "low"))
        if others:
            out.append(mk_finding(self.name, "registry_path_present",
                f"{'at least ' if capped else ''}{len(others)} registry path(s): "
                f"{', '.join(others[:3])}", "info"))

        # A name in the string table is weaker evidence than the same name in
        # an import table -- text is text -- but it is the only evidence there
        # is when a sample resolves its imports at runtime, which is the case
        # worth catching. The registry holds the severities; none reaches
        # medium.
        out.extend(apis.capability_findings(
            self.name, data.get("api_capabilities") or {},
            config_int(config, "api_min_names_per_capability", 2),
            view="string"))
        return out


class _RunScanner:
    """Finds runs of a pattern across chunk boundaries, in bounded memory.

    The rule that makes this correct: **carry the trailing bytes that could
    still be part of a run, not the trailing bytes that already matched one.**

    The first version carried a run only when the regex had matched and the
    match reached the end of the buffer. A fragment shorter than the minimum
    length can never match `{6,}`, so it was silently dropped and the next
    buffer restarted inside the run: `MZAPPDATAROAM` split at a 4096-byte
    boundary was reported as `PPDATAROAM`. Worse for UTF-16, where a
    continuation that resumed one byte late was emitted as a fresh run, so
    `wide_count` on 100 MB of `A\x00` was literally the number of chunks. The
    result depended on `read_chunk_bytes`, which is the one thing a stream
    extractor may never let a reader see.

    So the tail is found by walking backwards over what could continue a run,
    which covers the matched case and the too-short case with the same code,
    and matches are emitted only where they end before that tail begins.
    """

    def __init__(self, pattern, maximum: int, step: int) -> None:
        self.pattern, self.step = pattern, step
        self.ceiling = maximum * step
        self.carry = b""
        self.skipping = False
        self.skip_half = False

    def _continuable_from(self, buffer: bytes) -> int:
        """Where the trailing bytes that could still extend a run begin."""
        index = len(buffer)
        if self.step == 1:
            while index and 0x20 <= buffer[index - 1] <= 0x7E:
                index -= 1
            return index
        # A UTF-16LE run is (printable, NUL) pairs, so its prefixes are whole
        # pairs optionally followed by a lone printable byte -- the half pair
        # a boundary can split.
        if index and 0x20 <= buffer[index - 1] <= 0x7E:
            index -= 1
        while index >= 2 and buffer[index - 1] == 0 and 0x20 <= buffer[index - 2] <= 0x7E:
            index -= 2
        return index

    def _leading_run_end(self, buffer: bytes) -> tuple[int, bool]:
        """Where the run a previous buffer left unfinished stops.

        Returns the length consumed and whether it ended on half a UTF-16
        pair. The parity has to be carried: a chunk size that is odd, or that
        does not divide the run, leaves the next buffer starting on the NUL
        of a pair rather than on its printable half. Treating that lone NUL
        as the end of the run made a 200 000-pair file report one run per
        chunk at a chunk size of one, three or seven bytes.
        """
        index = 0
        if self.step == 1:
            while index < len(buffer) and 0x20 <= buffer[index] <= 0x7E:
                index += 1
            return index, False
        if self.skip_half:
            if index < len(buffer) and buffer[index] == 0:
                index += 1
            else:
                return index, False
        while (index + 1 < len(buffer) and 0x20 <= buffer[index] <= 0x7E
               and buffer[index + 1] == 0):
            index += 2
        half = index < len(buffer) and 0x20 <= buffer[index] <= 0x7E
        return (index + 1 if half else index), half

    def feed(self, chunk: bytes):
        if self.skipping:
            # Inside a run already emitted at its full length. Discard the
            # rest of it, and stop skipping the moment it ends -- which the
            # first version never did, so an unrelated later string was
            # thrown away as though it were a tail.
            consumed, half = self._leading_run_end(chunk)
            if consumed == len(chunk):
                self.skip_half = half
                return
            self.skipping = False
            self.skip_half = False
            chunk = chunk[consumed:]

        buffer = self.carry + chunk
        self.carry = b""
        tail = self._continuable_from(buffer)

        for match in self.pattern.finditer(buffer):
            if match.end() > tail:
                break
            run = match.group()
            if len(run) >= self.ceiling:
                yield run[: self.ceiling], True
            else:
                yield run, False

        pending = buffer[tail:]
        if len(pending) >= self.ceiling:
            yield pending[: self.ceiling], True
            self.skipping = True
            # The ceiling is a whole number of units, so what is left of the
            # run keeps the alignment `pending` started with.
            self.skip_half = self.step == 2 and len(pending) % 2 == 1
        else:
            self.carry = pending

    def flush(self):
        if self.carry and self.pattern.fullmatch(self.carry):
            yield self.carry[: self.ceiling], False
        self.carry = b""
        self.skipping = False
        self.skip_half = False


def _is_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and len(p) <= 3 and int(p) < 256
                                   for p in parts)


# PE

class ParserUnavailable(RuntimeError):
    """An optional parser an extractor needs is not installed.

    Raised rather than returned, so the pipeline files it under
    `report.errors` alongside every other reason analysis did not happen. The
    alternative is a report on a PE that carries no PE data and no
    explanation, which is indistinguishable from a report on a PE that had
    nothing to say.
    """


try:  # optional, and staying that way: see architecture.md, "Dependencies"
    import pefile as _pefile

    HAVE_PEFILE = True
except ImportError:
    _pefile = None
    HAVE_PEFILE = False


# Section characteristics, as the format defines them.
SCN_CNT_CODE = 0x00000020
SCN_CNT_INITIALIZED = 0x00000040
SCN_CNT_UNINITIALIZED = 0x00000080
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000

# COFF characteristics.
FILE_DLL = 0x2000
FILE_SYSTEM = 0x1000

SUBSYSTEM_NATIVE = 1
MAGIC_PE32_PLUS = 0x20B

DIRECTORY_IMPORT = 1
# The certificate table's data directory entry holds a file offset rather
# than an RVA, which is the one exception in the table and a standing trap.
DIRECTORY_SECURITY = 4
DIRECTORY_DEBUG = 6

DEBUG_ENTRY_SIZE = 28
DEBUG_TYPE_CODEVIEW = 2
# CodeView record layouts: the path follows a signature, a GUID or offset,
# and an age.
CODEVIEW_PATH_OFFSET = {b"RSDS": 24, b"NB10": 16}

# OBJECT IDENTIFIER 2.5.4.3, id-at-commonName.
CN_OID = bytes.fromhex("0603550403")


def region_entropy(data, start: int, length: int, cap: int,
                   chunk: int = 1048576) -> tuple[float | None, float | None, bool, int]:
    """Entropy of a region of a mapped file, without holding the region whole.

    Returns (entropy, ratio, sampled, scored). `scored` is how many bytes were
    actually read, which is not `length`: `cap` may cut the region short, and
    a region that runs past the end of the mapping yields fewer bytes than it
    claims. `sampled` says the answer describes part of the region rather than
    all of it. Both exist because a partial figure that reads as a whole one
    is worse than no figure.

    A region that yields nothing at all scores `None` rather than `0.0`. Zero
    is the entropy of a flat region, and a region that was never read is not a
    flat region.

    The histogram of a region is the sum of the histograms of its pieces, so
    this costs one 256-entry list and one chunk regardless of how large the
    region is. That is the same property that made the streaming entropy
    extractor possible, reused here where the boundaries come from the section
    table rather than from the read.
    """
    if length <= 0 or cap <= 0 or start < 0:
        return None, None, False, 0
    take = min(length, cap)
    counts = [0] * BYTE_VALUES
    scored = 0
    while scored < take:
        piece = bytes(data[start + scored: start + min(take, scored + chunk)])
        if not piece:
            break  # the mapping ended before the region the file claimed
        for value, count in enumerate(byte_counts(piece)):
            if count:
                counts[value] += count
        scored += len(piece)
    if not scored:
        return None, None, False, 0
    entropy = entropy_from_counts(counts, scored)
    return round(entropy, 4), _ratio(entropy, scored), scored < length, scored


def certificate_common_names(blob: bytes, limit: int = 16) -> list[str]:
    """Scan a PKCS#7 certificate blob for X.509 commonName strings.

    This is a scan, not a parse, and the shallowness is the point. It answers
    "whose name is written inside this signature", which is a triage question.
    It refuses to answer "is this signature valid", which is not a question
    v0.2 can answer: that needs a chain, a trust store and a clock, and none
    of those are dependencies this tool has taken.

    So: the blob carries the whole chain, the names returned therefore include
    issuing CAs as well as the signer, the order is the order they appear in
    the file, and none of it is verified. A crafted file can put any string
    here. Treat the result as an attribution hint to check, never as an
    identity to trust.
    """
    names: list[str] = []
    cursor = 0
    while len(names) < limit:
        found = blob.find(CN_OID, cursor)
        if found < 0:
            break
        cursor = found + len(CN_OID)
        if cursor + 2 > len(blob):
            break
        tag, length = blob[cursor], blob[cursor + 1]
        # Short-form lengths only. A CN longer than 127 bytes is not a name
        # worth chasing into multi-byte length decoding.
        if tag not in (0x0C, 0x13, 0x16, 0x1E) or length > 0x7F:
            continue
        raw = blob[cursor + 2: cursor + 2 + length]
        if len(raw) < length:
            break
        try:
            text = safe_text(
                raw.decode("utf-16-be" if tag == 0x1E else "ascii"), 256).strip()
        except (UnicodeDecodeError, ValueError):
            continue
        if text and text not in names:
            names.append(text)
    return names


def _lookup(table, value: int) -> str:
    """Read pefile's two-way enum tables without trusting them to be populated.

    The constant names carry the format's `IMAGE_FILE_MACHINE_` and
    `IMAGE_SUBSYSTEM_` prefixes, which say nothing a reader of a field called
    `machine_label` does not already know, so they come off.
    """
    try:
        label = table[value]
    except (KeyError, IndexError, TypeError):
        return "unknown"
    if not isinstance(label, str):
        return "unknown"
    for prefix in ("IMAGE_FILE_MACHINE_", "IMAGE_SUBSYSTEM_", "IMAGE_DEBUG_TYPE_"):
        if label.startswith(prefix):
            return label[len(prefix):]
    return label


class PEExtractor(RandomAccessExtractor):
    """Portable Executable structure, parsed with pefile.

    The first extractor that could not have been written as a forward pass.
    An import table lives at an RVA that resolves, through the section table,
    to a file offset nobody knows until the section table has been read, so
    this kind opens the sample and addresses it. pefile maps the file with
    `mmap`, and every figure derived here is computed over a bounded region of
    that mapping rather than over a copy of the sample.

    Extraction only. Every list this produces is data; the judgements about
    that data live in `findings`, and the judgements about import *names* are
    not here at all, because the roadmap puts them in v0.4 and a release
    boundary is not a reason to smuggle a heuristic into a parser.

    Directories are parsed one at a time rather than in a single call. On a
    file built to break a parser, an import table that throws should not also
    cost the export table, the debug directory and the TLS callbacks, and this
    is the same isolation the pipeline gives extractors, applied one level
    further in.
    """

    name = "pe"

    def applies_to(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> bool:
        return ctx.get("family") == "pe"

    def parse(self, path: Path, ctx: dict[str, Any],
              config: dict[str, Any]) -> dict[str, Any]:
        if not HAVE_PEFILE:
            raise ParserUnavailable(
                "pefile is not installed, so this file was identified as a PE "
                "but not parsed; install it with 'pip install pefile'")

        # Both ceilings exist because the input is hostile by assumption.
        # pefile's defaults are generous enough that a crafted export table
        # can keep it busy for a long time on a file that is not large.
        pe = _pefile.PE(
            name=str(path),
            fast_load=True,
            max_symbol_exports=config_int(config, "pe_max_symbol_exports", 4096),
            max_repeated_symbol=config_int(config, "pe_max_repeated_symbol", 64),
        )
        try:
            return self._parse(pe, ctx, config)
        finally:
            pe.close()

    # extraction

    def _parse(self, pe, ctx: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
        problems: list[str] = []

        def attempt(label, fn, default):
            """Run one piece of extraction. Partial data beats no data."""
            try:
                return fn()
            except Exception as exc:
                log.debug("pe %s failed: %s", label, exc)
                problems.append(f"{label}: {type(exc).__name__}: {exc}")
                return default

        coff, optional = pe.FILE_HEADER, pe.OPTIONAL_HEADER
        size = ctx["size"]

        data: dict[str, Any] = {
            "pe_type": "PE32+" if optional.Magic == MAGIC_PE32_PLUS else "PE32",
            "machine": coff.Machine,
            "machine_label": _lookup(_pefile.MACHINE_TYPE, coff.Machine),
            "subsystem": optional.Subsystem,
            "subsystem_label": _lookup(_pefile.SUBSYSTEM_TYPE, optional.Subsystem),
            "characteristics": coff.Characteristics,
            "is_dll": bool(coff.Characteristics & FILE_DLL),
            "is_system": bool(coff.Characteristics & FILE_SYSTEM),
            "is_driver": optional.Subsystem == SUBSYSTEM_NATIVE,
            "image_base": optional.ImageBase,
            "timestamp": coff.TimeDateStamp,
            "timestamp_iso": _iso_timestamp(coff.TimeDateStamp),
            "entry_point": optional.AddressOfEntryPoint,
        }

        data["sections"] = attempt("sections", lambda: self._sections(pe, ctx, config), [])
        starved = [s["name"] for s in data["sections"]
                   if s.get("entropy_skipped") == "budget_exhausted"]
        if starved:
            problems.append(
                "sections: the entropy budget ran out, so "
                f"{len(starved)} section(s) were not scored: {', '.join(starved[:8])}")
        data["entry_point_section"] = _section_for_rva(
            data["sections"], optional.AddressOfEntryPoint)

        # `imports_parsed` defaults to False here on purpose. If reading the
        # import table failed outright, the one thing that is certainly not
        # known is that the file has no imports.
        data.update(attempt("imports", lambda: self._imports(pe, config),
                            {"imports": {}, "import_count": 0, "imphash": None,
                             "imports_truncated": False, "imports_parsed": False,
                             "api_names": [], "api_capabilities": {}}))
        data.update(attempt("exports", lambda: self._exports(pe, config),
                            {"exports": [], "export_count": 0,
                             "exports_truncated": False}))
        data["tls_callbacks"] = attempt("tls", lambda: self._tls(pe, config), [])
        data["debug"] = attempt("debug", lambda: self._debug(pe, config), [])
        data["pdb_path"] = next((e["pdb_path"] for e in data["debug"] if e.get("pdb_path")),
                                None)
        data["certificate"] = attempt(
            "certificate", lambda: self._certificate(pe, size, config),
            {"present": False, "common_names": [], "validated": False})
        data["overlay"] = attempt(
            "overlay",
            lambda: self._overlay(pe, size, config, data["certificate"]), None)

        # pefile records a warning and carries on where it would otherwise
        # have to give up: an import directory at an impossible RVA, a
        # structure that overlaps another. Discarding those leaves the report
        # asserting an absence that was really a failure to look.
        warnings = attempt("warnings", pe.get_warnings, [])
        limit = config_int(config, "pe_max_listed_symbols", 256)
        if warnings:
            data["warnings"] = warnings[:limit]

        if problems:
            # Recorded inside the data rather than raised, so a file that
            # defeats one directory still yields the others. The pipeline's
            # `report.errors` is for an extractor that produced nothing, and
            # the CLI renders both, because either one means a report is
            # thinner than it looks.
            data["parse_errors"] = problems
        return data

    def _sections(self, pe, ctx: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        """The section table, with entropy scored inside a shared budget.

        The per-region cap alone is not a bound. A section table is 40 bytes
        per entry and pefile will parse thousands of them, so a header under
        100 KB can ask for a cap's worth of histogram work several thousand
        times over. The budget is therefore spent across the whole table.

        How it is divided matters as much as that it exists. Spending it in
        table order lets a file starve a section by putting it last, and
        section order has no effect on loading, so that would be a free
        evasion: move the packed section to the end and it is never scored.
        `_share_budget` allocates by size instead, which no reordering
        changes.

        A section granted less than the entropy floor is not scored at all.
        Scoring 64 bytes of a 16 MB section produces a ratio above 1.0 — the
        reference model is out of range below about 128 bytes — and that is a
        `medium` finding bought with a forged size field.
        """
        cap = config_int(config, "pe_region_entropy_bytes", 16777216)
        floor = config_int(config, "entropy_min_window_bytes", 256)
        size = ctx["size"]

        lengths = []
        for section in pe.sections:
            start = section.PointerToRawData
            # A section table may claim raw data that runs past the end of the
            # file. Score what is actually there, not what it says is there.
            lengths.append(
                max(0, min(section.SizeOfRawData, size - start)) if start < size else 0)
        grants = _share_budget([min(length, cap) for length in lengths],
                               config_int(config, "pe_entropy_budget_bytes", 67108864))

        out = []
        for section, length, grant in zip(pe.sections, lengths, grants):
            name = safe_text(section.Name.rstrip(b"\x00"), 64)
            characteristics = section.Characteristics
            skipped = None
            if length < floor:
                skipped = "too_short" if length else "no_bytes"
            elif grant < floor:
                skipped = "budget_exhausted"
            if skipped:
                entropy, ratio, sampled, scored = None, None, False, 0
            else:
                entropy, ratio, sampled, scored = region_entropy(
                    pe.__data__, section.PointerToRawData, length, grant)
                if not scored:
                    skipped = "unreadable"
            out.append({
                "name": name,
                "virtual_address": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "raw_pointer": section.PointerToRawData,
                "scored_bytes": scored,
                "characteristics": characteristics,
                "readable": bool(characteristics & SCN_MEM_READ),
                "writable": bool(characteristics & SCN_MEM_WRITE),
                "executable": bool(characteristics & SCN_MEM_EXECUTE),
                "code": bool(characteristics & SCN_CNT_CODE),
                "uninitialised": bool(characteristics & SCN_CNT_UNINITIALIZED),
                "entropy": entropy,
                "entropy_ratio": ratio,
                "entropy_sampled": sampled,
                # Why there is no figure, when there is none. "the section was
                # empty", "the section pointed past the end of the file" and
                # "there was no budget left to read it" are three different
                # facts, and a null with no reason attached is the shape of a
                # report that looks clean because nobody looked.
                "entropy_skipped": skipped,
            })
        return out

    def _imports(self, pe, config: dict[str, Any]) -> dict[str, Any]:
        """The import table, and whether it was actually read.

        "No imports" and "an import table this parser could not follow" are
        different facts about a file, and only the first is evidence that the
        binary resolves its API at runtime. pefile signals the second by
        recording a warning and defining no `DIRECTORY_ENTRY_IMPORT`, which
        looks identical to the first unless the directory entry is consulted.
        A forged import RVA would otherwise earn a medium finding, and the
        gate exits non-zero on a medium.
        """
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        claimed = (len(directory) > DIRECTORY_IMPORT
                   and bool(directory[DIRECTORY_IMPORT].VirtualAddress))
        pe.parse_data_directories(
            directories=[_pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        entries = getattr(pe, "DIRECTORY_ENTRY_IMPORT", None)
        limit = config_int(config, "pe_max_listed_symbols", 256)
        imports: dict[str, list[str]] = {}
        total, truncated = 0, False
        matched: set[str] = set()
        for entry in entries or []:
            dll = safe_text(entry.dll or b"", 256)
            names = []
            for imported in entry.imports:
                total += 1
                symbol = (safe_text(imported.name, 256) if imported.name
                          else f"#{imported.ordinal}")
                # Matched before the display cap is applied, for the reason
                # the strings extractor matches before its retained cap: a
                # binary with three thousand imports is exactly the one whose
                # interesting symbol sits past entry 256, and a capability
                # that depends on how long the list was allowed to get is not
                # a fact about the file.
                canonical, _categories = apis.match_symbol(symbol)
                if canonical is not None:
                    matched.add(canonical)
                if len(names) >= limit:
                    truncated = True
                    continue
                names.append(symbol)
            imports.setdefault(dll, []).extend(names)
        # imphash is computed over the import table pefile parsed, so it is
        # unaffected by the display cap above.
        imphash = pe.get_imphash() if imports else None
        return {
            "imports": imports,
            "import_count": total,
            "imphash": imphash or None,
            "imports_truncated": truncated,
            "imports_parsed": bool(entries) or not claimed,
            "api_names": sorted(apis.display(n) for n in matched),
            "api_capabilities": apis.categorise(matched, view="import"),
        }

    def _exports(self, pe, config: dict[str, Any]) -> dict[str, Any]:
        pe.parse_data_directories(
            directories=[_pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        symbols = getattr(directory, "symbols", []) if directory else []
        limit = config_int(config, "pe_max_listed_symbols", 256)
        names = [safe_text(s.name, 256) if s.name else f"#{s.ordinal}"
                 for s in symbols[:limit]]
        return {
            "exports": names,
            "export_count": len(symbols),
            "exports_truncated": len(symbols) > limit,
        }

    def _tls(self, pe, config: dict[str, Any]) -> list[int]:
        """Walk the TLS callback array.

        pefile parses the TLS directory but not the callback list it points
        at, and the list is worth having: a TLS callback runs before the entry
        point, which is exactly why it is used to defeat a debugger set to
        break there.

        Two bounds, both because the file supplies the numbers. The walk is
        capped, since the array ends at a terminator a hostile file can
        decline to provide. And the address must resolve into a real section
        before it is followed.

        That second test is stronger than it first looks like it needs to be,
        because `pefile.get_data` resolves an address three ways and only one
        of them is the array. A negative RVA, from `AddressOfCallBacks` below
        `ImageBase`, slices backwards from the header buffer and returns DOS
        stub and section-table bytes. An RVA inside the declared image but
        covered by no section falls through to being treated as a raw file
        offset, which on a file with an overlay returns the overlay. Both
        produce plausible-looking addresses, and each one earns a finding on
        the way out: invented structure filed as extracted data. Checking the
        RVA against `SizeOfImage` does not catch either, because `SizeOfImage`
        is also a field in the file. Landing in a section does.
        """
        pe.parse_data_directories(
            directories=[_pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]])
        directory = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
        if not directory or not getattr(directory, "struct", None):
            return []
        address = getattr(directory.struct, "AddressOfCallBacks", 0)
        optional = pe.OPTIONAL_HEADER
        rva = address - optional.ImageBase
        if not address or not _in_a_section(pe, rva):
            return []

        width = 8 if optional.Magic == MAGIC_PE32_PLUS else 4
        callbacks: list[int] = []
        for _ in range(config_int(config, "pe_max_tls_callbacks", 64)):
            if not _in_a_section(pe, rva):
                break
            raw = _safe_data(pe, rva, width)
            if len(raw) < width:
                break
            value = int.from_bytes(raw, "little")
            if not value:
                break
            callbacks.append(value)
            rva += width
        return callbacks

    def _debug(self, pe, config: dict[str, Any]) -> list[dict[str, Any]]:
        """Walk the debug directory without letting pefile size the read.

        pefile parses a CodeView record by slicing `SizeOfData` bytes out of
        the mapping and packing whatever is left over into `PdbFileName`.
        `SizeOfData` is a field in the file, so a one-DWORD edit turns a PDB
        path into a copy of the whole sample: a 40 MB file produced a 40 MB
        string, a 200 MB peak and an 84 MB JSON report, with no error raised.
        That is the bounded-memory invariant lost to a single forged number,
        so the directory is walked here and every read is given a length.
        """
        directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(directory) <= DIRECTORY_DEBUG:
            return []
        rva, size = directory[DIRECTORY_DEBUG].VirtualAddress, directory[DIRECTORY_DEBUG].Size
        if not rva or not size:
            return []

        limit = config_int(config, "pe_max_pdb_bytes", 1024)
        out = []
        for index in range(min(size // DEBUG_ENTRY_SIZE,
                               config_int(config, "pe_max_debug_entries", 32))):
            raw = _safe_data(pe, rva + index * DEBUG_ENTRY_SIZE, DEBUG_ENTRY_SIZE)
            if len(raw) < DEBUG_ENTRY_SIZE:
                break
            _, stamp, _, _, kind, data_size, data_rva, data_pointer = struct.unpack(
                "<IIHHIIII", raw)
            out.append({
                "type": kind,
                "type_label": _lookup(_pefile.DEBUG_TYPE, kind),
                "timestamp": stamp,
                "pdb_path": (self._pdb_path(pe, data_rva, data_pointer, data_size, limit)
                             if kind == DEBUG_TYPE_CODEVIEW else None),
            })
        return out

    @staticmethod
    def _pdb_path(pe, rva: int, pointer: int, size: int, limit: int) -> str | None:
        """Read the CodeView record by RVA, or by file pointer if that fails.

        The entry carries both, and a debug record is not required to be
        mapped: some linkers leave `AddressOfRawData` zero and only the file
        pointer valid. Reading the RVA alone also hands an attacker a
        one-DWORD eraser for the build path, which is one of the few
        attributable strings a stripped binary has.
        """
        if not size:
            return None
        take = min(size, limit)
        for record in (_safe_data(pe, rva, take), _file_data(pe, pointer, take)):
            offset = CODEVIEW_PATH_OFFSET.get(record[:4])
            if offset is None:
                continue
            path = safe_text(record[offset:].split(b"\x00")[0], 1024)
            if path:
                return path
        return None

    def _certificate(self, pe, size: int, config: dict[str, Any]) -> dict[str, Any] | None:
        """Presence and embedded names. Never validity: see
        `certificate_common_names` for why that line is drawn here."""
        absent = {"present": False, "common_names": [], "validated": False}
        directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(directories) <= DIRECTORY_SECURITY:
            return absent
        entry = directories[DIRECTORY_SECURITY]
        # This one entry holds a file offset, not an RVA.
        offset, length = entry.VirtualAddress, entry.Size
        if not offset or not length or offset >= size:
            return absent
        scanned = min(length, size - offset,
                      config_int(config, "pe_max_certificate_bytes", 1048576))
        blob = bytes(pe.__data__[offset: offset + scanned])
        return {
            "present": True,
            "offset": offset,
            "size": entry.Size,
            "scanned_bytes": len(blob),
            # A name past the ceiling is a name this scan did not look for,
            # and a report that says so is the difference between "no other
            # signer" and "no other signer that I read far enough to see".
            "scan_truncated": len(blob) < entry.Size,
            "common_names": certificate_common_names(blob),
            "validated": False,
        }

    def _overlay(self, pe, size: int, config: dict[str, Any],
                 certificate: dict[str, Any] | None) -> dict[str, Any] | None:
        """Bytes past the last section that no loader maps.

        The certificate table lives out here too, because that is where the
        format puts it, and counting it as an overlay would report every
        signed binary as carrying an appended payload. It is subtracted when
        it sits at the tail, which is the only place it is allowed to sit,
        *and* begins at or after the overlay does. Without that second test a
        forged security directory covering most of the file erases the
        overlay from the report entirely, which hides a dropper's payload for
        the price of two DWORDs.
        """
        start = pe.get_overlay_data_start_offset()
        if start is None:
            return None
        end = size
        if certificate and certificate.get("present"):
            offset = certificate["offset"]
            tail = offset + certificate["size"]
            if offset >= start and tail >= size - 8:  # alignment padding is permitted
                end = offset
        if start >= end:
            return None
        length = end - start
        cap = config_int(config, "pe_region_entropy_bytes", 16777216)
        floor = config_int(config, "entropy_min_window_bytes", 256)
        entropy, ratio, sampled, _ = (region_entropy(pe.__data__, start, length, cap)
                                      if length >= floor else (None, None, False, 0))
        return {
            "offset": start,
            "size": length,
            "fraction_of_file": round(length / size, 4) if size else 0.0,
            "excludes_certificate": end != size,
            "entropy": entropy,
            "entropy_ratio": ratio,
            "entropy_sampled": sampled,
        }

    # findings

    def findings(self, data: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        """Turn PE structure into things worth a human's attention.

        Nothing here is `high`. `extension_mismatch` earns high because PE
        content under a `.pdf` extension is near-unambiguous deception;
        packing is not deception, it is the normal state of most installers.
        And `GATE_SEVERITY` is medium, so every medium below is a new reason
        for this tool to exit non-zero in somebody's CI. A finding sits at
        medium only if a file deserves a human because of it alone.
        """
        out: list[dict[str, Any]] = []
        sections = data.get("sections") or []
        out.extend(self._section_findings(sections, data, config))
        out.extend(self._import_findings(data, config))
        out.extend(self._other_findings(data, config))
        return out

    def _section_findings(self, sections, data, config):
        out = []
        threshold = config_ratio(config, "pe_section_entropy_ratio", 0.94)
        percent = config_int(config, "pe_virtual_size_percent", 200, minimum=100)
        packers = {p.lower() for p in config_list(config, "pe_packer_sections", [])}
        standard = {s.lower() for s in config_list(config, "pe_standard_sections", [])}

        hot = [s for s in sections
               if s.get("entropy_ratio") is not None and s["entropy_ratio"] >= threshold]
        if hot:
            out.append(mk_finding(self.name, "section_entropy_high",
                "high-entropy section(s): " + ", ".join(
                    f"{s['name']} at {s['entropy_ratio']} of random" for s in hot) +
                ", consistent with a packed, compressed or encrypted section",
                "medium"))

        wx = [s["name"] for s in sections if s["writable"] and s["executable"]]
        if wx:
            out.append(mk_finding(self.name, "writable_executable_section",
                f"section(s) {', '.join(wx)} are both writable and executable, "
                "which is what code that rewrites itself needs and what a "
                "compiler does not emit", "medium"))

        # A virtual size far above the raw size is space reserved in memory
        # that no bytes in the file fill: the room an unpacker unpacks into.
        swollen = [s for s in sections
                   if not s["uninitialised"] and s["raw_size"]
                   and s["virtual_size"] * 100 > s["raw_size"] * percent]
        if swollen:
            out.append(mk_finding(self.name, "virtual_size_mismatch",
                "section(s) " + ", ".join(
                    f"{s['name']} ({s['virtual_size']} virtual vs {s['raw_size']} raw)"
                    for s in swollen) +
                " reserve far more memory than the file provides, the shape of "
                "an unpacking stub", "medium"))

        named = [s["name"] for s in sections if s["name"].lower() in packers]
        if named:
            out.append(mk_finding(self.name, "known_packer_section",
                f"section name(s) {', '.join(named)} match a known packer's "
                "conventional layout", "medium"))

        entry = data.get("entry_point_section")
        entry_section = next((s for s in sections if s["name"] == entry), None)
        if entry_section and entry_section["writable"]:
            out.append(mk_finding(self.name, "entry_point_in_writable_section",
                f"the entry point at {hex(data.get('entry_point', 0))} is in "
                f"'{entry}', which is writable, so the first code to run can "
                "be modified before it runs", "medium"))

        odd = [s["name"] for s in sections
               if s["name"].lower() not in standard and s["name"].lower() not in packers]
        if odd:
            out.append(mk_finding(self.name, "nonstandard_section_name",
                f"section name(s) {', '.join(odd)} are not names a mainstream "
                "toolchain emits", "low"))
        return out

    def _import_findings(self, data, config):
        out = []
        count = data.get("import_count", 0)
        few = config_int(config, "pe_few_imports", 6)
        # A DLL that imports nothing is unusual; an executable that imports
        # nothing cannot call the operating system it runs on, so it must
        # resolve its own imports at runtime, which is what a packed stub does.
        #
        # Gated on `imports_parsed` because an import table that could not be
        # followed is not an absent one, and this is the finding a forged
        # import RVA would otherwise buy at medium.
        if not count and data.get("imports_parsed") and not data.get("is_driver"):
            out.append(mk_finding(self.name, "no_imports",
                "no imports at all, so this cannot reach the API it needs "
                "without resolving it at runtime, the usual mark of a packed "
                "or self-loading binary", "medium"))
        elif 0 < count < few:
            names = sorted({d for d in (data.get("imports") or {})})
            out.append(mk_finding(self.name, "few_imports",
                f"only {count} imported symbol(s) from {', '.join(names)}, thin "
                "enough to suggest the real import table is resolved at "
                "runtime", "low"))

        # The capabilities the import table names outright. This is the
        # stronger of the two views: an import is a symbol the loader will
        # resolve, so there is no question of whether the name means what it
        # looks like. It still does not reach medium, because every name here
        # is one that legitimate software also calls.
        out.extend(apis.capability_findings(
            self.name, data.get("api_capabilities") or {},
            config_int(config, "api_min_names_per_capability", 2),
            view="import"))
        return out

    def _other_findings(self, data, config):
        out = []
        timestamp = data.get("timestamp")
        floor = config_int(config, "pe_min_timestamp", 725846400)
        if timestamp is not None and (timestamp == 0 or timestamp < floor
                                      or timestamp > _now() + 86400):
            out.append(mk_finding(self.name, "implausible_timestamp",
                f"compile timestamp {timestamp} ({data.get('timestamp_iso')}) is "
                "zero, older than the format, or in the future, so it has been "
                "stripped or forged", "low"))

        overlay = data.get("overlay")
        if overlay:
            large = config_int(config, "pe_large_overlay_bytes", 1048576)
            if overlay["size"] >= large:
                out.append(mk_finding(self.name, "large_overlay",
                    f"{overlay['size']} bytes appended after the last section "
                    f"({overlay['fraction_of_file']} of the file), which no "
                    "loader maps and which is where a dropper keeps its payload",
                    "low"))
            else:
                out.append(mk_finding(self.name, "overlay_present",
                    f"{overlay['size']} bytes appended after the last section",
                    "info"))

        callbacks = data.get("tls_callbacks") or []
        if callbacks:
            out.append(mk_finding(self.name, "tls_callbacks_present",
                f"{len(callbacks)} TLS callback(s), which run before the entry "
                "point and therefore before a debugger breaking on it", "low"))

        certificate = data.get("certificate")
        if certificate and certificate.get("present"):
            names = certificate.get("common_names") or []
            detail = "an embedded certificate table is present"
            if names:
                detail += f", naming {', '.join(names[:3])}"
            out.append(mk_finding(self.name, "signature_present",
                detail + "; nothing here validates it", "info"))
        return out


def _share_budget(wants: list[int], budget: int) -> list[int]:
    """Divide `budget` between claimants, smallest claim first.

    Each claimant receives what it asked for, or an equal share of what is
    still unspent, whichever is smaller; a claimant that wanted less than its
    share leaves the remainder to the others. The result depends only on the
    sizes claimed, never on the order they arrive in, which is the property
    that matters here because the order is a field in the file.

    Claimants asking for the same amount are settled as a group rather than
    one after another. Settling them individually leaves the division's
    remainder with whichever of them came last, so two equal sections would
    get 3510 and 3511 bytes according to their position in the table — a one
    byte difference, but enough to move an entropy figure in its fourth
    decimal place and therefore enough to make the ordering observable. Any
    remainder is left unspent instead; at most one byte per claimant.
    """
    groups: dict[int, list[int]] = {}
    for index, want in enumerate(wants):
        groups.setdefault(want, []).append(index)

    grants = [0] * len(wants)
    remaining, unsettled = budget, len(wants)
    for want in sorted(groups):
        indices = groups[want]
        share = min(want, remaining // unsettled)
        for index in indices:
            grants[index] = share
        remaining -= share * len(indices)
        unsettled -= len(indices)
    return grants


def _in_a_section(pe, rva: int) -> bool:
    """Whether an RVA lands in a section that has bytes behind it.

    `pefile.get_data` will resolve an address that is not in any section, by
    falling back to the header buffer or to treating it as a file offset. That
    is helpful when parsing a structure whose location is already trusted and
    dangerous when following a pointer the file supplied.
    """
    if rva < 0:
        return False
    try:
        section = pe.get_section_by_rva(rva)
    except Exception:
        return False
    return section is not None and bool(section.SizeOfRawData)


def _file_data(pe, offset: int, length: int) -> bytes:
    """A bounded read at a file offset rather than an RVA."""
    if offset <= 0 or length <= 0 or offset >= len(pe.__data__):
        return b""
    return bytes(pe.__data__[offset: offset + length])


def _safe_data(pe, rva: int, length: int) -> bytes:
    """A bounded read at an RVA that may not be a real one.

    `pefile.get_data` raises on an address it cannot resolve, which is the
    right behaviour for a caller parsing one structure and the wrong one for a
    caller walking an array: a single bad entry should end the walk, not
    discard the entries already read.
    """
    if rva < 0 or length <= 0:
        return b""
    try:
        return pe.get_data(rva, length) or b""
    except Exception:
        return b""


def _now() -> int:
    return int(time.time())


def _iso_timestamp(value: int) -> str | None:
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        return None


def _section_for_rva(sections: list[dict[str, Any]], rva: int) -> str | None:
    for section in sections:
        start = section["virtual_address"]
        span = max(section["virtual_size"], section["raw_size"], 1)
        if start <= rva < start + span:
            return section["name"]
    return None


# ELF

ELF_MAGIC = b"\x7fELF"

ELF_TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
ELF_MACHINES = {
    0x02: "SPARC", 0x03: "386", 0x08: "MIPS", 0x14: "PPC", 0x15: "PPC64",
    0x16: "S390", 0x28: "ARM", 0x2A: "SUPERH", 0x32: "IA_64", 0x3E: "X86_64",
    0xB7: "AARCH64", 0xF3: "RISCV",
}
ELF_OSABI = {0: "SYSV", 1: "HPUX", 2: "NETBSD", 3: "LINUX", 6: "SOLARIS",
             9: "FREEBSD", 12: "OPENBSD"}
SEGMENT_TYPES = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE",
                 6: "PHDR", 7: "TLS", 0x6474E550: "GNU_EH_FRAME",
                 0x6474E551: "GNU_STACK", 0x6474E552: "GNU_RELRO"}
SECTION_TYPES = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
                 5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
                 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY"}

SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 0x1, 0x2, 0x4
PF_X, PF_W, PF_R = 0x1, 0x2, 0x4
PT_INTERP, PT_DYNAMIC, PT_LOAD, PT_NOTE = 3, 2, 1, 4
PT_GNU_STACK = 0x6474E551
SHT_SYMTAB, SHT_STRTAB, SHT_DYNAMIC, SHT_NOBITS, SHT_NOTE = 2, 3, 6, 8, 7

DT_NULL, DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH = 0, 1, 14, 15, 29

# Section-name families a mainstream toolchain emits, matched by prefix
# because each is an open set: one per DWARF section, one per relocated
# section, one per note, one per Go runtime structure. Enumerating them in
# config would mean a list that goes stale every toolchain release, and the
# cost of getting this wrong is `nonstandard_section_name` firing on
# essentially every binary in existence, which is a finding carrying no
# information at all.
SECTION_NAME_FAMILIES = (".debug", ".zdebug", ".rela", ".rel", ".note", ".gnu",
                         ".data.rel.ro", ".go.", ".llvm")
NT_GNU_BUILD_ID = 3


class ElfExtractor(RandomAccessExtractor):
    """ELF structure, parsed with `struct` and nothing else.

    The asymmetry with the PE extractor is deliberate and is argued in
    `architecture.md`: pay a dependency where the format is genuinely hostile,
    not where it is merely binary. An ELF header, a program header table and a
    section header table are fixed-layout records, and there is no equivalent
    of pefile's accumulated knowledge of malformed real-world files to buy.
    So this one has no optional import, never reports a missing parser, and
    works on a bare checkout.

    That also means every bound is this module's own. Nothing here trusts a
    count, an offset or a size read out of the file: the header supplies
    `e_phnum` and `e_shnum` as sixteen-bit numbers, `sh_offset` and `sh_size`
    as full words, and `e_shstrndx` as an index into a table it also
    describes. Each is clipped against the mapping and capped by config, and
    the section entropy budget is shared across the table rather than granted
    per section, for the reason the PE extractor learned: a per-item ceiling
    is not a bound when the item count is also a field in the file.
    """

    name = "elf"

    def applies_to(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> bool:
        return ctx.get("family") == "elf"

    def parse(self, path: Path, ctx: dict[str, Any],
              config: dict[str, Any]) -> dict[str, Any]:
        with path.open("rb") as handle:
            # Mapped rather than read. The random-access contract permits the
            # extractor to address the file; it does not permit holding it.
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
                return self._parse(data, ctx, config)

    # extraction

    def _parse(self, data, ctx: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
        problems: list[str] = []

        def attempt(label, fn, default):
            try:
                return fn()
            except Exception as exc:
                log.debug("elf %s failed: %s", label, exc)
                problems.append(f"{label}: {type(exc).__name__}: {exc}")
                return default

        size = len(data)
        if size < 64 or data[:4] != ELF_MAGIC:
            raise ValueError("not an ELF: the identification bytes are wrong")

        elf_class, elf_data, version, osabi = data[4], data[5], data[6], data[7]
        if elf_class not in (1, 2):
            raise ValueError(f"unknown ELF class {elf_class}")
        if elf_data not in (1, 2):
            raise ValueError(f"unknown ELF byte order {elf_data}")

        wide = elf_class == 2
        endian = "<" if elf_data == 1 else ">"
        header_fmt = f"{endian}16sHHIQQQIHHHHHH" if wide else f"{endian}16sHHIIIIIHHHHHH"
        header_size = 64 if wide else 52

        (_, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, _,
         e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
         e_shstrndx) = struct.unpack(header_fmt, bytes(data[:header_size]))

        info: dict[str, Any] = {
            "elf_class": "ELF64" if wide else "ELF32",
            "endianness": "little" if endian == "<" else "big",
            "os_abi": osabi,
            "os_abi_label": ELF_OSABI.get(osabi, "unknown"),
            "ident_version": version,
            "version": e_version,
            "type": e_type,
            "type_label": ELF_TYPES.get(e_type, "unknown"),
            "machine": e_machine,
            "machine_label": ELF_MACHINES.get(e_machine, "unknown"),
            "entry": e_entry,
        }

        # SHN_XINDEX: a file with more sections than `e_shnum` can express
        # puts the real count in the first section header and sets the field
        # to zero. Without this a legal file reports no section table at all
        # and earns `no_section_headers`, which is a medium.
        if e_shoff and not e_shnum:
            e_shnum, e_shstrndx = self._extended_counts(
                data, endian, wide, e_shoff, e_shentsize, e_shstrndx, size)

        info["segments"] = attempt(
            "segments",
            lambda: self._segments(data, endian, wide, e_phoff, e_phentsize,
                                   e_phnum, size, config), [])
        info["sections"] = attempt(
            "sections",
            lambda: self._sections(data, endian, wide, e_shoff, e_shentsize,
                                   e_shnum, e_shstrndx, size, config), [])

        # A header that claims a table the extractor could not read is not the
        # same fact as a header that claims none, and `e_shentsize = 0` -- one
        # two-byte field -- used to produce the first while the report stated
        # the second. The file still runs: the kernel never reads section
        # headers. So `stripped` said "no symbol table" about a binary with a
        # full one, and the entropy and packer-name findings vanished without
        # a word.
        info["section_headers_present"] = bool(info["sections"])
        if e_shoff and e_shnum and not info["sections"]:
            problems.append(
                f"sections: the header claims {e_shnum} section header(s) of "
                f"{e_shentsize} bytes at offset {e_shoff}, which could not be read")
        if e_phoff and e_phnum and not info["segments"]:
            problems.append(
                f"segments: the header claims {e_phnum} program header(s) of "
                f"{e_phentsize} bytes at offset {e_phoff}, which could not be read")

        info["entry_segment"] = _segment_for_address(info["segments"], e_entry)
        info["interpreter"] = attempt(
            "interpreter", lambda: self._interpreter(data, info["segments"], config), None)
        info.update(attempt("dynamic",
                            lambda: self._dynamic(data, endian, wide, info, size, config),
                            {"needed": [], "soname": None, "rpath": None,
                             "runpath": None, "dynamic_entries": 0,
                             "needed_truncated": False,
                             "dynamic_truncated": False}))
        info["build_id"] = attempt(
            "notes", lambda: self._build_id(data, endian, info["sections"], config), None)
        # None, not False, when the table was never read. "There is no symbol
        # table" and "I could not look" are different facts, and only the
        # first is a statement about the binary.
        info["stripped"] = (None if not info["sections"]
                            else not any(s["type"] == SHT_SYMTAB
                                         for s in info["sections"]))
        info["statically_linked"] = (
            None if not info["segments"] else
            info["interpreter"] is None
            and not any(s["type"] == PT_DYNAMIC for s in info["segments"]))
        info["trailing"] = attempt(
            "trailing",
            lambda: self._trailing(data, info, e_shoff, e_shentsize, e_shnum,
                                   size, config), None)

        # Every cap this extractor applies says so. The project's own rule,
        # learned from the YARA extractor: `truncated` is the field whose
        # whole job is to say that nothing was left out, and a cap that goes
        # unrecorded is a report that looks complete because nobody counted.
        info["sections_truncated"] = getattr(self, "_sections_truncated", False)
        info["segments_truncated"] = getattr(self, "_segments_truncated", False)
        info["names_truncated"] = getattr(self, "_names_truncated", False)
        for label, flag, cap in (
                ("sections", info["sections_truncated"], "elf_max_sections"),
                ("segments", info["segments_truncated"], "elf_max_segments"),
                ("names", info["names_truncated"], "elf_max_string_table_bytes"),
                ("dynamic", info.get("dynamic_truncated"), "elf_max_dynamic_entries"),
                ("needed", info.get("needed_truncated"), "elf_max_listed_names")):
            if flag:
                problems.append(f"{label}: the table was longer than {cap}, so it "
                                "was read only as far as that")

        starved = [s["name"] for s in info["sections"]
                   if s.get("entropy_skipped") == "budget_exhausted"]
        if starved:
            problems.append(
                "sections: the entropy budget ran out, so "
                f"{len(starved)} section(s) were not scored: {', '.join(starved[:8])}")
        if problems:
            info["parse_errors"] = problems
        return info

    @staticmethod
    def _extended_counts(data, endian, wide, shoff, entry_size, shstrndx, size):
        """Read SHN_XINDEX's real section count and name index out of shdr[0]."""
        expected = 64 if wide else 40
        if entry_size < expected or shoff + expected > size:
            return 0, shstrndx
        fmt = f"{endian}IIQQQQIIQQ" if wide else f"{endian}IIIIIIIIII"
        fields = struct.unpack(fmt, bytes(data[shoff:shoff + expected]))
        count, link = fields[5], fields[6]
        return count, link if shstrndx == 0xFFFF else shstrndx

    def _segments(self, data, endian, wide, offset, entry_size, count, size, config):
        """The program header table: what the loader will actually map.

        Capped and clipped. `e_phnum` is a sixteen-bit field, so a header
        under a hundred bytes can ask for 65535 entries, and `p_offset` and
        `p_filesz` are full words that need not describe a region of the file
        that exists.
        """
        expected = 56 if wide else 32
        if not offset or not count or entry_size < expected:
            return []
        fmt = f"{endian}IIQQQQQQ" if wide else f"{endian}IIIIIIII"
        limit = min(count, config_int(config, "elf_max_segments", 256))
        out = []
        self._segments_truncated = count > limit
        for index in range(limit):
            start = offset + index * entry_size
            if start + expected > size:
                break
            fields = struct.unpack(fmt, bytes(data[start:start + expected]))
            if wide:
                p_type, flags, p_offset, vaddr, _, filesz, memsz, align = fields
            else:
                # The 32-bit layout puts p_flags after p_memsz rather than
                # after p_type. Reading it as a narrow copy of the 64-bit
                # record produces a file that parses and lies about which
                # segments are executable.
                p_type, p_offset, vaddr, _, filesz, memsz, flags, align = fields
            out.append({
                "type": p_type,
                "type_label": SEGMENT_TYPES.get(p_type, f"0x{p_type:x}"),
                "flags": flags,
                "readable": bool(flags & PF_R),
                "writable": bool(flags & PF_W),
                "executable": bool(flags & PF_X),
                "offset": p_offset,
                "vaddr": vaddr,
                "file_size": filesz,
                "memory_size": memsz,
                "align": align,
                "in_file": p_offset < size,
            })
        return out

    def _sections(self, data, endian, wide, offset, entry_size, count,
                  shstrndx, size, config):
        """The section header table, with per-section entropy.

        The entropy budget is shared across the table for the same reason it
        is in the PE extractor: `elf_region_entropy_bytes` bounds one section
        and `e_shnum` bounds nothing, so a header can ask for a ceiling's
        worth of work sixty-five thousand times over. Allocation is by size so
        that reordering the table cannot starve a section.
        """
        expected = 64 if wide else 40
        if not offset or not count or entry_size < expected:
            return []
        fmt = f"{endian}IIQQQQIIQQ" if wide else f"{endian}IIIIIIIIII"
        limit = min(count, config_int(config, "elf_max_sections", 512))
        self._sections_truncated = count > limit

        raw = []
        for index in range(limit):
            start = offset + index * entry_size
            if start + expected > size:
                break
            (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
             sh_link, _, _, _) = struct.unpack(fmt, bytes(data[start:start + expected]))
            raw.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link))

        names, self._names_truncated = self._section_names(
            data, endian, wide, offset, entry_size, shstrndx, len(raw), size, config)

        # SHT_NOBITS occupies address space and no file space, so its offset
        # and size do not describe a region of the file and must not be scored.
        lengths = [0 if kind == SHT_NOBITS or sh_offset >= size
                   else max(0, min(sh_size, size - sh_offset))
                   for _, kind, _, _, sh_offset, sh_size, _ in raw]
        cap = config_int(config, "elf_region_entropy_bytes", 16777216)
        grants = _share_budget([min(length, cap) for length in lengths],
                               config_int(config, "elf_entropy_budget_bytes", 67108864))
        floor = config_int(config, "entropy_min_window_bytes", 256)

        out = []
        for index, (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                    sh_link) in enumerate(raw):
            length, grant = lengths[index], grants[index]
            skipped = None
            if sh_type == SHT_NOBITS:
                skipped = "no_file_bytes"
            elif length < floor:
                skipped = "too_short" if length else "no_bytes"
            elif grant < floor:
                skipped = "budget_exhausted"
            if skipped:
                entropy, ratio, sampled, scored = None, None, False, 0
            else:
                entropy, ratio, sampled, scored = region_entropy(
                    data, sh_offset, length, grant)
                if not scored:
                    skipped = "unreadable"
            out.append({
                "name": _name_at(names, sh_name),
                "type": sh_type,
                "type_label": SECTION_TYPES.get(sh_type, f"0x{sh_type:x}"),
                "flags": sh_flags,
                "alloc": bool(sh_flags & SHF_ALLOC),
                "writable": bool(sh_flags & SHF_WRITE),
                "executable": bool(sh_flags & SHF_EXECINSTR),
                "addr": sh_addr,
                "offset": sh_offset,
                "size": sh_size,
                "link": sh_link,
                "scored_bytes": scored,
                "entropy": entropy,
                "entropy_ratio": ratio,
                "entropy_sampled": sampled,
                "entropy_skipped": skipped,
            })
        return out

    def _section_names(self, data, endian, wide, offset, entry_size, shstrndx,
                       count, size, config):
        """The section name string table, returned whole rather than indexed.

        Names are resolved by scanning from each `sh_name` to the next NUL,
        not by walking the table and keying the offsets that follow one. GNU
        ld tail-merges `.shstrtab`, so most names are interior offsets:
        `.rela.plt\\0` also serves `.plt` at +5 and `.plt.got\\0` serves `.got`
        at +4. Indexing only post-NUL offsets mis-resolved at least one name
        in 3181 of 3185 real binaries on this machine, which made
        `nonstandard_section_name` fire on almost every ELF in existence and
        let a crafted `sh_name` pointing into the middle of a string evade
        `packer_section_name` entirely.
        """
        expected = 64 if wide else 40
        if shstrndx == 0 or shstrndx >= count:
            return b"", False
        start = offset + shstrndx * entry_size
        if start + expected > size:
            return b"", False
        fmt = f"{endian}IIQQQQIIQQ" if wide else f"{endian}IIIIIIIIII"
        fields = struct.unpack(fmt, bytes(data[start:start + expected]))
        kind, table_offset, table_size = fields[1], fields[4], fields[5]
        # A NOBITS section describes no file bytes, so following its offset
        # decodes section names out of whatever happens to be there -- the ELF
        # header itself, in the case that found this.
        if kind == SHT_NOBITS or table_offset >= size:
            return b"", False
        cap = config_int(config, "elf_max_string_table_bytes", 262144)
        available = min(table_size, size - table_offset)
        return bytes(data[table_offset:table_offset + min(available, cap)]), available > cap

    def _interpreter(self, data, segments, config):
        for segment in segments:
            if segment["type"] != PT_INTERP or not segment["in_file"]:
                continue
            length = min(segment["file_size"],
                         config_int(config, "elf_max_string_bytes", 4096),
                         len(data) - segment["offset"])
            blob = bytes(data[segment["offset"]:segment["offset"] + length])
            return blob.split(b"\x00")[0].decode("ascii", "replace") or None
        return None

    def _dynamic(self, data, endian, wide, info, size, config):
        """The dynamic table: what this binary loads and where it looks.

        `runpath` and `rpath` matter for triage because they say where the
        loader will search before the system paths, which is a hijack the file
        itself asks for.
        """
        empty = {"needed": [], "soname": None, "rpath": None, "runpath": None,
                 "dynamic_entries": 0, "needed_truncated": False,
                 "dynamic_truncated": False}
        section = next((s for s in info["sections"] if s["type"] == SHT_DYNAMIC), None)
        segment = next((s for s in info["segments"]
                        if s["type"] == PT_DYNAMIC and s["in_file"]), None)
        if section is not None and section["offset"] < size:
            offset, length, link = section["offset"], section["size"], section["link"]
        elif segment is not None:
            offset, length, link = segment["offset"], segment["file_size"], None
        else:
            return empty

        strings = self._dynamic_strings(data, info, link, size, config)
        word = f"{endian}QQ" if wide else f"{endian}II"
        step = 16 if wide else 8
        length = min(length, size - offset)
        cap = config_int(config, "elf_max_dynamic_entries", 1024)
        available = length // step
        limit = min(available, cap)
        name_cap = config_int(config, "elf_max_listed_names", 128)

        # Whether the walk ended because the file said so. Stopping at DT_NULL
        # is the table ending; stopping at the cap is this extractor giving
        # up. Reporting the first as the second made a five-entry table
        # announce itself as truncated on every ordinary binary.
        terminated = False
        needed, soname, rpath, runpath, seen, dropped = [], None, None, None, 0, False
        for index in range(limit):
            tag, value = struct.unpack(
                word, bytes(data[offset + index * step:offset + (index + 1) * step]))
            seen += 1
            if tag == DT_NULL:
                terminated = True
                break
            if tag == DT_NEEDED:
                if len(needed) < name_cap:
                    needed.append(_read_string(strings, value, config))
                else:
                    dropped = True
            elif tag == DT_SONAME:
                soname = _read_string(strings, value, config)
            elif tag == DT_RPATH:
                rpath = _read_string(strings, value, config)
            elif tag == DT_RUNPATH:
                runpath = _read_string(strings, value, config)
        return {"needed": [n for n in needed if n], "soname": soname,
                "rpath": rpath, "runpath": runpath, "dynamic_entries": seen,
                "needed_truncated": dropped,
                "dynamic_truncated": not terminated and seen >= cap}

    def _dynamic_strings(self, data, info, link, size, config):
        """The `.dynstr` bytes, found through `sh_link` or by name."""
        target = None
        if link is not None and 0 < link < len(info["sections"]):
            target = info["sections"][link]
        if target is None:
            target = next((s for s in info["sections"] if s["name"] == ".dynstr"), None)
        if target is None or target["offset"] >= size:
            return b""
        length = min(target["size"], size - target["offset"],
                     config_int(config, "elf_max_string_table_bytes", 262144))
        return bytes(data[target["offset"]:target["offset"] + length])

    def _build_id(self, data, endian, sections, config):
        """The GNU build id, which is the closest ELF has to a PDB path."""
        section = next((s for s in sections
                        if s["type"] == SHT_NOTE and "build-id" in s["name"]), None)
        if section is None or not section["scored_bytes"] and not section["size"]:
            return None
        offset, length = section["offset"], min(section["size"], 4096)
        if offset + 12 > len(data):
            return None
        name_size, desc_size, kind = struct.unpack(
            f"{endian}III", bytes(data[offset:offset + 12]))
        if kind != NT_GNU_BUILD_ID or desc_size > 64:
            return None
        start = offset + 12 + ((name_size + 3) // 4) * 4
        if start + desc_size > offset + length or start + desc_size > len(data):
            return None
        return bytes(data[start:start + desc_size]).hex()

    def _trailing(self, data, info, shoff, shentsize, shnum, size, config):
        """Bytes past everything the file describes.

        The ELF counterpart of a PE overlay, and computed the same way: the
        end of the last thing any header accounts for, subtracted from the
        size of the file. Only regions that are actually inside the file
        count, or a forged offset would push the boundary past the end and
        report no trailing data at all.
        """
        end = 0
        for section in info["sections"]:
            if section["type"] == SHT_NOBITS or section["offset"] >= size:
                continue
            end = max(end, min(section["offset"] + section["size"], size))
        for segment in info["segments"]:
            if not segment["in_file"]:
                continue
            end = max(end, min(segment["offset"] + segment["file_size"], size))
        if shoff and shnum and shoff < size:
            end = max(end, min(shoff + shentsize * shnum, size))
        if end >= size:
            return None

        length = size - end
        cap = config_int(config, "elf_region_entropy_bytes", 16777216)
        floor = config_int(config, "entropy_min_window_bytes", 256)
        entropy, ratio, sampled, _ = (region_entropy(data, end, length, cap)
                                      if length >= floor else (None, None, False, 0))
        return {
            "offset": end,
            "size": length,
            "fraction_of_file": round(length / size, 4) if size else 0.0,
            "entropy": entropy,
            "entropy_ratio": ratio,
            "entropy_sampled": sampled,
        }

    # findings

    def findings(self, data: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        """The same tiering discipline the PE extractor is held to.

        Nothing here is `high`. `GATE_SEVERITY` is medium, so a finding earns
        medium only if a file deserves a human because of it alone. Being
        stripped and being statically linked are `info`, however unusual they
        may look, because release builds are stripped and Go binaries are
        static: a level that fires on most of a distribution is a level that
        tells an analyst nothing.
        """
        out: list[dict[str, Any]] = []
        out.extend(self._segment_findings(data, config))
        out.extend(self._section_findings(data, config))
        out.extend(self._linkage_findings(data, config))
        return out

    def _segment_findings(self, data, config):
        out = []
        segments = data.get("segments") or []
        # PT_LOAD only. PT_GNU_STACK is a flags-only marker rather than a
        # mapping, and `gcc -z execstack` sets it on request, so counting it
        # here called an ordinary build "a loadable segment mapped writable
        # and executable" -- both halves untrue, at medium, in somebody's CI.
        wx = [s for s in segments
              if s["type"] == PT_LOAD and s["writable"] and s["executable"]]
        if wx:
            out.append(mk_finding(self.name, "writable_executable_segment",
                f"{len(wx)} loadable segment(s) are mapped both writable and "
                "executable, which no mainstream toolchain emits and which "
                "self-modifying code needs", "medium"))

        if any(s["type"] == PT_GNU_STACK and s["executable"] for s in segments):
            out.append(mk_finding(self.name, "executable_stack",
                "the stack is marked executable, which a modern toolchain only "
                "does when asked", "low"))

        loadable = [s for s in segments if s["type"] == PT_LOAD]
        entry = data.get("entry")
        if loadable and entry:
            holder = next((s for s in loadable
                           if s["vaddr"] <= entry < s["vaddr"] + s["memory_size"]), None)
            if holder is None:
                out.append(mk_finding(self.name, "entry_point_outside_segments",
                    f"the entry point at {hex(entry)} is not inside any loadable "
                    "segment, so the file cannot start the way its header says",
                    "medium"))
            elif not holder["executable"]:
                out.append(mk_finding(self.name, "entry_point_not_executable",
                    f"the entry point at {hex(entry)} is in a segment that is not "
                    "mapped executable", "medium"))
        return out

    def _section_findings(self, data, config):
        out = []
        sections = data.get("sections") or []
        if not data.get("section_headers_present"):
            out.append(mk_finding(self.name, "no_section_headers",
                "the section header table is absent, which every mainstream "
                "toolchain emits and several packers remove", "medium"))
            return out

        threshold = config_ratio(config, "elf_section_entropy_ratio", 0.94)
        # Only sections the loader maps, and only those it maps writable or
        # executable. Measured against 7119 real binaries, scoring every
        # section fired this medium on 8.5% of them: 548 from `.debug_*`
        # alone, because DWARF is dense, and the rest from read-only tables --
        # a 256-byte byte-permutation table reaches a ratio above 1.0 while
        # being the most ordered data there is, since the reference is an
        # estimate of what a random *sample* reaches. Debug data is not mapped
        # and a payload has to be mapped to run, which is the line drawn here.
        hot = [s for s in sections
               if s.get("entropy_ratio") is not None and s["entropy_ratio"] >= threshold
               and s["alloc"] and (s["writable"] or s["executable"])]
        if hot:
            out.append(mk_finding(self.name, "section_entropy_high",
                "high-entropy section(s): " + ", ".join(
                    f"{s['name']} at {s['entropy_ratio']} of random" for s in hot) +
                ", consistent with a packed, compressed or encrypted section",
                "medium"))

        packers = {p.lower() for p in config_list(config, "elf_packer_sections", [])}
        standard = {p.lower() for p in config_list(config, "elf_standard_sections", [])}
        named = [s["name"] for s in sections if s["name"].lower() in packers]
        if named:
            out.append(mk_finding(self.name, "packer_section_name",
                f"section name(s) {', '.join(named)} match a known packer's "
                "conventional layout", "medium"))

        odd = [s["name"] for s in sections
               if s["name"] and s["name"].lower() not in standard
               and s["name"].lower() not in packers
               and not s["name"].startswith(SECTION_NAME_FAMILIES)]
        if odd:
            out.append(mk_finding(self.name, "nonstandard_section_name",
                f"section name(s) {', '.join(odd[:8])} are not names a mainstream "
                "toolchain emits", "low"))
        return out

    def _linkage_findings(self, data, config):
        out = []
        for key, tag in (("runpath", "DT_RUNPATH"), ("rpath", "DT_RPATH")):
            value = data.get(key)
            if value:
                out.append(mk_finding(self.name, f"{key}_set",
                    f"{tag} is '{value}', so the loader searches there before the "
                    "system paths and a writable entry in it is a hijack the "
                    "binary asks for", "low"))

        trailing = data.get("trailing")
        if trailing:
            large = config_int(config, "elf_large_trailing_bytes", 1048576)
            if trailing["size"] >= large:
                out.append(mk_finding(self.name, "large_trailing_data",
                    f"{trailing['size']} bytes past everything the headers "
                    f"account for ({trailing['fraction_of_file']} of the file), "
                    "which no loader maps", "low"))
            else:
                out.append(mk_finding(self.name, "trailing_data_present",
                    f"{trailing['size']} bytes past everything the headers "
                    "account for", "info"))

        if data.get("stripped"):
            out.append(mk_finding(self.name, "stripped_symbols",
                "no symbol table, which is ordinary for a release build and is "
                "recorded because it bounds what any later analysis can say",
                "info"))
        if data.get("statically_linked"):
            out.append(mk_finding(self.name, "statically_linked",
                "no interpreter and no dynamic section, so nothing is resolved "
                "at load time", "info"))
        if data.get("build_id"):
            out.append(mk_finding(self.name, "build_id_present",
                f"GNU build id {data['build_id']}", "info"))
        return out


# C0 (0x00-0x1F), DEL, and C1 (0x80-0x9F). C1 matters because 0x9B is the
# single-byte form of the CSI introducer that `ESC [` spells in two, so a
# string carrying it repaints a terminal without containing an ESC at all. It
# survives the one path in this project that decodes to `str` before
# sanitising -- a certificate common name read as UTF-16.
CONTROL_CHARACTERS = ({c: None for c in range(0x20)} | {0x7F: None}
                      | {c: None for c in range(0x80, 0xA0)})


def safe_text(raw: bytes | str, limit: int = 512) -> str:
    """Decode a string the sample supplied, with the control bytes removed.

    Every string in this file comes out of the sample: a section name, an
    interpreter path, a DT_RUNPATH, a PDB path, a certificate common name. All
    of them end up in a report an analyst reads in a terminal, and a run of
    ANSI escapes in one of them can move the cursor up and clear the screen.
    A sample whose RUNPATH is "\x1b[6A\x1b[0J  findings (info max):" erases the
    three medium findings printed above it and prints a clean-looking block in
    their place, which is the most direct attack on a triage tool there is:
    not evading a finding, but unprinting one.

    Length is capped for the same reason. `decode(..., "replace")` alone keeps
    every control character, so it is not enough on its own.
    """
    text = raw.decode("ascii", "replace") if isinstance(raw, bytes) else raw
    text = text.translate(CONTROL_CHARACTERS)
    return text[:limit]


def _name_at(table: bytes, offset: int) -> str:
    """One name out of a string table, read from `offset` to the next NUL."""
    if not 0 <= offset < len(table):
        return f"<name+{offset}>" if offset >= 0 else "<name+invalid>"
    end = table.find(b"\x00", offset)
    return safe_text(table[offset:end if end >= 0 else len(table)], 256)


def _read_string(blob: bytes, offset: int, config: dict[str, Any]) -> str | None:
    """One NUL-terminated string out of a table, bounded.

    The offset comes from a dynamic entry and the table from a section header,
    so neither is trustworthy and both are the file's own account of itself.
    """
    if offset < 0 or offset >= len(blob):
        return None
    cap = config_int(config, "elf_max_string_bytes", 4096)
    end = blob.find(b"\x00", offset, offset + cap)
    end = end if end >= 0 else min(offset + cap, len(blob))
    return safe_text(blob[offset:end]) or None


def _segment_for_address(segments: list[dict[str, Any]], address: int) -> str | None:
    for segment in segments:
        if segment["type"] != PT_LOAD:
            continue
        if segment["vaddr"] <= address < segment["vaddr"] + segment["memory_size"]:
            return segment["type_label"]
    return None


# YARA

try:  # optional, needs libyara, so not a hard requirement
    import yara as _yara

    HAVE_YARA = True
except ImportError:
    _yara = None
    HAVE_YARA = False


#: Rules shipped with the project. User paths from config are added to these
#: rather than replacing them.
BUNDLED_RULES = Path(__file__).resolve().parent / "rules"

RULE_SUFFIXES = (".yar", ".yara")


def rule_files(config: dict[str, Any]) -> tuple[list[Path], list[str]]:
    """Every rule file to compile, bundled first, then configured paths.

    Returns the files and whatever was wrong with the configuration, because
    an unusable rule path has to reach the report. A path that does not exist,
    is not a regular file, is a `Path` where a string was expected, or cannot
    be read produced a scan that looked like a full run while the configured
    rules never executed. Silence there is the failure this project names most
    often: a report that looks clean for a reason the reader cannot see.

    Paths are resolved and de-duplicated. Naming the bundled directory in
    `yara_rule_paths` is a natural thing to do, since configured paths add to
    the bundled set rather than replacing it, and without this every rule in
    it would match twice and emit two findings.

    The filesystem work is deliberately independent of yara: it answers "is
    there anything to scan with" without the library installed, which is what
    lets the extractor tell "no rules" apart from "no parser".
    """
    problems: list[str] = []
    roots: list[Path] = [BUNDLED_RULES]
    for entry in config_list(config, "yara_rule_paths", []):
        if not isinstance(entry, str) or not entry.strip():
            problems.append(f"config: yara_rule_paths entry {entry!r} is not a path, skipped")
            continue
        roots.append(Path(entry))

    found: list[Path] = []
    seen: set[str] = set()

    def take(path: Path) -> None:
        try:
            key = str(path.resolve())
        except OSError as exc:
            problems.append(f"config: {path} could not be resolved: {exc}")
            return
        if key not in seen:
            seen.add(key)
            found.append(path)

    for root in roots:
        try:
            if root.is_file():
                take(root)
            elif root.is_dir():
                # Suffix only. An entry that is a dangling symlink, a symlink
                # loop or a directory named `sub.yar` used to fail an
                # `is_file()` test here and disappear without a word, which
                # silently shortened the rule set: a moved rules repository or
                # an unchecked-out submodule is ordinary breakage and it must
                # not read as "these rules found nothing". Passing it to the
                # compiler instead means the failure is reported by the same
                # path as a syntax error.
                for entry in sorted(root.iterdir()):
                    if entry.suffix.lower() in RULE_SUFFIXES:
                        take(entry)
            elif root != BUNDLED_RULES:
                # The bundled directory being absent is a checkout problem and
                # is reported by the extractor declining; a configured path
                # that is not there is a configuration problem and is this.
                problems.append(f"config: {root} is not a rule file or directory")
        except OSError as exc:
            problems.append(f"config: {root} is unreadable: {exc}")
    return found, problems


def rule_fingerprint(paths: list[Path]) -> tuple:
    """What a compiled rule set was compiled from.

    The extractor caches its compiled rules, and `analyse_directory` hands one
    instance to every file, so the cache needs a key or it answers with
    whichever rule set it happened to see first. That is worse than
    recompiling: a report says which rule files ran, and a stale cache makes
    that statement false rather than merely slow.
    """
    stamps = []
    for path in paths:
        try:
            stat = path.stat()
            stamps.append((str(path), stat.st_mtime_ns, stat.st_size))
        except OSError:
            stamps.append((str(path), None, None))
    return tuple(stamps)


def compile_rules(paths: list[Path], allow_includes: bool = False
                  ) -> tuple[list[tuple[str, Any]], list[str]]:
    """Compile each rule file separately.

    One file at a time rather than one `yara.compile` over all of them,
    because a syntax error anywhere in a combined compile loses every rule in
    it. That is the same isolation the pipeline gives extractors and the PE
    extractor gives directories, applied to rule files: a rule someone is
    halfway through writing must not disable the bundled set.

    `include` is disabled unless `yara_allow_includes` turns it on. An include
    is resolved relative to the rule file and is not confined to the rules
    directory, so `include "/etc/passwd"` is opened and parsed, and YARA
    quotes offending tokens in its syntax errors — which puts a rule file in
    reach of the whole filesystem and of the report. A bundled set does not
    need includes, and a rules directory fed from somewhere else is exactly
    the case that should not have them by default.

    The namespace is the file's stem, so a match can say which file claimed it.
    """
    compiled, problems = [], []
    for path in paths:
        try:
            compiled.append(
                (path.stem, _yara.compile(filepath=str(path), includes=allow_includes)))
        except Exception as exc:
            log.warning("yara rule file %s failed to compile: %s", path, exc)
            problems.append(f"{path.name}: {type(exc).__name__}: {exc}")
    return compiled, problems


class YaraExtractor(RandomAccessExtractor):
    """Pattern matching against the bundled and configured rule sets.

    Random-access because yara maps the file itself. `match(filepath=...)`
    hands libyara the path and it does its own bounded read, which is the
    third kind's contract exactly; the alternative, `match(data=...)`, needs
    the sample whole in memory and is therefore not available to this project.

    It is also the first extractor that can bound its own execution time.
    `architecture.md` records that isolation covers a parser that raises and
    not one that hangs, and a rule set is the easiest way to write a hang by
    accident. yara takes a timeout and raises on it, and the timeout here is
    spent across the whole rule set rather than granted to each file in it,
    because the number of rule files is a directory listing and not a bound.

    Findings carry offsets and never bytes. A rule that matches a credential
    pattern would otherwise put the credential into a report that gets stored,
    piped and shared, which turns a detection into a leak. The extractor never
    reads `matched_data`, so there is no flag to leave switched on — and
    `console_callback` is installed for the same reason, because YARA's
    `console` module writes to the process's own stdout when nothing captures
    it, which put sample bytes on the terminal from inside a rule, under
    `--quiet`, without appearing anywhere in the report.

    Every match is filed under one finding key, `yara_match`, with the rule
    name carried in the finding's data rather than promoted to a key of its
    own. Rules are user-extensible, and a key set that grows with somebody's
    rules directory is not a key set a dashboard can count on.
    """

    name = "yara"

    def __init__(self) -> None:
        self._rules: list[tuple[str, Any]] = []
        self._fingerprint: tuple | None = None
        self._problems: list[str] = []
        self._loaded_from: list[str] = []

    def applies_to(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> bool:
        # Nothing configured is not a failure. No parser for what *is*
        # configured is, and that is decided in `parse`.
        paths, problems = rule_files(config)
        return bool(paths or problems)

    def _load(self, config: dict[str, Any], paths: list[Path]) -> list[tuple[str, Any]]:
        """Compile once per rule set, not once per sample.

        Compilation is the expensive part of a yara run and the samples are
        the cheap part, which is why `analyse_directory` builds its extractors
        once and hands the same instances to every file. This is the first
        extractor for which that reuse is worth anything — and the first that
        therefore needs to notice when the thing it cached has changed.
        """
        # Both inputs to the compile, not just one. Keying on the files alone
        # meant that flipping `yara_allow_includes` off after a permissive
        # compile kept running the include-bearing rule set, with empty
        # parse_errors, after the caller had explicitly asked for it not to.
        allow = config_bool(config, "yara_allow_includes", False)
        fingerprint = (allow, rule_fingerprint(paths))
        if fingerprint != self._fingerprint:
            self._rules, self._problems = compile_rules(paths, allow)
            self._loaded_from = [p.name for p in paths]
            self._fingerprint = fingerprint
        return self._rules

    def parse(self, path: Path, ctx: dict[str, Any],
              config: dict[str, Any]) -> dict[str, Any]:
        paths, problems = rule_files(config)
        if not HAVE_YARA:
            raise ParserUnavailable(
                f"yara-python is not installed, so {len(paths)} rule file(s) were "
                "not run; install it with 'pip install yara-python'")

        rules = self._load(config, paths)
        problems = problems + list(self._problems)

        ceiling = config_int(config, "yara_max_scan_bytes", 67108864)
        if ctx["size"] > ceiling:
            # The same refusal `max_parse_bytes` makes, for the same reason
            # and at a lower threshold. Fast matching bounds the common case
            # but libyara ignores it for any string whose condition reads its
            # count, offset or length, and a rule can allocate through the
            # console module until the deadline fires. Neither cost is bounded
            # by anything this extractor controls, so the one thing it can
            # bound is how much file it hands over.
            return {
                "rule_files": self._loaded_from,
                "namespaces": [namespace for namespace, _ in rules],
                "matches": [], "match_count": 0, "matches_truncated": False,
                "parse_errors": problems + [
                    f"scan: skipped, {ctx['size']} bytes is above "
                    f"yara_max_scan_bytes={ceiling}"],
            }

        budget = config_int(config, "yara_timeout_seconds", 10)
        limit = config_int(config, "yara_max_rules_reported", 64)
        fast = config_bool(config, "yara_fast_matching", True)

        matches: list[dict[str, Any]] = []
        deadline = time.monotonic() + budget
        for namespace, compiled in rules:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                problems.append(
                    f"{namespace}: not run, the {budget}s scan budget was already spent")
                continue
            try:
                found = compiled.match(
                    filepath=str(path),
                    timeout=max(1, int(remaining)),
                    fast=fast,
                    # Discarded rather than printed. See the class docstring.
                    console_callback=lambda line, ns=namespace: log.debug(
                        "yara console (%s): %s", ns, line),
                )
            except Exception as exc:
                # A timeout is the interesting case and it is reported like
                # any other failure: a rule set that could not finish is not
                # a rule set that found nothing.
                log.warning("yara namespace %s failed on %s: %s", namespace, path, exc)
                problems.append(f"{namespace}: {type(exc).__name__}: {exc}")
                continue
            for match in found:
                matches.append(self._describe(match, namespace, config, not fast))

        data: dict[str, Any] = {
            "rule_files": self._loaded_from,
            "namespaces": [namespace for namespace, _ in rules],
            "fast_matching": fast,
            "matches": matches[:limit],
            "match_count": len(matches),
            "matches_truncated": len(matches) > limit,
        }
        if problems:
            data["parse_errors"] = problems
        return data

    def _describe(self, match, namespace: str, config: dict[str, Any],
                  complete: bool = True) -> dict[str, Any]:
        limit = config_int(config, "yara_max_matches", 64)
        meta = dict(getattr(match, "meta", {}) or {})
        strings = []
        for string in getattr(match, "strings", []) or []:
            instances = list(getattr(string, "instances", []) or [])
            strings.append({
                "identifier": string.identifier,
                # Offsets and lengths only. `matched_data` is never read.
                "offsets": [i.offset for i in instances[:limit]],
                "lengths": [i.matched_length for i in instances[:limit]],
                "count": len(instances),
                "truncated": len(instances) > limit,
                # Whether `count` is a total. Under fast matching libyara
                # stops after the first occurrence of a string, so a bomb with
                # seven hundred thousand hits reported `count: 1` and
                # `truncated: false` -- and `truncated` is the field whose
                # whole job is to say that nothing was left out.
                "complete": complete and len(instances) <= limit,
            })
        return {
            "rule": match.rule,
            "namespace": namespace,
            "tags": list(getattr(match, "tags", []) or []),
            "severity": self._severity(meta, config),
            "description": meta.get("description"),
            "meta": meta,
            "strings": strings,
        }

    @staticmethod
    def _severity(meta: dict[str, Any], config: dict[str, Any]) -> str:
        """A rule's own severity, if it declared one this project recognises.

        The default is `info` rather than something louder, because a rule
        that forgot to say how much it matters should not be able to fail
        somebody's build by forgetting.
        """
        for candidate in (meta.get("severity"), config.get("yara_default_severity")):
            # `isinstance` before the membership test, and not after: an
            # unhashable config value raises on `in` against a dict, and that
            # exception would cost the whole extractor every match it had
            # already found.
            if isinstance(candidate, str) and candidate in SEVERITY_RANK:
                return candidate
        return "info"

    def findings(self, data: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        for match in data.get("matches") or []:
            where = match["strings"][0]["offsets"] if match["strings"] else []
            detail = (match.get("description")
                      or f"rule '{match['rule']}' matched")
            if where:
                detail += f", first at offset {where[0]}"
            tags = match.get("tags") or []
            if tags:
                detail += f" [{', '.join(tags)}]"
            out.append(mk_finding(self.name, "yara_match",
                                  f"{match['rule']}: {detail}", match["severity"]))
        return out


def default_extractors() -> list[Extractor]:
    """Order matters for the header phase: file type runs first so the stream
    phase can gate on the family it publishes."""
    return [FileTypeExtractor(), HashExtractor(), EntropyExtractor(),
            StringsExtractor(),
            PEExtractor(), ElfExtractor(), YaraExtractor(),
            FuzzyHashExtractor()]
