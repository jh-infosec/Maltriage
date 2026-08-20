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

Config is read through the validated accessors in sample_data, never with a
bare `.get`, so a bad value falls back to a default instead of silently
producing a wrong answer.
"""

from __future__ import annotations
import hashlib
import logging
import math
import struct
import time
from abc import ABC, abstractmethod
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from models import mk_finding
from sample_data import config_int, config_list, config_ratio

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
            text = raw.decode("utf-16-be" if tag == 0x1E else "ascii").strip()
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
                             "imports_truncated": False, "imports_parsed": False}))
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
            name = section.Name.rstrip(b"\x00").decode("ascii", "replace")
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
        for entry in entries or []:
            dll = (entry.dll or b"").decode("ascii", "replace")
            names = []
            for imported in entry.imports:
                total += 1
                if len(names) >= limit:
                    truncated = True
                    continue
                names.append(imported.name.decode("ascii", "replace")
                             if imported.name else f"#{imported.ordinal}")
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
        }

    def _exports(self, pe, config: dict[str, Any]) -> dict[str, Any]:
        pe.parse_data_directories(
            directories=[_pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        symbols = getattr(directory, "symbols", []) if directory else []
        limit = config_int(config, "pe_max_listed_symbols", 256)
        names = [s.name.decode("ascii", "replace") if s.name else f"#{s.ordinal}"
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
            path = record[offset:].split(b"\x00")[0].decode("ascii", "replace")
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


def default_extractors() -> list[Extractor]:
    """Order matters for the header phase: file type runs first so the stream
    phase can gate on the family it publishes."""
    return [FileTypeExtractor(), HashExtractor(), EntropyExtractor(),
            PEExtractor(), FuzzyHashExtractor()]
