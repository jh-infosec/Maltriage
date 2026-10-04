"""
The extractor contract, and the few helpers every format module needs.

Three kinds of extractor, and the difference is where their bytes come from
rather than what they do. `extractors.py` has the long version; this module
holds the classes themselves, so that a format module can import the contract
without importing every other format.

`safe_text` and `region_entropy` live here for the same reason: PE and ELF
both need them, and a helper that two format modules share belongs under both
rather than inside one of them.
"""

from __future__ import annotations
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from .entropy import BYTE_VALUES, byte_counts, entropy_from_counts, ratio as _ratio

log = logging.getLogger(__name__)


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


class ParserUnavailable(RuntimeError):
    """An optional parser an extractor needs is not installed.

    Raised rather than returned, so the pipeline files it under
    `report.errors` alongside every other reason analysis did not happen. The
    alternative is a report on a PE that carries no PE data and no
    explanation, which is indistinguishable from a report on a PE that had
    nothing to say.
    """


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


# C0 (0x00-0x1F), DEL, and C1 (0x80-0x9F). C1 matters because 0x9B is the
# single-byte form of the CSI introducer that `ESC [` spells in two, so a
# string carrying it repaints a terminal without containing an ESC at all. It
# survives the one path in this project that decodes to `str` before
# sanitising - a certificate common name read as UTF-16.
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
    get 3510 and 3511 bytes according to their position in the table - a one
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
