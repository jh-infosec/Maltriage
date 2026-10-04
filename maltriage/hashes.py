"""
Cryptographic hashing off the shared pass, and optional fuzzy hashing.

Two extractors of two different kinds, kept together because they answer the
same question - what is this file, as an identifier somebody else can match --
and because the second is the first one's footnote.
"""

from __future__ import annotations
import hashlib
from pathlib import Path
from typing import Any

from .base import RandomAccessExtractor, StreamExtractor


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
