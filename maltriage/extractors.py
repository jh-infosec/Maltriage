"""
maltriage extraction engine: the extractor set, and the names it is imported by.

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
make corpus-scale work possible, which since v0.4.2 is a thing that happens
rather than a thing that is planned.

A stream extractor must keep its own memory bounded. Buffering the chunks it
is handed would reintroduce exactly the problem this design removes.

Config is read through the validated accessors in `config`, never with a
bare `.get`, so a bad value falls back to a default instead of silently
producing a wrong answer.


## This file used to be all of it

Until v0.4.5 every extractor lived here, and the file reached 3,091 lines --
a quarter of the project, holding eight extractors for six formats. It was
split one module per format, with no behaviour change: the ranges were moved
rather than retyped, and the same 412 tests pass on both sides of the move.

The split happened when it did because v0.5 adds an archive parser and v0.6
adds two document parsers, and each of them would have made the same work
larger. A file that grows by a format per release is not a file anybody
chooses; it is one nobody got around to dividing.

**Everything is still importable from here, and that is the point.** The
pipeline, the corpus harness, the fixtures and the suite import from
`maltriage.extractors`, and a refactor that forces every caller to learn a new
module layout has spent its own benefit. The names below are re-exported for
the same reason `entropy.py`'s were when the secret engine took them.
"""

from __future__ import annotations

from .base import (
    Extractor,
    HeaderExtractor,
    ParserUnavailable,
    RandomAccessExtractor,
    StreamExtractor,
    CONTROL_CHARACTERS,
    region_entropy,
    safe_text,
)
from .entropy import (
    BYTE_VALUES,
    HAVE_NUMPY,
    byte_counts,
    entropy_from_counts,
    expected_random_entropy,
    shannon,
)
from .entropy_scan import EntropyExtractor, entropy_window_size
from .filetype import FileTypeExtractor
from .hashes import HAVE_SSDEEP, FuzzyHashExtractor, HashExtractor
from .strings import (
    ASCII_RUN,
    IOC_PATTERNS,
    PRINTABLE,
    RUN_KEY_MARKERS,
    WIDE_RUN,
    StringsExtractor,
)
from .pe import (
    HAVE_PEFILE,
    SECURITY_DIRECTORY,
    PEExtractor,
    certificate_common_names,
    certificate_range,
)
from .archives import (
    ARCHIVE_FAMILIES,
    UNSUPPORTED_FAMILIES,
    ArchiveExtractor,
    Budget,
    budget_from,
    safe_member_path,
)
from .elf import ELF_MAGIC, ElfExtractor
from .rules import (
    BUNDLED_RULES,
    HAVE_YARA,
    RULE_SUFFIXES,
    YaraExtractor,
    compile_rules,
    rule_fingerprint,
    rule_files,
)

__all__ = [
    "Extractor", "HeaderExtractor", "StreamExtractor", "RandomAccessExtractor",
    "ParserUnavailable", "CONTROL_CHARACTERS", "region_entropy", "safe_text",
    "BYTE_VALUES", "HAVE_NUMPY", "byte_counts", "entropy_from_counts",
    "expected_random_entropy", "shannon",
    "EntropyExtractor", "entropy_window_size",
    "FileTypeExtractor",
    "HashExtractor", "FuzzyHashExtractor", "HAVE_SSDEEP",
    "StringsExtractor", "PRINTABLE", "ASCII_RUN", "WIDE_RUN", "IOC_PATTERNS",
    "RUN_KEY_MARKERS",
    "PEExtractor", "HAVE_PEFILE", "SECURITY_DIRECTORY", "certificate_range",
    "certificate_common_names",
    "ElfExtractor", "ELF_MAGIC",
    "ArchiveExtractor", "ARCHIVE_FAMILIES", "UNSUPPORTED_FAMILIES",
    "Budget", "budget_from", "safe_member_path",
    "YaraExtractor", "HAVE_YARA", "BUNDLED_RULES", "RULE_SUFFIXES",
    "rule_files", "rule_fingerprint", "compile_rules",
    "default_extractors",
]


def default_extractors() -> list[Extractor]:
    """Order matters for the header phase: file type runs first so the stream
    phase can gate on the family it publishes."""
    return [FileTypeExtractor(), HashExtractor(), EntropyExtractor(),
            StringsExtractor(),
            PEExtractor(), ElfExtractor(), ArchiveExtractor(), YaraExtractor(),
            FuzzyHashExtractor()]
