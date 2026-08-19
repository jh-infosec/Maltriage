# Changelog

## Unreleased -- v0.2 groundwork

No new findings and no change to any severity. This is the foundation the PE
and ELF work sits on: a third extractor kind, for structure that cannot be
reached in one forward pass, and a synthetic executable to test a parser
against.

### Added

- `RandomAccessExtractor`, a third extractor kind. It implements `parse`,
  runs in a third phase after the stream phase closes, and may open the
  sample for itself. It exists because a PE import table lives at an RVA that
  resolves through the section table to an offset no forward pass can reach
- `build_pe` in `sample_data.py`, which constructs a structurally valid PE32
  byte by byte: DOS header, PE signature, COFF and optional headers, section
  table, section bodies, an import directory whose thunks are real RVAs, and
  an optional overlay. Variants come from its arguments, so a fixture that
  drifts from the format drifts for every test at once
- `max_parse_bytes`, a ceiling on the random-access phase. A parser decides
  for itself how much structure to walk, so its cost is the one thing not
  bounded by the configured read sizes. A sample above the ceiling is
  declined and the refusal recorded, because a report that silently skipped
  an analysis looks identical to one that found nothing

### Changed

- "One open, one read" is restated rather than quietly broken. The pipeline
  still performs exactly one sequential read; a random-access extractor may
  additionally map the file and touch bounded regions of it. Bounded memory
  was always the invariant that mattered, and reading once was its proxy
- The phase-1 dispatch no longer calls `extract()` on anything that is not a
  header or stream extractor. No class has ever defined that method, so the
  branch produced an `AttributeError` that read as though the extractor had
  failed at its job rather than as though it had no contract. An object of no
  known kind now raises a `TypeError` naming the three that exist

### Notes

`pefile` maps the sample with `mmap` and never reads it into the process,
which is why the random-access phase opens the file rather than being handed
a capped buffer. Any cap chosen in advance is wrong in one of two directions:
too small and imports past the cutoff vanish silently, too large and peak
memory is back in proportion to sample size.

Neither existing memory test would have caught the second open, and both
looked like they guarded it. `test_the_file_is_opened_once_and_read_once`
patches `Path.open` while pefile calls the builtin, and `tracemalloc` does
not account for mapped pages. The new contract is pinned by tests written for
it rather than inherited from tests that would have stayed green either way.

ssdeep is still the exception it always was. Under the new kind it is simply
the first member of a documented category, and it should move into the
random-access phase when the PE extractor lands.

## Version 0.1.2

Internal release. No new findings, no change to any severity. The extraction
engine now reads a sample once instead of twice and no longer holds it in
memory, which is what makes the corpus work planned for v0.6 possible.

### Changed

- The file is opened once and read once. v0.1.1 opened every sample three
  times and read it in full twice, once streamed for hashing and once whole
  for entropy
- Peak memory is governed by the read chunk size rather than the sample size.
  On a 200 MB sample, peak RSS falls from 220 MB to 23 MB
- Entropy is accumulated from a running 256-entry histogram instead of a
  whole-file buffer. The histogram of a file is the sum of the histograms of
  its parts, so the whole-file figure needs nothing held in memory
- Extractors are now either header or stream extractors. Header extractors
  implement `read_header` and are handed the bytes the pipeline already read.
  Stream extractors implement `begin`, `feed` and `finish` and are fed every
  chunk in order
- The header bytes are fed into the stream phase rather than re-read, so no
  byte is read twice and nothing seeks backwards
- `findings` failures are isolated from extraction failures and recorded
  under `<name>.findings`. A broken heuristic no longer costs the data that
  produced it
- `hash_chunk_bytes` is replaced by `read_chunk_bytes`, which now governs the
  whole pass rather than one extractor. `header_bytes` is new
- `SCHEMA_VERSION` is 1.2

### Added

- `byte_counts`, which uses numpy when it is installed and falls back to the
  standard library otherwise. Both paths are asserted to agree, because
  entropy silently changing with the environment would be worse than being
  slow
- `entropy_from_counts`, entropy from a histogram rather than from bytes
- Tests pinning the guarantees the refactor rests on: results independent of
  chunk size and header size, streamed entropy equal to the whole-buffer
  calculation, one open and no `read_bytes`, peak memory flat across a 100x
  size increase, mid-stream failure dropping only its own extractor, failure
  in `begin` never reaching `feed`, stream extractors gating on the header
  phase, and instances remaining reusable across files

### Notes

Runtime on a 200 MB sample falls from 14.4s to 7.5s on the standard library
alone, and to 2.2s with numpy installed. numpy is optional and listed
commented out in `requirements.txt`. Hashes and entropy are identical across
all three configurations.

`begin` must reset everything `feed` accumulates. Reusing one extractor
instance across a directory scan is the normal case, not the exception, and
there is a test for it.

A stream extractor must keep its own memory bounded. Buffering the chunks it
is handed would reintroduce exactly the problem this release removes.

ssdeep remains the one component that reads the file a second time, because
its API takes a path rather than bytes. This is stated rather than hidden,
and it is one reason ssdeep stays optional.
