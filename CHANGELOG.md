# Changelog

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
