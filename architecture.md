# maltriage Architecture

## Overview

maltriage is a static triage pipeline for suspicious files. It extracts
hashes, format information and entropy characteristics, and surfaces findings
that warrant an analyst's attention.

This document is the source of truth for the project architecture. Where this
document and the code disagree, one of them is wrong and should be corrected
deliberately rather than left to drift.

The platform consists of five modules:

```
              Suspicious File
                     │
                     ▼
                   CLI
                     │
                     ▼
                 Pipeline
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
  Extraction Engine          Report Schema
        │                         │
        └────────────┬────────────┘
                     ▼
            Findings & Severity
                     │
                     ▼
              JSON / stdout
```

The pipeline is the orchestrator. Extractors never write output and the
report schema never runs analysis.

## Design Principles

These are the invariants the rest of the system depends on. Changing any of
them is a redesign, not a refactor.

### Static analysis only

maltriage reads bytes from disk. It never executes, launches, unpacks to a
running process or otherwise activates a sample.

This is a design decision, not a limitation. It means the tool is safe to run
outside a sandbox and safe for anyone to clone and try.

### Extractors are independent

Each extractor is a self-contained capability with no knowledge of the others.
The only coupling is the shared `ctx` dict, which is written by the header
phase and read by the stream phase.

This is what makes per-extractor error isolation possible.

### One open, one read, bounded memory

The pipeline opens the sample once and reads it once. The first `header_bytes`
serve the header phase and are then fed into the stream phase rather than
re-read, so no byte is read twice and nothing seeks backwards.

Nothing holds the sample whole. Peak memory is governed by `read_chunk_bytes`,
not by sample size, which is what makes the corpus harness in v0.7 possible.

A stream extractor must therefore keep its own memory bounded. Buffering the
chunks it is handed would reintroduce exactly the problem this design removes.

This principle is amended by the random-access phase accepted for v0.2. The
memory half survives unchanged; the single-read half does not. See
"v0.2: the random-access phase" below.

### Three phases, so gating still works

Header extractors run first and publish to `ctx`. Stream extractors are then
selected with `applies_to` using what the header phase learned. Random-access
extractors run last and see everything both earlier phases published.

A single undivided pass would be simpler and would leave the PE parser
arriving in v0.2 unable to know it is looking at a PE before it starts. The
split exists for that reason and for no other.

### One failure never loses a run

Malformed headers are an anti-analysis technique, not an accident. An
extractor that raises has its exception captured into `report.errors` and the
run continues with the remaining extractors. One that raises mid-stream is
dropped for the rest of the pass while the others keep receiving chunks.

`findings` is isolated from extraction separately and recorded under
`<name>.findings`, so a broken heuristic costs its own observations and not
the data that produced them.

There are tests for all of this. Any change that lets one extractor abort the
run breaks the invariant.

### Data and findings are separate

`report.data` is everything the extractors learned. `report.findings` is the
subset an analyst should look at, each carrying a severity.

Adding a detection heuristic means changing `findings()`, never `extract()`.

### Thresholds live in config, not code

Every tunable value is read from `DEFAULT_CONFIG`. The config is
JSON-serialisable so it can later be loaded from a file or an API without
restructuring.

### Config is validated, never trusted

Config is read through the accessors in `sample_data.py`, never with a bare
`config.get`. Each accessor validates, falls back to a stated default and
never raises.

v0.1.0 read config directly, which let `hash_chunk_bytes: 0` through and made
every digest the hash of an empty file with nothing raised anywhere. A triage
tool returning a confident wrong hash is worse than one that crashes.

A rejected value is recorded under `config` in `report.errors`, so a report
never looks clean while quietly ignoring what the caller asked for.

### Entropy is scored against what random data of that length reaches

The plug-in entropy estimator is biased low on short samples: 375 random bytes
cannot fill 256 buckets evenly and measure about 7.42 rather than 8.0.

Thresholds are therefore ratios of `expected_random_entropy(n)`, not absolute
bits per byte. One threshold then holds at every window size. An absolute 7.5
was unreachable below about 512 bytes, which is why v0.1.0 could not see a
packed payload in a dropper-sized file even in principle.

### Findings are advisory

maltriage decides what deserves a human. It does not deliver verdicts,
quarantine files or claim a sample is malicious.

## Components

### cli.py

The command line front end. Parses arguments, dispatches to a command,
renders human-readable output and writes JSON.

Owns the exit-code contract: anything scoring at or above `GATE_SEVERITY`
exits non-zero so the tool can be used as a shell or CI gate.

### pipeline.py

Orchestration. Loads the config and extractor list, runs each extractor in
order against a file, merges results into a report and isolates failures.

`analyse` handles one file. `analyse_directory` handles many.

### extractors.py

The extraction engine. All extractors live here.

A `HeaderExtractor` implements `read_header` and is handed the bytes the
pipeline already read. A `StreamExtractor` implements `begin`, `feed` and
`finish` and is fed every chunk in order. A `RandomAccessExtractor`
implements `parse` and opens the sample itself, for structure that no forward
pass can reach. All three may implement `findings` and `applies_to`.

An object that is none of the three has no contract the pipeline can honour,
and is reported as a `TypeError` rather than called and allowed to fail as
though the extractor itself were broken.

`begin` must reset everything `feed` accumulates. Reusing one instance across
a directory scan is the normal case, not the exception.

`byte_counts` uses numpy when installed and the standard library otherwise.
Both paths are asserted to agree, because entropy silently changing with the
environment would be worse than being slow.

Current extractors: `filetype`, `hashes`, `entropy`.

Finding keys: `unrecognised_format`, `extension_mismatch`,
`high_file_entropy`, `entropy_hotspot`.

`expected_random_entropy` is the reference the entropy ratios are measured
against. It is the Miller bias correction, floored by log2(n), and it tracks
measured randomness within 3% from 128 bytes upward. There is a test for
that, because if the reference drifts the thresholds stop meaning anything.

Severity levels are `high`, `medium`, `low` and `info`.

### models.py

The report schema and the finding constructor. No other module defines the
shape of output.

`SCHEMA_VERSION` is bumped when the report shape changes so consumers can
fail loudly rather than mis-parse.

### sample_data.py

Bundled synthetic fixtures, the default config, and the validated accessors
every other module uses to read it.

Every fixture is generated in-process. No malicious samples are required to
develop or test this tool.

`build_pe` constructs a structurally valid PE32 from the format's own
structures, so a PE parser can be tested without a real executable. It is the
single source of every PE fixture: variants are arguments to it rather than
separate builders, so a fixture that drifts from the format drifts for every
test at once and is caught immediately. What it produces contains no code.

### test_maltriage.py

Test suite covering the extraction engine, the config plumbing, the report
schema and the error-isolation guarantee. Run with `pytest`.

## Analysis Flow

1. File path received by the CLI
2. Pipeline builds an empty report from the file's name and size
3. Config validated once, any problems recorded under `config` in
   `report.errors`
4. File opened once and the first `header_bytes` read
5. Header extractors run in order, file type publishing `family` to `ctx`
6. Stream extractors selected with `applies_to`, now able to see `family`
7. The header bytes, then the rest of the file, fed to every stream extractor
   in chunks of `read_chunk_bytes`
8. The file is closed, the pipeline's single sequential read complete
9. Random-access extractors selected with `applies_to`, now able to see both
   `family` and `sha256`, and each opens the sample for itself unless the
   sample is above `max_parse_bytes`, in which case the refusal is recorded
10. Each extractor's data is merged into `report.data`
11. Each extractor's findings are appended to `report.findings`
12. An extractor that raises is recorded in `report.errors` and skipped
13. Report severity is the maximum severity across all findings
14. Report rendered to stdout, JSON array or JSON Lines

## Known Constraints

These are accepted limitations of the current design, recorded so they are
not rediscovered as bugs.

### ssdeep reads the file a second time

Every other extractor works from the shared pass. ssdeep's API takes a path
rather than bytes, so when the optional library is installed it opens and
reads the sample again. This is one reason it stays optional.

v0.2 makes this a category rather than an exception. Under the random-access
phase accepted below, ssdeep is simply the first extractor of a kind that is
allowed to open the sample for itself, and it should move there when that
phase is built.

### Format identification is header-only

Detection matches magic bytes at a fixed offset. Polyglot files, files with
prepended data and formats identified by structure rather than a header will
be reported as `unknown`.

### Entropy thresholds are heuristics

0.90 whole-file and 0.94 per window, as ratios of random, are tuned for recall
over precision. A legitimate compressed installer will trip
`high_file_entropy`, and a PNG will trip `entropy_hotspot` because it is
deflate-compressed data inside a low-entropy container. This is intended:
triage decides what deserves a human, not what is malicious.

### Entropy is not reported below roughly 128 bytes

A sample that short has too few observations to say anything about 256
possible byte values. `window_count` is 0 and no hotspot finding is produced.
Reporting nothing is correct; a score would be noise.

### No enrichment or reputation data

Findings are derived entirely from the file's own bytes. There is no
reputation lookup, threat intelligence or prior-sighting context until v0.4.

### Flat module layout

Modules import each other by bare name (`import models`), so commands must be
run from the project directory. This matches the layout used across the other
projects in this portfolio and is not suitable for installation as a library.

## Accepted Designs

Decided, not yet built. Recorded here so the implementation has something to
be checked against, and so the reasoning survives the gap between deciding
and building. When one of these ships, its section moves up into the body of
this document and stops being provisional.

### v0.2: the random-access phase

Status: the third kind, the phase that runs it, the `max_parse_bytes` ceiling
and the synthetic PE builder are built and tested. No PE or ELF extractor
exists yet, so nothing in `default_extractors()` uses the phase. Everything
below from "What v0.2 extracts" onward is still design rather than code.

v0.2 adds executable structure. It is the first release whose extractors gate
on the header phase, which is what that phase was built for, and the first
that the two-phase design cannot accommodate as it stands.

#### Why a third phase is needed

The two existing kinds offer an extractor a fixed prefix or a forward-only
stream that it may not buffer. PE analysis needs neither.

An import table lives at a relative virtual address that resolves, through
the section table, to a file offset that can be anywhere in the file. The
same is true of exports, TLS callbacks, debug directories and the certificate
table. Reaching them means seeking to a position that is not known until the
section table has been read.

`header_bytes` cannot cover this. Growing it until it does is just holding
the sample whole with extra steps, which is the problem v0.1.2 removed.
Buffering the stream to reach a backward offset is the same thing again and
is already forbidden. Neither option is a near miss; both reintroduce the
defect deliberately.

So v0.2 adds a third kind, and the naming logic of the existing two carries
over. `HeaderExtractor` and `StreamExtractor` are named for where their bytes
come from. The third is `RandomAccessExtractor`, because its bytes come from
anywhere in the file, addressed rather than streamed.

#### The contract

```
class RandomAccessExtractor(Extractor):
    def parse(self, path, ctx, config) -> dict[str, Any]
```

It runs in a third phase, after the stream phase has finished, so `ctx`
already carries `family` from the header phase and `sha256` and `size` from
the stream phase. It is gated with `applies_to` like everything else; the PE
extractor's gate is `ctx.get("family") == "pe"`, which is the header phase
finally paying for itself.

It may open the sample for itself, read-only. It must not write to it, must
not execute it, and must not read it whole. Error isolation is unchanged: a
`parse` that raises is recorded in `report.errors[name]` and the run
continues with everything else intact.

Because it opens the file itself, this phase runs after the pipeline's own
handle has closed. The pipeline's read lifetime is therefore unchanged.

#### Why it opens the file rather than being handed the pipeline's handle

The alternative was to keep the pipeline's handle open, seek it back to zero
and let the extractor work from it. That preserves the literal one-open
claim, and it was rejected.

`pefile.PE(name=...)` maps the file with `mmap` and `MAP_PRIVATE`. It never
reads the sample into the process. Resident memory is bounded by the pages
the parser actually touches, which for a triage parse is the headers, the
section table and the directories it resolves — kilobytes on a sample of any
size. Passing bytes instead, with `pefile.PE(data=...)`, requires deciding in
advance how many bytes to hand it, and every choice is wrong: too few and
imports past the cutoff silently vanish, too many and peak memory tracks
sample size again.

The mapped path is better on both correctness and memory. Its only cost is
the second open, and the invariant that actually matters is the memory one.
The single-read claim was always a proxy for it.

So the principle is restated rather than quietly broken. The pipeline still
performs exactly one full sequential read of the sample. A random-access
extractor may additionally map the file and touch bounded regions of it.
What remains absolute is that nothing holds the sample whole.

#### The trap in the existing tests

Neither memory test would notice this change, and both look like they would.

`test_the_file_is_opened_once_and_read_once` patches `Path.open`. pefile
calls the builtin `open`, so the second open is invisible to it.
`test_peak_memory_does_not_track_sample_size` uses `tracemalloc`, which
accounts for Python allocations and does not see mapped pages.

Two tests that appear to guard this boundary would both stay green while it
moved. v0.2 must therefore pin the new contract deliberately: that the
pipeline's own sequential read is still one read, that a random-access
extractor's resident cost does not scale with sample size, and that the
second open is the mapped one and not an accident.

#### Dependencies

`pefile` is the first library maltriage would depend on for a finding rather
than for speed, and it does not become a hard requirement.

The tool's safety pitch is that anyone can clone it and run it, and the
existing pattern is already established twice, by numpy and by ssdeep: try
the import, degrade if it is absent. The difference is what degradation is
allowed to look like. numpy's absence changes nothing observable, so it is
silent. pefile's absence removes findings, so it must not be.

A PE sample analysed without pefile installed records the reason under
`report.errors`, exactly as a rejected config value does. The rule is the one
already stated for config: a report must never look clean while quietly
omitting what it could not do. An absent parser is that same failure wearing
a different hat.

ELF goes the other way and stays in the standard library. The ELF header,
program headers and section headers are fixed-layout structures that `struct`
reads in well under two hundred lines, and there is no equivalent of pefile's
accumulated knowledge of malformed real-world files to buy. The asymmetry is
deliberate: pay a dependency where the format is genuinely hostile, not where
it is merely binary.

#### Per-section entropy belongs to the PE extractor

Section boundaries do not exist until the PE is parsed, which happens after
the stream phase has ended and its accumulator is gone. Per-section entropy
is therefore computed by the PE extractor from mapped section data, not by
the entropy extractor.

The two share `byte_counts` and `entropy_from_counts` and nothing else.
Sharing a pure function is not coupling. The PE extractor does not reach into
`EntropyExtractor` state and does not consult `report.data["entropy"]`, and
the independence principle is intact.

#### What v0.2 extracts, and what it does not

Data: machine, subsystem, PE type, DLL and driver flags, compile timestamp,
entry point and its section, the section table with per-section entropy and
characteristics, imports with imphash, exports, TLS callbacks, debug
directory and PDB path, overlay offset, size and entropy, and whether a
certificate table is present.

Signature *presence* is free from the directory. Cryptographic *validation*
is not: it needs a certificate chain and a trust decision. v0.2 reports the
presence and the embedded signer name and stops there, and the roadmap entry
should say "presence and signer" rather than "validity" until something
actually verifies it.

Suspicious import names stay in v0.4 where the roadmap puts them. v0.2 emits
the import list as data. Turning that list into an observation is a
heuristic, and heuristics go in `findings()`, not in `parse()`. This is the
data-and-findings split doing its job across a release boundary.

#### Severity discipline

Nothing in v0.2 is `high`.

`extension_mismatch` is currently the only high finding, and it earns that
because PE content under a `.pdf` extension is near-unambiguous deception.
Packing is not deception. It is common in commercial software and it is the
normal state of most installers.

Proposed keys: `section_entropy_high`, `writable_executable_section`,
`virtual_size_mismatch`, `known_packer_section`, `no_imports` and
`entry_point_in_writable_section` at medium; `nonstandard_section_name`,
`few_imports`, `implausible_timestamp`, `large_overlay` and
`tls_callbacks_present` at low; `overlay_present` and `signature_present` at
info.

The tiering is load-bearing rather than cosmetic. `GATE_SEVERITY` is medium,
so every medium added here is a new reason for the tool to exit non-zero in
somebody's CI. A finding belongs at medium only if a human should look at the
file because of it alone.

#### Schema

`report.data["pe"]` and `report.data["elf"]` are additive, and
`SCHEMA_VERSION` goes to 1.3 anyway. The rule is that the version moves when
the shape changes, and additive is a change. A consumer that pins 1.2 should
be told, not left to discover new keys by accident.

#### The fixture problem, which gates everything else

Every fixture in this project is generated in-process, and no malicious
sample is required to develop or test the tool. That promise is not
negotiable, and v0.2 is the first release where keeping it costs real work.

Testing a PE parser needs a valid PE. `sample_data.py` must therefore
construct one by hand: DOS header and stub, PE signature, COFF header,
optional header, a section table, and section data positioned to match it.
That is roughly sixty lines of `struct` and it must be correct enough that
pefile agrees with it, or every test built on it is testing the fixture
rather than the parser.

It should be built first, and verified by checking that pefile's own
`get_imphash()` and section parsing agree with what the fixture was built to
contain. Once it exists the rest of v0.2 has something to stand on, and the
variants come cheaply from the same builder: a packed-looking section, a
writable executable section, an appended overlay, a stripped import table, a
truncated header for the isolation test.

This is the first task of v0.2, not a chore to be done alongside it.

#### Hostile input is not fully solved here

Malformed headers are an anti-analysis technique, and the isolation guarantee
covers a parser that raises. It does not cover a parser that hangs or that
allocates without bound on a crafted file. pefile carries `max_symbol_exports`
and `max_repeated_symbol` for precisely this reason and both should be set
rather than left at their defaults.

A `max_parse_bytes` ceiling, above which a random-access extractor declines
and says so, belongs in the config for the same reason. Genuine timeout
handling needs a mechanism the pipeline does not have and is not in scope for
v0.2; it is recorded here as a known gap rather than left to be rediscovered.

## Required Files

The following files are part of the project structure and must be preserved:

```
cli.py              pipeline.py         extractors.py
models.py           sample_data.py      test_maltriage.py
requirements.txt    architecture.md     README.md
CHANGELOG.md        ROADMAP.md          .gitignore
.githooks/pre-commit
```

`.gitignore` and `.githooks/pre-commit` are part of the safety design rather
than repository housekeeping. The ignore rules cannot catch a sample that
lies about its extension, which is the only kind that matters here, so the
hook checks magic bytes on staged content and is the actual guarantee. It
needs `git config core.hooksPath .githooks` once per clone, because git does
not install hooks on clone.
