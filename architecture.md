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
The only coupling is the shared `ctx` dict, which is written by earlier
extractors and read by later ones.

This is what makes per-extractor error isolation possible.

### One failure never loses a run

Malformed headers are an anti-analysis technique, not an accident. An
extractor that raises has its exception captured into `report.errors` and the
run continues with the remaining extractors.

There is a test for this. Any change that lets one extractor abort the run
breaks the invariant.

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

Each subclasses `Extractor` and implements `extract`, optionally `findings`
and `applies_to`.

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

### test_maltriage.py

Test suite covering the extraction engine, the config plumbing, the report
schema and the error-isolation guarantee. Run with `pytest`.

## Analysis Flow

1. File path received by the CLI
2. Pipeline builds an empty report from the file's name and size
3. Config validated once, any problems recorded under `config` in
   `report.errors`
4. File type extracted first, publishing `family` to the shared context
5. Remaining extractors run in order, each reading config and context
6. Each extractor's data is merged into `report.data`
7. Each extractor's findings are appended to `report.findings`
8. An extractor that raises is recorded in `report.errors` and skipped
9. Report severity is the maximum severity across all findings
10. Report rendered to stdout, JSON array or JSON Lines

## Known Constraints

These are accepted limitations of the current design, recorded so they are
not rediscovered as bugs.

### Entropy loads the whole file

`EntropyExtractor` calls `read_bytes()`, so peak memory is the size of the
sample. Hashing streams in chunks and does not have this problem. A very
large sample will be limited by the entropy pass.

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
reputation lookup, threat intelligence or prior-sighting context until v0.5.

### Flat module layout

Modules import each other by bare name (`import models`), so commands must be
run from the project directory. This matches the layout used across the other
projects in this portfolio and is not suitable for installation as a library.

## Required Files

The following files are part of the project structure and must be preserved:

```
cli.py              pipeline.py         extractors.py
models.py           sample_data.py      test_maltriage.py
requirements.txt    architecture.md     README.md
CHANGELOG.md        ROADMAP.md
```
