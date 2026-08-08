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

Every tunable value is read with `config.get(key, default)` from
`DEFAULT_CONFIG`. The config is JSON-serialisable so it can later be loaded
from a file or an API without restructuring.

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

Severity levels are `high`, `medium`, `low` and `info`.

### models.py

The report schema and the finding constructor. No other module defines the
shape of output.

`SCHEMA_VERSION` is bumped when the report shape changes so consumers can
fail loudly rather than mis-parse.

### sample_data.py

Bundled synthetic fixtures and the default config, used during development
and by the test suite.

Every fixture is generated in-process. No malicious samples are required to
develop or test this tool.

### test_maltriage.py

Test suite covering the extraction engine, the config plumbing, the report
schema and the error-isolation guarantee. Run with `pytest`.

## Analysis Flow

1. File path received by the CLI
2. Pipeline builds an empty report from the file's name and size
3. File type extracted first, publishing `family` to the shared context
4. Remaining extractors run in order, each reading config and context
5. Each extractor's data is merged into `report.data`
6. Each extractor's findings are appended to `report.findings`
7. An extractor that raises is recorded in `report.errors` and skipped
8. Report severity is the maximum severity across all findings
9. Report rendered to stdout, JSON or JSON Lines

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

7.2 whole-file and 7.5 per window are tuned for recall over precision. A
legitimate compressed installer will trip `high_file_entropy`. This is
intended: triage decides what deserves a human, not what is malicious.

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
