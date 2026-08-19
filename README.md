# maltriage

> Static Triage Pipeline for Suspicious Files

---

## Why maltriage?

Malware triage begins with a question that has nothing to do with reverse
engineering: of the files in front of me, which one do I look at first?

Answering it well means extracting enough signal to rank a queue, quickly,
without running anything. maltriage does that pass and hands the analyst a
structured report.

The project is being developed alongside my studies in offensive security and
artificial intelligence, and forms the static-analysis foundation for a
machine learning classifier planned in a later version.

---

## Project Goals

maltriage is designed to answer three questions:

- What is this file?
- What is unusual about it?
- Does it deserve a human?

It never claims a file is malicious. It ranks a queue.

---

## Current Features

- Command line interface with human and JSON output
- Cryptographic hashing with streaming reads
- Format identification from magic bytes, no external dependencies
- Whole-file and windowed Shannon entropy, scaled to the size of the sample
- Extension mismatch detection
- Validated config, so a bad threshold is reported rather than absorbed
- Severity scoring and a non-zero exit gate
- Synthetic sample generation
- Automated test suite

---

## Architecture

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
```

Every file enters through the pipeline.

The extraction engine runs each extractor in turn and produces findings, which
are merged into a report and rendered as text or JSON.

Extractors never write output and the report schema never runs analysis.

See `architecture.md` for the full design.

---

## Safety

maltriage is a static analysis tool. It reads bytes from disk and never
executes, launches or modifies a sample.

The entire test suite runs on synthetic fixtures. You can develop and test
this tool without touching a live sample.

`samples/`, `demo/` and common executable extensions are gitignored. Do not
commit malware, to a public repository or a private one.

Extension rules are not enough on their own. This project's own fixture
`invoice.pdf` is a PE, which is precisely the case the tool exists to detect,
and any ignore rule that trusts a filename waves exactly that file through.
So there is a pre-commit hook that checks magic bytes on staged content and
refuses anything that is an executable or a container, whatever it is named.

Git hooks are not installed by cloning. Enable it once per clone:

```bash
git config core.hooksPath .githooks
```

It is dependency-free and project-agnostic, so it can be copied into any
repository that must never receive a sample. `ALLOW_BINARY=1 git commit`
overrides it when you genuinely mean to.

Scan output is gitignored too. A report records the absolute path of every
file scanned, so it carries the directory layout and the username of the
machine that produced it.

If you do work with real samples, use an isolated virtual machine with
snapshots and no host networking, and source them from a reputable feed.

---

## Technology

Current stack

- Python
- Standard library only

Planned

- pefile for PE parsing
- yara-python for rule matching
- scikit-learn and LightGBM for classification

---

## Roadmap

### v0.1

- Extraction Engine
- Hashing
- Format Identification
- Entropy Analysis
- CLI

### v0.2

- PE Parsing
- Imphash
- Section Analysis
- Overlay Detection

### v0.3

- YARA Integration
- Bundled Rule Set

### v0.4

- String Extraction
- IOC Extraction

### v0.5

- Reputation Enrichment
- Local Result Cache

### v0.6

- Feature Vectors
- Machine Learning Classifier

### v1.0

- HTML Reports
- Batch Corpus Analysis
- Packaged Distribution

---

## Running maltriage

Install the dependencies

```bash
pip install -r requirements.txt
```

Generate some synthetic test files

```bash
python cli.py samples ./demo
```

Scan them

```bash
python cli.py scan ./demo
```

Scan a single file and write a JSON report

```bash
python cli.py scan suspicious.bin --json report.json
```

Scan a directory into JSON Lines, one object per file

```bash
python cli.py scan ./samples --recursive --json-lines out.jsonl
```

`--json` always writes an array, one object per file, whatever the file count.

Exit codes are 0 for clean, 1 when something scores medium or above, and 2
when the scan could not run at all, so the tool drops into a shell pipeline
or a CI gate without conflating a finding with a failure.

---

## Testing

Run the test suite

```bash
pytest
```

---

## Philosophy

maltriage is intended to assist analysts, not replace them.

Extraction is deterministic and configuration-driven.

Thresholds are heuristics tuned for recall over precision. A legitimate
compressed installer will trip the entropy check, and that is the correct
trade for a triage tool.

Entropy is scored against what random data of the same length actually
reaches, not against a fixed bits-per-byte number. A short sample cannot
score 8.0 no matter how random it is, so a fixed threshold silently stops
working on small files. Where a sample is too short to say anything at all,
nothing is reported rather than a number that looks like a measurement.

Machine learning is planned for a later version. When it arrives it will
score and rank, and it will never be the only thing standing between a sample
and a verdict.
