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
- One open and one sequential read of the sample, with peak memory bounded by
  the chunk size rather than by the file
- Three extraction phases: header, stream, and random access for structure no
  forward pass can reach
- Per-extractor error isolation, because a malformed header is an
  anti-analysis technique rather than an accident
- Cryptographic hashing off the shared pass, and optional fuzzy hashing
- Format identification from magic bytes, no external dependencies
- Whole-file and windowed Shannon entropy, scaled to the size of the sample
- PE structure: sections with per-section entropy, imports and imphash,
  exports, TLS callbacks, debug directory and PDB path, overlay, and
  certificate presence with the names embedded in it
- ELF structure: segments and their permissions, sections with per-section
  entropy, dynamic linkage with RPATH and RUNPATH, the interpreter, the build
  id, and trailing data. Standard library only
- YARA matching against a bundled structural rule set and any rules you add,
  with per-rule-file compile isolation and offsets-only match context
- ASCII and UTF-16 string extraction, with URL, email, IP, registry path,
  mutex and absolute path indicators drawn from them
- Suspicious API name detection, grouped into capabilities and reported from
  two views: the names a PE imports outright, and the names that appear as
  literal text, which is the only evidence there is when a sample resolves its
  imports at runtime
- Extension mismatch detection
- Validated config, so a bad threshold is reported rather than absorbed
- Severity scoring and a non-zero exit gate
- Synthetic sample generation, including a structurally valid PE built from
  scratch and containing no code
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

Git does not install hooks on clone, so this is per clone and per machine. The
hook is a shell wrapper around `.githooks/pre-commit.py`: Git for Windows runs
hooks through its bundled `sh`, where a shebang of `python3` often resolves to
nothing, and a guard that cannot start is not a guard.

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
- Standard library only for everything the tool must be able to do

Optional, each degrading rather than failing

- pefile for PE parsing. Its absence is recorded in `report.errors`, because
  it removes findings rather than only speed, and a report must never look
  clean while quietly omitting the analysis nobody ran
- yara-python for rule matching, on the same terms as pefile
- ssdeep for fuzzy hashing, reported as `available: false` when missing
- numpy for faster byte counting. Silently absent, because it changes nothing
  observable

Planned

- yara-python for rule matching
- scikit-learn and LightGBM for classification

---

## Roadmap

`ROADMAP.md` is the roadmap. This section used to restate it and had drifted
into a second, contradictory one: it put the classifier at v0.6 and
reputation enrichment at v0.5, and it stopped at v0.6 entirely. Rather than
keep two lists in step, here is the shape, and the file has the detail.

- **v0.1** extraction engine, hashing, format identification, entropy, CLI
- **v0.2** executable structure: PE and ELF
- **v0.3** YARA integration, a bundled structural rule set, rule authoring notes
- **v0.4** a package layout, strings/IOCs and API capability detection
  (shipped); the shared secret engine, ATT&CK mapping, the findings envelope
  and reputation enrichment
- **v0.5** archive recursion, with the bomb, traversal and time bounds that
  make it safe, plus known-good filtering
- **v0.6** OLE2 and OOXML, VBA macros and auto-execute triggers
- **v0.7** the measurement release: corpus harness, precision and recall
- **v0.8** feature vectors and a gradient boosting classifier
- **v0.9** the adversarial release: attack that classifier, then harden it
- **v1.0** HTML reports, a stable envelope, packaged distribution, CI

From v0.4 the roadmap stops being local. The secret engine, the ATT&CK
registry, the archive path-locking primitive and the HTML renderer are shared
with claude-recon-agent and Shadowfax, and the findings envelope is the wire
format the three of them speak.

---

## Installing

```bash
pip install -e .            # the tool, with no hard dependencies
pip install -e '.[all]'     # plus pefile, yara-python and numpy
pip install -e '.[test]'    # plus pytest and pyelftools, to run the suite
```

Then `maltriage scan <path>`, or `python -m maltriage scan <path>` without
installing.

## Running maltriage

Generate some synthetic test files

```bash
maltriage samples ./demo
```

Scan them

```bash
maltriage scan ./demo
```

Scan a single file and write a JSON report

```bash
maltriage scan suspicious.bin --json report.json
```

Scan a directory into JSON Lines, one object per file

```bash
maltriage scan ./samples --recursive --json-lines out.jsonl
```

Every `maltriage` above works as `python -m maltriage` if you would rather not
install, or if the console script is not on your `PATH`.

`--json` always writes an array, one object per file, whatever the file count.

Exit codes are 0 for clean, 1 when something scores medium or above, and 2
when the scan could not run at all, so the tool drops into a shell pipeline
or a CI gate without conflating a finding with a failure.

---

## Testing

```bash
pip install -e '.[test]'
python -m pytest -q
```

Expect **224 passed, 39 skipped**. The 39 need pefile, yara-python, ssdeep or
numpy, and skip rather than fail when those are absent — the same rule the
extractors follow. `pip install -e '.[all]'` runs all 263, though `ssdeep`
needs libfuzzy present and will not build on a stock Windows box; `.[pe,yara,fast]`
gets everything except the fuzzy-hash tests.

`python -m pytest` rather than `pytest`, because a `pip install -e` into a
Python that is not on `PATH` puts the console script somewhere `PATH` does not
reach. The module form uses the interpreter you already named.

**On Windows, if every test that touches a file errors with
`PermissionError: [WinError 5]` on `AppData\Local\Temp\pytest-of-<user>`:**

```bash
python -m pytest -q --basetemp=./_tmp
```

That is pytest's own temp directory being unreadable, not a maltriage failure —
the traceback ends in `_pytest/pathlib.py`, before any code in this repository
runs. The suite writes synthetic executables into that directory, so endpoint
security taking an interest in it is a predictable outcome rather than a
surprising one. Relocating the scratch space is the fix; adding an antivirus
exclusion for it is not, because that is a permanent hole in the machine's
coverage traded for a command-line flag.

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

---

## License

MIT. See `LICENSE`.
