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
- Whole-file and windowed Shannon entropy, scaled to the size of the sample,
  and excluding a PE's Authenticode signature, which is high-entropy by
  construction and is not the file's own content
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
- Findings envelope emit, an interchange format that carries findings and what
  could not be run, and deliberately carries no path, no filename and no
  extraction output
- ATT&CK technique mapping, on one finding key and on any rule that declares
  one. Deliberately sparse: a technique id is a claim about adversary
  behaviour, and most of what a static triage tool sees is merely unusual
- Secret detection over extracted strings: known vendor formats, assignment
  context, and entropy for the formats no rule exists for. Findings carry the
  offset, the length and the rule name, and never the value
- Archive recursion into ZIP, GZIP and TAR, with members analysed as child
  reports and severity propagating out of the container. RAR and 7z are
  recognised and not opened. Every limit is shared by the whole tree: depth,
  entry count, bytes written, wall-clock time and the expansion ratio, which
  is measured from bytes actually written rather than from the sizes the
  archive declares
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
- **v0.4** a package layout, strings/IOCs, API capability detection, the
  findings envelope, ATT&CK mapping, the shared secret engine and the corpus
  harness (shipped); reputation enrichment and offline mode
- **v0.5** archive recursion, with the bomb, traversal and time bounds that
  make it safe, plus known-good filtering
- **v0.6** OLE2 and OOXML, VBA macros and auto-execute triggers
- **v0.7** the measurement release: precision and recall against a labelled
  corpus, run diffing, and what known-good filtering costs in false negatives.
  The harness itself shipped in v0.4.2, because six decisions were waiting on
  it and nothing else was
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

Write findings envelopes, the interchange format described in
`findings-envelope.md`

```bash
maltriage scan ./samples --recursive --envelope out.jsonl
```

This is the one output that is safe to hand to somebody else. It carries the
findings, what could not be run, and a content hash - and no path, no
filename and no extraction data, so it does not leak the directory layout and
username that every other output here does.

Measure what the findings cost, against files you already know the nature of

```bash
maltriage corpus ./corpus --counterfactual
```

A corpus root holds directories named `benign` and `malicious`, and anything
outside one is skipped rather than guessed at. **A corpus of benign files
alone is enough**, and is the case this is built for: precision and recall
need both labels, false positive rates need only one, and the false positive
rate is what a severity decision turns on. What cannot be computed from what
you supplied comes back as `null` rather than as a zero.

`--counterfactual` is the part that answers a question: for every key below
the gate, how many ordinary files promoting it would newly flag, and for every
key at or above it, how many demoting it would stop flagging. Both marginal - 
counting only the files where nothing else already decides the outcome.

For a corpus you already have rather than one you assembled, name the label
instead of building the directory

```bash
maltriage corpus --benign /usr/bin --benign /usr/lib --limit 500
```

`--benign` and `--malicious` are repeatable and take the label as given, so a
system directory can be measured in place. `--limit` scans at most that many
files of each label, drawn at random with a fixed seed - the first files of a
sorted system directory are a coherent group rather than an arbitrary one, and
a sample nobody can redraw is a measurement nobody can check. A sampled result
says what it was sampled from, in the output and in the JSON.

```bash
maltriage corpus ./corpus --json corpus.json --max-false-positive-rate 0.01
```

Exits non-zero if the gate flags more than 1% of the benign files, so a rate
you measured once can be pinned in CI. Without that flag a corpus run always
exits clean; it is a measurement, not a gate.

The result carries counts and rates and no filenames. `--per-file` adds a
record per file keyed by SHA-256, and is off unless asked for: a corpus
directory is, by construction, a description of somebody's sample collection.

Every `maltriage` above works as `python -m maltriage` if you would rather not
install, or if the console script is not on your `PATH`.

`--json` always writes an array, one object per file, whatever the file count.

Exit codes are 0 for clean, 1 when something scores medium or above, and 2
when the scan could not run at all, so the tool drops into a shell pipeline
or a CI gate without conflating a finding with a failure.

A container is scanned by scanning what is inside it. `maltriage scan
installer.zip` unpacks members into a temporary directory the tool deletes
when the scan ends, analyses each one, and attaches the result as a child
report. **The exit code follows the worst thing in the tree**, so an installer
carrying a dropper exits non-zero even though the zip itself is unremarkable.

Nothing an archive says about itself is believed. A declared member size is a
claim by the sample, so members are read through a cap and the cap ends the
read; the expansion ratio is computed from bytes actually written. Entry names
are checked before anything is written, and one that escapes its own container
is reported at `high` rather than quietly skipped. Depth, entry count, bytes
and seconds are one budget shared by the whole tree, because a thousand small
archives are the same attack as one enormous member.

`archive_recursion: false` turns it off.

---

## Testing

```bash
pip install -e '.[test]'
python -m pytest -q
```

The suite is **461 tests**, and how many run depends on which optional
dependencies are present. A test that needs one skips rather than fails when
it is missing - the same rule the extractors follow. Two anchors, both
verified: with everything installed, **461 passed, 0 skipped**; with neither
pefile nor yara-python, **350 passed, 111 skipped**. Anything in between is
normal and the skip reasons say which dependency is absent (`pytest -rs`
lists them).

`pip install -e '.[all]'` is the full run, though `ssdeep` needs libfuzzy
present and will not build on a stock Windows box; `.[pe,yara,fast]` gets
everything except the fuzzy-hash tests.

`python -m pytest` rather than `pytest`, because a `pip install -e` into a
Python that is not on `PATH` puts the console script somewhere `PATH` does not
reach. The module form uses the interpreter you already named.

**On Windows, if every test that touches a file errors with
`PermissionError: [WinError 5]` on `AppData\Local\Temp\pytest-of-<user>`:**

```bash
python -m pytest -q --basetemp=./_tmp
```

That is pytest's own temp directory being unreadable, not a maltriage failure - 
the traceback ends in `_pytest/pathlib.py`, before any code in this repository
runs. The suite writes synthetic executables into that directory, so endpoint
security taking an interest in it is a predictable outcome rather than a
surprising one. Relocating the scratch space is the fix; adding an antivirus
exclusion for it is not, because that is a permanent hole in the machine's
coverage traded for a command-line flag.

**If your antivirus reports detections under `AppData\Local\Temp\pytest-of-*`,
they are this suite's fixtures.** The synthetic PEs are built in-process and
contain no code, but they are deliberately odd: writable executable sections,
packed section names, no imports, high-entropy regions, and one PE wearing a
`.pdf` extension. That is the shape a heuristic engine scores, and a commercial
engine agreeing with maltriage about these files is the system working rather
than failing.

Quarantine them; they are disposable. Do not add an exclusion for the Temp
tree, for the reason just given. `pyproject.toml` sets
`tmp_path_retention_policy = "failed"`, so a passing test's directory is
deleted immediately and only the ones worth opening survive.

**If you develop on Linux and ship to Windows, run the suite once like this
before you tag anything:**

```bash
LANG=C LC_ALL=C python -X utf8=0 -m pytest -q
```

That forces the interpreter to decode text files with an ASCII locale instead
of UTF-8, which is the same class of failure a default Windows install
produces with cp1252. Two of the v0.4.1 README tests shipped broken on Windows
for a release because "verified from a clean clone" was verified on one
operating system, and the file they read draws a diagram with box characters.
Every text read and write in this repository now states `encoding="utf-8"`,
and a test walks the source with `ast` and fails if a new one does not.

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
