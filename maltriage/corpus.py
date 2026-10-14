"""
Corpus harness: what the findings actually cost.

Points maltriage at directories of files whose nature you already know, and
answers the question every threshold in this project has been deferring:
how often does each finding key fire on something that is fine?


## Labels are directory names, and one label is enough

A corpus root holds directories named for what is in them:

    corpus/
      benign/      files known to be ordinary
      malicious/   files known to be samples

Anything in a directory not named for a label is ignored rather than guessed
at, because a corpus whose ground truth is inferred is not ground truth.

That layout is for a corpus you are assembling. For one you already have,
a system directory, a package cache, a software library - name the label
instead of building the directory:

    maltriage corpus --benign C:\\Windows\\System32 --limit 500

`named_files` takes the labels as given rather than reading them off a path,
because copying two gigabytes of Windows in order to rename its parent folder
is a cost this tool has no business imposing.

**A corpus with only benign files is useful, and the harness is built for
that case rather than tolerating it.** Precision and recall need both labels.
False positive rates need only one, and the false positive rate is what every
open severity decision in this project turns on: whether `api_capability` may
reach medium, whether `registry_persistence_path` is held too low, whether a
YARA rule may declare its own severity. None of those questions needs a single
malicious file to answer, and a repository that must never contain one should
not have a harness that waits for it.

Where a rate cannot be computed from what was supplied, this module returns
`None` rather than a number. A precision of zero over an empty malicious set
is a lie with a decimal point in it.


## What it reports

- Per finding key: how many files of each label it fired on, and the rate.
- The gate: how often `GATE_SEVERITY` or above was reached per label. This is
  the number a CI user actually experiences.
- What could not be run, from `report.errors`, because a corpus where the PE
  parser failed on a third of the files is not measuring what it claims to.
- Throughput, in files and bytes per second.
- The counterfactual: what raising or lowering each key would do to the gate.


## It reports rates, not filenames

By default the result carries counts and rates and no paths. A corpus report
is an artefact that gets kept and compared against later runs, and a corpus
directory is, by construction, a description of somebody's sample collection.
`per_file` exists for the moment you need to go and look at which file did
that, and it is off unless asked for.
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .extractors import Extractor, default_extractors
from .models import SEVERITY_RANK, Report
from .pipeline import analyse

#: The severity at or above which a file is flagged. Mirrors `cli.GATE_SEVERITY`
#: rather than importing it, because the CLI imports this module.
GATE_SEVERITY = "medium"

#: Directory names that carry a label. A directory named anything else is
#: skipped: inferring ground truth defeats the purpose of having any.
LABELS = ("benign", "malicious")


@dataclass
class KeyOutcome:
    """How one finding key behaved, per label."""

    key: str
    severity: str = "info"
    #: Files of each label on which this key fired at least once.
    fired: dict[str, int] = field(default_factory=dict)
    #: Benign files where this key fired and nothing already flagged the file.
    #: The marginal cost of promoting it: a key that only ever fires on files
    #: some other key already flags would cost nothing to raise.
    would_newly_flag: int = 0
    #: Benign files this key alone flags. The marginal benefit of demoting it:
    #: anything else at the gate on the same file would keep it flagged.
    sole_cause: int = 0

    def rate(self, label: str, totals: dict[str, int]) -> float | None:
        """Share of `label` files this key fired on, or None if there were none."""
        total = totals.get(label, 0)
        if not total:
            return None
        return round(self.fired.get(label, 0) / total, 4)


@dataclass
class CorpusResult:
    """One run over a labelled corpus."""

    files: dict[str, int] = field(default_factory=dict)
    bytes: dict[str, int] = field(default_factory=dict)
    #: Files of each label the gate flagged, at or above GATE_SEVERITY.
    flagged: dict[str, int] = field(default_factory=dict)
    keys: dict[str, KeyOutcome] = field(default_factory=dict)
    #: Extractors that failed, and on how many files. A corpus where a parser
    #: was absent measures the tool without that parser, which is a different
    #: tool.
    incomplete: dict[str, int] = field(default_factory=dict)
    elapsed: float = 0.0
    per_file: list[dict[str, Any]] = field(default_factory=list)
    #: Labelled files found, per label, before any sampling. Equal to `files`
    #: on a full run. It is carried so a sampled result cannot be mistaken for
    #: a complete one six months later, when the only thing left is the JSON.
    available: dict[str, int] = field(default_factory=dict)
    #: Files of each label that turned out to be containers, and how many
    #: members were examined inside them. Reported because a corpus of
    #: documents is a corpus of archives, and a rate computed over files that
    #: are each a hundred members is a different measurement from one over
    #: a hundred loose files.
    containers: dict[str, int] = field(default_factory=dict)
    members: dict[str, int] = field(default_factory=dict)
    #: How many files of each label were of each detected family. A rate over
    #: a directory is an average over whatever formats were in it, and the
    #: average is the wrong number when the question is what a rule does to
    #: documents. The family is what the bytes said, not what the name
    #: claimed, which is the same stance every other finding here takes.
    families: dict[str, dict[str, int]] = field(default_factory=dict)
    #: The extensions the population was restricted to, if any. Selecting by
    #: extension looks like a contradiction in a tool whose whole stance is
    #: that a name proves nothing, and it is not one: this chooses which
    #: files to measure, it never decides what a file is. Every finding below
    #: still comes from the bytes. The distinction matters because a home
    #: directory can be 45% one application's cache, and a rate drawn at
    #: random from it describes that cache rather than the question asked.
    #: Recorded because a rate over a filtered population is a different
    #: claim, and the filter has to survive into the artefact.
    selected_extensions: list[str] = field(default_factory=list)
    #: Every scanned file's SHA-256, per label. Held so a run can be compared
    #: against a manifest written by an earlier one, and deliberately absent
    #: from `to_dict`: a per-file list is what `--per-file` is opt-in for, and
    #: this must not become a back door into it.
    scanned: dict[str, list[str]] = field(default_factory=dict)
    #: Manifest comparison, present only when one was supplied. `missing` is
    #: the count of hashes the manifest expected and this run did not see.
    #: It exists because a corpus of samples is a corpus an antivirus is
    #: actively removing files from, and a denominator that shrinks quietly
    #: is the one failure a rate must not have. The files that go first are
    #: the ones the scanner recognised, which biases recall upward.
    manifest: dict[str, Any] = field(default_factory=dict)

    @property
    def total_files(self) -> int:
        return sum(self.files.values())

    @property
    def total_bytes(self) -> int:
        return sum(self.bytes.values())

    def false_positive_rate(self) -> float | None:
        """Share of benign files the gate flagged.

        The number a CI user feels. Every other figure here explains it.
        """
        benign = self.files.get("benign", 0)
        if not benign:
            return None
        return round(self.flagged.get("benign", 0) / benign, 4)

    def recall(self) -> float | None:
        """Share of malicious files the gate flagged.

        `None` without a malicious set, which is the honest answer and not a
        zero. This is the half a benign-only corpus cannot supply.
        """
        malicious = self.files.get("malicious", 0)
        if not malicious:
            return None
        return round(self.flagged.get("malicious", 0) / malicious, 4)

    def precision(self) -> float | None:
        """Share of flagged files that were malicious. Needs both labels."""
        if not self.files.get("malicious") or not self.files.get("benign"):
            return None
        flagged = self.flagged.get("malicious", 0) + self.flagged.get("benign", 0)
        if not flagged:
            return None
        return round(self.flagged.get("malicious", 0) / flagged, 4)

    def throughput(self) -> dict[str, float]:
        if self.elapsed <= 0:
            return {"files_per_second": 0.0, "bytes_per_second": 0.0}
        return {
            "files_per_second": round(self.total_files / self.elapsed, 2),
            "bytes_per_second": round(self.total_bytes / self.elapsed, 2),
        }

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "files": dict(sorted(self.files.items())),
            "bytes": dict(sorted(self.bytes.items())),
            "flagged": dict(sorted(self.flagged.items())),
            "gate": {
                "severity": GATE_SEVERITY,
                "false_positive_rate": self.false_positive_rate(),
                "recall": self.recall(),
                "precision": self.precision(),
            },
            "keys": {
                key: {
                    "severity": outcome.severity,
                    "fired": dict(sorted(outcome.fired.items())),
                    "rates": {label: outcome.rate(label, self.files)
                              for label in sorted(self.files)},
                }
                for key, outcome in sorted(self.keys.items())
            },
            "incomplete": dict(sorted(self.incomplete.items())),
            # Always present, including as empty dictionaries, so a reader
            # comparing two results can tell "no containers" from "a result
            # written before anything counted them".
            "containers": dict(sorted(self.containers.items())),
            "members": dict(sorted(self.members.items())),
            "families": {label: dict(sorted(counts.items()))
                         for label, counts in sorted(self.families.items())},
            **({"selected_extensions": list(self.selected_extensions)}
               if self.selected_extensions else {}),
            "elapsed_seconds": round(self.elapsed, 3),
            # Present only when a sample was taken, and then unmissable. A rate
            # over 500 of 4,000 files is a different claim from a rate over
            # 4,000, and the difference has to survive into the artefact.
            **({"sampled_from": dict(sorted(self.available.items()))}
               if self.available and self.available != self.files else {}),
            "throughput": self.throughput(),
            "counterfactual": counterfactual(self),
        }
        if self.per_file:
            out["per_file"] = self.per_file
        return out


def files_under(label: str, directory: Path) -> list[tuple[str, Path]]:
    """Every regular file below `directory`, carrying `label`.

    Symbolic links are skipped. On Windows a large system directory is full of
    reparse points and hard links, and following them measures the same file
    twice under two names - which inflates a denominator quietly, which is the
    one thing a false positive rate must not do.
    """
    return [(label, path) for path in sorted(directory.rglob("*"))
            if path.is_file() and not path.is_symlink()]


def labelled_files(root: Path) -> list[tuple[str, Path]]:
    """Every file under a label directory, with its label.

    Directories that are not a label are skipped rather than walked, because
    a corpus root is also where people put notes, scripts and the hashes they
    downloaded the samples with.
    """
    found: list[tuple[str, Path]] = []
    for label in LABELS:
        directory = root / label
        if directory.is_dir():
            found.extend(files_under(label, directory))
    return found


def named_files(sources: dict[str, list[Path]]) -> list[tuple[str, Path]]:
    """Every file under directories the caller labelled itself.

    The corpus layout wants files arranged as `corpus/benign/...`, which is
    fine when you are assembling a corpus and useless when you already have
    one. `C:\\Windows\\System32` is two thousand of the most ordinary Windows
    binaries in existence, and copying two gigabytes to measure them would be
    a cost this tool imposed for the sake of a directory name.
    """
    unknown = sorted(set(sources) - set(LABELS))
    if unknown:
        raise ValueError(f"unknown label(s) {unknown}, expected {list(LABELS)}")
    found: list[tuple[str, Path]] = []
    for label in LABELS:
        for directory in sources.get(label) or []:
            if not directory.is_dir():
                raise NotADirectoryError(f"not a directory: {directory}")
            found.extend(files_under(label, directory))
    return found


def write_manifest(result: CorpusResult, path: Path) -> None:
    """Record what this corpus held, as hashes and nothing else.

    No names and no paths. A manifest listing the filenames of a malicious
    corpus is a description of somebody's sample collection, and this file is
    meant to be committed beside a measurement.
    """
    payload = {
        "version": 1,
        "labels": {label: sorted(digests)
                   for label, digests in sorted(result.scanned.items())},
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def read_manifest(path: Path) -> dict[str, set[str]]:
    """A manifest as sets of hashes, per label."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or "labels" not in payload:
        raise ValueError(f"not a corpus manifest: {path}")
    return {label: set(digests)
            for label, digests in (payload["labels"] or {}).items()}


def compare_manifest(result: CorpusResult,
                     expected: dict[str, set[str]]) -> dict[str, Any]:
    """What this run saw against what the manifest said was there.

    `missing` is the number that were expected and not seen. On a corpus an
    antivirus is quarantining from, that number is the measurement's
    integrity: the samples it takes first are the ones it recognised, so a
    recall figure computed over what survived is biased upward.
    """
    out: dict[str, Any] = {}
    for label in sorted(set(expected) | set(result.scanned)):
        want = expected.get(label, set())
        seen = set(result.scanned.get(label, []))
        out[label] = {
            "expected": len(want),
            "seen": len(seen),
            "missing": len(want - seen),
            "unexpected": len(seen - want),
        }
    return out


def _normalise_extensions(extensions: list[str]) -> list[str]:
    """`docx`, `.docx` and `.DOCX` are one selection, written three ways.

    A selection nobody can spell is a selection nobody uses, and the failure
    mode is silent: an unnormalised list simply matches nothing and reports a
    rate over zero files.
    """
    out = []
    for raw in extensions:
        value = raw.strip().lower()
        if not value:
            continue
        if not value.startswith("."):
            value = "." + value
        if value not in out:
            out.append(value)
    return out


def sample(items: list[tuple[str, Path]], limit: int,
           seed: int = 0) -> list[tuple[str, Path]]:
    """At most `limit` files of each label, drawn at random and reproducibly.

    Random rather than the first `limit`, because the first files of a sorted
    system directory all begin with the same letter, and on Windows that is a
    coherent group rather than an arbitrary one - `api-ms-win-*` alone is
    hundreds of stub DLLs that are nothing like the rest.

    Seeded, because a sample nobody can redraw is a measurement nobody can
    check.
    """
    if limit <= 0:
        raise ValueError(f"limit must be positive, got {limit}")
    chosen: list[tuple[str, Path]] = []
    picker = random.Random(seed)
    for label in LABELS:
        group = [item for item in items if item[0] == label]
        chosen.extend(group if len(group) <= limit
                      else sorted(picker.sample(group, limit)))
    return chosen


def scan_corpus(root: Path | str, config: dict[str, Any] | None = None,
                extractors: list[Extractor] | None = None,
                per_file: bool = False, limit: int | None = None,
                extensions: list[str] | None = None) -> CorpusResult:
    """Run maltriage over a labelled corpus and count what happened."""
    root = Path(root)
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")
    return scan_files(labelled_files(root), config, extractors, per_file, limit,
                      extensions)


def scan_files(items: Iterable[tuple[str, Path]],
               config: dict[str, Any] | None = None,
               extractors: list[Extractor] | None = None,
               per_file: bool = False,
               limit: int | None = None,
               extensions: list[str] | None = None) -> CorpusResult:
    """Run maltriage over labelled files and count what happened.

    Extractors are built once and reused, which is the contract
    `analyse_directory` relies on and the reason a corpus run is not a
    thousand YARA compilations.
    """
    items = list(items)
    result = CorpusResult()
    if extensions:
        result.selected_extensions = _normalise_extensions(extensions)
        items = [(label, path) for label, path in items
                 if path.suffix.lower() in result.selected_extensions]
    for label, _ in items:
        result.available[label] = result.available.get(label, 0) + 1
    if limit is not None:
        items = sample(items, limit)

    extractors = extractors if extractors is not None else default_extractors()
    started = time.perf_counter()

    for label, path in items:
        try:
            report = analyse(path, config, extractors)
        except OSError:
            # Unreadable file. A corpus is somebody's directory and this is
            # expected rather than exceptional, but it must not silently
            # shrink the denominator.
            result.incomplete["unreadable"] = result.incomplete.get("unreadable", 0) + 1
            continue
        _record(result, label, report, per_file)

    result.elapsed = time.perf_counter() - started
    return result


def _record(result: CorpusResult, label: str, report: Report,
            per_file: bool) -> None:
    result.files[label] = result.files.get(label, 0) + 1
    # The container's own size, which is the file on disk the analyst scanned.
    # A member's bytes are inside that number already, and adding them would
    # make the throughput figure describe work rather than input.
    result.bytes[label] = result.bytes.get(label, 0) + report.size_bytes

    members = _members(report)
    if members:
        result.containers[label] = result.containers.get(label, 0) + 1
        result.members[label] = result.members.get(label, 0) + members

    family = _family(report)
    by_family = result.families.setdefault(label, {})
    by_family[family] = by_family.get(family, 0) + 1

    digest = (report.data.get("hashes") or {}).get("sha256")
    if digest:
        result.scanned.setdefault(label, []).append(digest)

    # Once per file per key, not once per finding. A file with forty
    # `yara_match` findings is one file that matched rules, and counting the
    # findings would let a single noisy sample dominate a rate that is
    # supposed to describe a corpus.
    #
    # Over the whole tree, because the unit being measured is the file the
    # analyst handed to the tool. Reading `report.findings` alone measured a
    # gate the tool does not ship: `main` exits on `report.severity`, which
    # propagates from members, so a zip holding a PE named `.txt` exited
    # non-zero in the field and counted as a clean unflagged file here, in the
    # same record that recorded its severity as high. The Linux corpus could
    # not see it - 3.4% of files were containers and not one member reached
    # medium - and a corpus of documents is a corpus of archives, so the
    # measurement would have been wrong exactly where it was about to be used.
    worst_by_key: dict[str, str] = {}
    for node in _tree(report):
        for source in node.errors:
            result.incomplete[source] = result.incomplete.get(source, 0) + 1
        for finding in node.findings:
            key = finding["key"]
            worst_by_key[key] = _worst(worst_by_key.get(key, "info"),
                                       finding["severity"])

    at_gate = [key for key, severity in worst_by_key.items()
               if SEVERITY_RANK[severity] >= SEVERITY_RANK[GATE_SEVERITY]]
    flagged = bool(at_gate)

    if flagged:
        result.flagged[label] = result.flagged.get(label, 0) + 1

    for key, severity in worst_by_key.items():
        outcome = result.keys.setdefault(key, KeyOutcome(key=key))
        outcome.fired[label] = outcome.fired.get(label, 0) + 1
        outcome.severity = _worst(outcome.severity, severity)

        # The two marginal counts, accumulated here rather than derived later,
        # because deriving them would need every file's key set kept in memory
        # and the answer is a running total either way.
        if label != "benign":
            continue
        if not flagged:
            # Raising this key would newly flag this file: nothing else does.
            outcome.would_newly_flag += 1
        elif at_gate == [key]:
            # Demoting this key would unflag this file: nothing else holds it.
            outcome.sole_cause += 1

    if per_file:
        result.per_file.append({
            "label": label,
            "sha256": (report.data.get("hashes") or {}).get("sha256"),
            "size_bytes": report.size_bytes,
            "severity": report.severity,
            "keys": sorted(worst_by_key),
            "members": members,
            # The family, deliberately not the extension. An extension comes
            # from the name, and the one rule this record follows is that it
            # carries nothing from the name.
            "family": family,
        })


def _tree(report: Report):
    """The report and every member below it, depth first."""
    yield report
    for child in report.children:
        yield from _tree(child)


def _members(report: Report) -> int:
    return sum(1 for _ in _tree(report)) - 1


def _family(report: Report) -> str:
    """What the bytes said this file was, or `unknown` if nothing claimed it.

    A string either way rather than `None`, because this is a dictionary key
    and a corpus of files nothing recognises is a result worth reading.

    A container that turned out to be something more specific is reported as
    that. A DOCX, a JAR and an APK share a magic number, so 58 real documents
    came back as `zip 58`, which answered nothing about documents. The
    refinement still comes from the bytes: it is read from the member names,
    not from the extension.
    """
    kind = (report.data.get("archive") or {}).get("container_kind")
    if kind:
        return kind
    return (report.data.get("filetype") or {}).get("family") or "unknown"


def _worst(left: str, right: str) -> str:
    return left if SEVERITY_RANK[left] >= SEVERITY_RANK[right] else right


def counterfactual(result: CorpusResult) -> dict[str, Any]:
    """What each key's severity is costing, and what changing it would cost.

    This is the half of the harness that answers a question rather than
    reporting a number. Six decisions in this project are recorded as deferred
    until the corpus can state a cost - whether a capability may reach
    medium, whether a persistence path is held too low, whether a rule may
    declare its own severity. Each of them is the same question: if this key
    were at the gate, how many ordinary files would it flag that are not
    flagged now?

    Both sides are marginal rather than gross, which is the whole point. A key
    that fires on two hundred benign files but only ever on files something
    else already flags is free to promote, and a gross count would have said
    it was the most expensive key in the set.

    `raising`, for keys below the gate: benign files that would be newly
    flagged, counting only those nothing else already flags.

    `lowering`, for keys at or above it: benign files that would stop being
    flagged, counting only those where this key is the sole cause.
    """
    benign = result.files.get("benign", 0)
    if not benign:
        return {"available": False,
                "reason": "no benign files, so there is no cost to state"}

    raising, lowering = {}, {}
    for key, outcome in sorted(result.keys.items()):
        fired = outcome.fired.get("benign", 0)
        if not fired:
            continue
        if SEVERITY_RANK[outcome.severity] >= SEVERITY_RANK[GATE_SEVERITY]:
            lowering[key] = {
                "severity": outcome.severity,
                "benign_files_fired_on": fired,
                "benign_files_it_alone_flags": outcome.sole_cause,
                "false_positive_rate_after": round(
                    (result.flagged.get("benign", 0) - outcome.sole_cause) / benign, 4),
            }
        else:
            raising[key] = {
                "severity": outcome.severity,
                "benign_files_fired_on": fired,
                "benign_files_it_would_newly_flag": outcome.would_newly_flag,
                "false_positive_rate_after": round(
                    (result.flagged.get("benign", 0) + outcome.would_newly_flag)
                    / benign, 4),
            }

    return {
        "available": True,
        "benign_files": benign,
        "current_false_positive_rate": result.false_positive_rate(),
        # Keys below the gate, worst first: the ones it would cost most to
        # promote.
        "raising": dict(sorted(raising.items(),
                               key=lambda kv: -kv[1]["benign_files_it_would_newly_flag"])),
        # Keys at or above it, worst first: the ones responsible for the
        # current rate.
        "lowering": dict(sorted(lowering.items(),
                                key=lambda kv: -kv[1]["benign_files_it_alone_flags"])),
    }


def render(result: CorpusResult) -> str:
    """The result as text, for somebody reading rather than parsing."""
    lines = []
    totals = ", ".join(f"{count} {label}"
                       for label, count in sorted(result.files.items()))
    speed = result.throughput()
    lines.append(f"corpus: {totals or 'no labelled files'}")
    if result.selected_extensions:
        # Before the sampling line, because this is the narrower statement:
        # a sample is drawn from the selection, not from the directory.
        lines.append("  restricted to " + ", ".join(result.selected_extensions))
    if result.available and result.available != result.files:
        lines.append("  sampled from " + ", ".join(
            f"{count:,} {label}"
            for label, count in sorted(result.available.items())))
    lines.append(f"  {result.total_bytes / 1e6:.1f} MB in {result.elapsed:.1f}s "
                 f"({speed['bytes_per_second'] / 1e6:.1f} MB/s, "
                 f"{speed['files_per_second']:.0f} files/s)")

    for label, counts in sorted(result.manifest.items()):
        # Loud, and above the rates rather than below them. A run that lost
        # files is a run whose denominator is wrong, and that has to be read
        # before the numbers it produced.
        state = (f"{counts['missing']} MISSING" if counts["missing"]
                 else "all present")
        extra = (f", {counts['unexpected']} not in the manifest"
                 if counts["unexpected"] else "")
        lines.append(f"  {label} manifest: {counts['seen']} of "
                     f"{counts['expected']}, {state}{extra}")

    fpr = result.false_positive_rate()
    if fpr is None:
        lines.append(f"  gate ({GATE_SEVERITY}+): no benign files, "
                     "so no false positive rate")
    else:
        lines.append(f"  gate ({GATE_SEVERITY}+): flags {fpr:.1%} of benign files")
    recall = result.recall()
    lines.append(f"  recall: {recall:.1%}" if recall is not None
                 else "  recall: no malicious files, so none to state")

    for label, counts in sorted(result.families.items()):
        # Every family, not the top few. A corpus that turns out to be 95%
        # one format is the single most important thing about a rate taken
        # over it, and a truncated list is where that fact would hide.
        shown = ", ".join(f"{family} {count}" for family, count in
                          sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))
        lines.append(f"  {label} families: {shown}")

    if result.containers:
        # Said out loud, because a rate over files that are each a hundred
        # members is not the same measurement as one over loose files, and
        # the figure above cannot tell you which you are reading.
        lines.append("  containers: " + ", ".join(
            f"{count} {label} file(s) held "
            f"{result.members.get(label, 0):,} member(s)"
            for label, count in sorted(result.containers.items())))

    if result.incomplete:
        lines.append("  incomplete: " + ", ".join(
            f"{source} on {count} file(s)"
            for source, count in sorted(result.incomplete.items())))

    lines.append("")
    lines.append("  findings, by share of each label")
    for key, outcome in sorted(result.keys.items(),
                               key=lambda kv: -kv[1].fired.get("benign", 0)):
        rates = "  ".join(
            f"{label} {outcome.rate(label, result.files):.1%}"
            for label in sorted(result.files)
            if outcome.rate(label, result.files) is not None)
        lines.append(f"    {outcome.severity:>6}  {key:<34} {rates}")
    return "\n".join(lines)


def render_counterfactual(result: CorpusResult) -> str:
    """The counterfactual as text. Separate from `render` because it answers a
    different question: not what the tool did, but what it would do if a
    severity were changed.
    """
    analysis = counterfactual(result)
    if not analysis["available"]:
        return f"counterfactual: {analysis['reason']}"

    benign = analysis["benign_files"]
    current = analysis["current_false_positive_rate"]
    lines = [f"counterfactual over {benign:,} benign file(s), "
             f"currently flagging {current:.1%}"]

    for heading, section, marginal, verb in (
        ("raising to the gate", "raising", "benign_files_it_would_newly_flag",
         "newly flags"),
        ("lowering below the gate", "lowering", "benign_files_it_alone_flags",
         "unflags"),
    ):
        entries = analysis[section]
        lines.append("")
        if not entries:
            lines.append(f"  {heading}: no keys on that side of the gate fired")
            continue
        lines.append(f"  {heading}:")
        for key, row in entries.items():
            lines.append(
                f"    {row['severity']:>6}  {key:<34} "
                f"fires on {row['benign_files_fired_on']:,}, "
                f"{verb} {row[marginal]:,} "
                f"-> {row['false_positive_rate_after']:.1%}")
    return "\n".join(lines)
