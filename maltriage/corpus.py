"""
Corpus harness: what the findings actually cost.

Points maltriage at directories of files whose nature you already know, and
answers the question every threshold in this project has been deferring --
how often does each finding key fire on something that is fine?


## Labels are directory names, and one label is enough

A corpus root holds directories named for what is in them:

    corpus/
      benign/      files known to be ordinary
      malicious/   files known to be samples

Anything in a directory not named for a label is ignored rather than guessed
at, because a corpus whose ground truth is inferred is not ground truth.

That layout is for a corpus you are assembling. For one you already have --
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
                per_file: bool = False, limit: int | None = None) -> CorpusResult:
    """Run maltriage over a labelled corpus and count what happened."""
    root = Path(root)
    if not root.is_dir():
        raise NotADirectoryError(f"not a directory: {root}")
    return scan_files(labelled_files(root), config, extractors, per_file, limit)


def scan_files(items: Iterable[tuple[str, Path]],
               config: dict[str, Any] | None = None,
               extractors: list[Extractor] | None = None,
               per_file: bool = False,
               limit: int | None = None) -> CorpusResult:
    """Run maltriage over labelled files and count what happened.

    Extractors are built once and reused, which is the contract
    `analyse_directory` relies on and the reason a corpus run is not a
    thousand YARA compilations.
    """
    items = list(items)
    result = CorpusResult()
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
    result.bytes[label] = result.bytes.get(label, 0) + report.size_bytes

    for source in report.errors:
        result.incomplete[source] = result.incomplete.get(source, 0) + 1

    # Once per file per key, not once per finding. A file with forty
    # `yara_match` findings is one file that matched rules, and counting the
    # findings would let a single noisy sample dominate a rate that is
    # supposed to describe a corpus.
    worst_by_key: dict[str, str] = {}
    for finding in report.findings:
        key = finding["key"]
        worst_by_key[key] = _worst(worst_by_key.get(key, "info"), finding["severity"])

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
            "keys": sorted({f["key"] for f in report.findings}),
        })


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
    if result.available and result.available != result.files:
        lines.append("  sampled from " + ", ".join(
            f"{count:,} {label}"
            for label, count in sorted(result.available.items())))
    lines.append(f"  {result.total_bytes / 1e6:.1f} MB in {result.elapsed:.1f}s "
                 f"({speed['bytes_per_second'] / 1e6:.1f} MB/s, "
                 f"{speed['files_per_second']:.0f} files/s)")

    fpr = result.false_positive_rate()
    if fpr is None:
        lines.append(f"  gate ({GATE_SEVERITY}+): no benign files, "
                     "so no false positive rate")
    else:
        lines.append(f"  gate ({GATE_SEVERITY}+): flags {fpr:.1%} of benign files")
    recall = result.recall()
    lines.append(f"  recall: {recall:.1%}" if recall is not None
                 else "  recall: no malicious files, so none to state")

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
