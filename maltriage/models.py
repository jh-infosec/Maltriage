"""
Report schema for maltriage.

Defines the shape of a triage report and the findings it carries.

This module is the contract. Extractors produce data that lands here, and the
CLI, any future HTML renderer and the planned classifier all consume this
shape. `SCHEMA_VERSION` is bumped deliberately when the shape changes so
consumers can fail loudly rather than mis-parse.
"""

from __future__ import annotations
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import attack

SCHEMA_VERSION = "1.7"

SEVERITIES = ("info", "low", "medium", "high")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def mk_finding(extractor: str, key: str, detail: str, severity: str = "info",
               evidence: list[dict[str, Any]] | None = None,
               discriminator: str | None = None,
               mitre: list[str] | None = None) -> dict[str, Any]:
    """Build a single finding. Mirrors the alert constructor in Shadowfax.

    `evidence` and `discriminator` are optional and are omitted from the
    result when not given, so a finding that supplies neither is byte for byte
    what v0.4 produced. They are named for the findings envelope, and they are
    parameters here rather than a lookup table in the emitter because an
    observation belongs to whoever observed it: a table mapping keys to
    evidence would be a second description of every finding, kept in a
    different file, drifting.

    `evidence` is a list of `{"name": ..., "value": ...}`. The rule for what
    belongs, from `findings-envelope.md`: an observation is something the
    subject would have to change for the value to change. And it never carries
    what was found - an offset, a length, a count or a name from this
    project's own vocabulary, never the matched bytes, the extracted string or
    the credential. There is no configuration switch to relax that, for the
    reason v0.3 gave about YARA match context: the person most likely to
    enable one is the person debugging a rule that matches secrets.

    `discriminator` says which instance of `key` this is - the rule name, the
    capability category, the section. It is what lets the key set stay bounded
    while the findings underneath it are not.

    `mitre` is a list of ATT&CK technique ids, and every one must be in
    `attack.TECHNIQUES` or this raises. Validating here rather than at the
    emitter is the point: a technique id is the field a consumer is most
    likely to aggregate without reading the finding underneath it, so an id
    that does not exist must not be able to reach a report by way of a typo.
    Whether a finding *deserves* a technique is a separate question and a much
    harder one - `attack.py` records the rule and the findings it disqualifies.
    """
    if severity not in SEVERITY_RANK:
        raise ValueError(f"unknown severity '{severity}', expected one of {SEVERITIES}")
    finding = {
        "extractor": extractor,
        "key": key,
        "detail": detail,
        "severity": severity,
    }
    if evidence:
        finding["evidence"] = list(evidence)
    if discriminator:
        finding["discriminator"] = discriminator
    if mitre:
        unknown = [t for t in mitre if not attack.is_known(t)]
        if unknown:
            raise ValueError(
                f"unknown ATT&CK technique(s) {unknown}, not in attack.TECHNIQUES")
        finding["mitre"] = list(dict.fromkeys(mitre))
    return finding


def at_gate(report: "Report", gate: str) -> bool:
    """Whether this file should fail a build.

    One computation, called by the CLI's exit code and by the corpus
    harness, because the last time those two answered the question
    separately they disagreed: `main` counted members and the harness did
    not, so a zip holding a disguised PE exited non-zero in the field and
    was recorded as a clean unflagged file. The gate severity is passed in
    rather than imported, so this stays the lowest layer.

    A file the caller vouched for is not at the gate, and its severity is
    unchanged. The report still says what it found; what the known-good set
    buys is a build that does not fail, not a file that looks clean.
    """
    if (report.data.get("known_good") or {}).get("matched"):
        return False
    return SEVERITY_RANK[report.severity] >= SEVERITY_RANK[gate]


def max_severity(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "info"
    return max((f["severity"] for f in findings), key=SEVERITY_RANK.__getitem__)


@dataclass
class Report:
    """One analysed file.

    `data` is everything the extractors learned. `findings` is the subset an
    analyst should look at. Keeping them separate means adding a heuristic
    never changes what gets extracted.
    """

    path: str
    filename: str
    size_bytes: int
    schema_version: str = SCHEMA_VERSION
    analyzed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    #: Reports on what was inside this one. Populated by the pipeline for an
    #: archive, and empty for everything else.
    children: list["Report"] = field(default_factory=list)

    @property
    def severity(self) -> str:
        """The worst of this file's own findings and everything inside it.

        Children count. A zip is a wrapper, and a gate that scored the wrapper
        rather than its contents would exit clean on an installer carrying a
        dropper - which is the case archive recursion exists for. The
        propagation is here rather than in the CLI because every consumer of a
        report needs the same answer: the corpus harness, the envelope and the
        exit code all ask this property what the file is worth.
        """
        worst = max_severity(self.findings)
        for child in self.children:
            worst = max((worst, child.severity), key=SEVERITY_RANK.__getitem__)
        return worst

    def thin(self) -> dict[str, str]:
        """Analysis that ran and came back short, labelled by where.

        `errors` is analysis that did not run at all; this is every
        extractor's `parse_errors` and `warnings`, which mean the same thing
        to someone reading an absence. It lived in the CLI's renderer until
        an audit found the envelope asking a different question: the human
        report said a ZIP refused unopened was incomplete, and its envelope
        said "examined, nothing found". One computation now, so the two
        cannot disagree again.
        """
        out: dict[str, str] = {}
        for name, data in self.data.items():
            if not isinstance(data, dict):
                continue
            for note in data.get("parse_errors") or []:
                # Two rule files with the same basename, or two directories
                # that both fail, produce the same label. A plain assignment
                # rendered them as one line, which understates how thin the
                # report is: the exact failure this block exists to prevent.
                label = f"{name}.{note.split(':')[0]}"
                suffix, index = "", 2
                while label + suffix in out:
                    suffix, index = f" ({index})", index + 1
                out[label + suffix] = note.partition(": ")[2]
            for index, warning in enumerate(data.get("warnings") or [], start=1):
                # Numbered, because a malformed PE routinely produces five or
                # more distinct warnings and a fixed key would print one.
                out[f"{name}.warning {index}"] = warning
        return out

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["severity"] = self.severity
        # `asdict` recurses into the children for us, but it copies fields and
        # `severity` is a property, so each child's own worst score would be
        # missing from its dictionary while the parent's was present.
        out["children"] = [child.to_dict() for child in self.children]
        return out

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
