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

SCHEMA_VERSION = "1.6"

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
    what was found -- an offset, a length, a count or a name from this
    project's own vocabulary, never the matched bytes, the extracted string or
    the credential. There is no configuration switch to relax that, for the
    reason v0.3 gave about YARA match context: the person most likely to
    enable one is the person debugging a rule that matches secrets.

    `discriminator` says which instance of `key` this is -- the rule name, the
    capability category, the section. It is what lets the key set stay bounded
    while the findings underneath it are not.

    `mitre` is a list of ATT&CK technique ids, and every one must be in
    `attack.TECHNIQUES` or this raises. Validating here rather than at the
    emitter is the point: a technique id is the field a consumer is most
    likely to aggregate without reading the finding underneath it, so an id
    that does not exist must not be able to reach a report by way of a typo.
    Whether a finding *deserves* a technique is a separate question and a much
    harder one -- `attack.py` records the rule and the findings it disqualifies.
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

    @property
    def severity(self) -> str:
        return max_severity(self.findings)

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["severity"] = self.severity
        return out

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
