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

SCHEMA_VERSION = "1.3"

SEVERITIES = ("info", "low", "medium", "high")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def mk_finding(extractor: str, key: str, detail: str, severity: str = "info") -> dict[str, Any]:
    """Build a single finding. Mirrors the alert constructor in Shadowfax."""
    if severity not in SEVERITY_RANK:
        raise ValueError(f"unknown severity '{severity}', expected one of {SEVERITIES}")
    return {
        "extractor": extractor,
        "key": key,
        "detail": detail,
        "severity": severity,
    }


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
