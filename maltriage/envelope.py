"""
Findings envelope emit.

Converts a `Report` into the interchange format described in
`findings-envelope.md`, which is what maltriage hands to a tool that did not
produce the findings and does not know what a PE section is.

Read that document for the shape and for why each field is there. This module
is the serialiser, and what it adds is three rules the document states and the
code has to enforce:

**It is lossy on purpose.** `report.data` does not cross. Neither does
`report.path`, which is a resolved absolute path and therefore carries the
directory layout and the username of the machine that produced it -- and the
envelope is the artefact most likely to be handed to somebody else, so it is
the one that must not carry that. Subjects are identified by content hash and
by nothing else.

**`report.errors` does cross, as `incomplete`.** This is the field that keeps
the format honest. An envelope carrying only findings turns "I could not look"
into "I looked and found nothing", and that distinction is the one this project
has spent five releases defending: `imports_parsed`, `entropy_skipped`,
`scan_truncated` and every `parse_errors` message exist for it.

**Emitting is not analysis.** This module makes no judgements, applies no
thresholds and adds no findings. If it is ever tempted to decide something, the
decision belongs in an extractor's `findings()` where it can be tested against
a sample.
"""

from __future__ import annotations

from typing import Any

from .models import Report, max_severity

#: The version of `findings-envelope.md` this emitter writes to. Moves
#: independently of `SCHEMA_VERSION`: one tracks what a maltriage report looks
#: like, the other tracks what three tools have agreed to say to each other,
#: and they change for different reasons.
ENVELOPE_VERSION = "0.1"

#: Findings whose substance is a string the subject supplied. Nothing was
#: tested to produce these, so `validated` is false: the emitter transcribed
#: what the file said about itself, and a file can say anything.
#:
#: Everything not listed here is true, because something was compared,
#: counted, walked or computed and could have come back the other way. See
#: `findings-envelope.md` for the three that look like transcription and are
#: not -- `ipv4_present` rejects out-of-range octets, `registry_persistence_
#: path` is a membership test, and `api_capability` counts against a
#: threshold.
TRANSCRIBED = frozenset({
    "signature_present",
    "build_id_present",
    "runpath_set",
    "rpath_set",
    "urls_present",
    "emails_present",
    "mutexes_present",
    "windows_paths_present",
    "unix_paths_present",
    "registry_path_present",
})


def _validated(finding: dict[str, Any], report: Report) -> bool:
    """Whether the emitter did work that could have falsified this claim.

    The obvious test -- did the emitter compute it rather than assume it -- is
    useless, because nearly every finding reads a field and a boolean that is
    true twelve times in thirteen carries no information. This one asks the
    counterfactual instead: was there a version of this file for which the
    same work would have produced no finding?
    """
    key = finding["key"]
    if key == "extension_mismatch":
        # The one finding whose answer depends on how it was reached. A
        # successful parse could have contradicted the extension; two magic
        # bytes could not, because header-only identification is a claim the
        # file makes about itself.
        return "pe" in report.data or "elf" in report.data
    return key not in TRANSCRIBED


def to_envelope(report: Report) -> dict[str, Any]:
    """One report, as one envelope."""
    hashes = report.data.get("hashes") or {}
    filetype = report.data.get("filetype") or {}
    sha256 = hashes.get("sha256")

    subject: dict[str, Any] = {
        # A content address, algorithm included in the string so the id is a
        # single comparable token. Absent only if hashing itself failed, in
        # which case `incomplete` says so and the subject cannot be correlated
        # -- which is the honest answer rather than a fabricated one.
        "id": f"sha256:{sha256}" if sha256 else None,
        "kind": "file",
        "size_bytes": report.size_bytes,
    }
    family = filetype.get("family")
    if family:
        # maltriage's own family string, not a MIME type: it is a claim from
        # magic bytes, and calling it `application/x-dosexec` would dress a
        # guess as an identification.
        subject["media_type"] = family

    findings = [_finding(f, report) for f in report.findings]

    return {
        "envelope_version": ENVELOPE_VERSION,
        "emitter": {"name": "maltriage", "version": _version()},
        "subject": subject,
        "observed_at": report.analyzed_at,
        "severity": max_severity(report.findings),
        "findings": findings,
        "incomplete": [{"source": source, "reason": reason}
                       for source, reason in sorted(report.errors.items())],
    }


def _finding(finding: dict[str, Any], report: Report) -> dict[str, Any]:
    out: dict[str, Any] = {
        "key": finding["key"],
        "source": finding["extractor"],
        "severity": finding["severity"],
        "validated": _validated(finding, report),
        "summary": finding["detail"],
        # Empty means this site has not been taught to supply evidence yet,
        # not that there is none. `findings-envelope.md` says so explicitly,
        # because a consumer treating `[]` as a weaker finding would be
        # reading a fact about this codebase as a fact about the sample.
        "evidence": list(finding.get("evidence") or []),
    }
    discriminator = finding.get("discriminator")
    if discriminator:
        # Present only when the key alone does not identify what was found.
        # This is what makes a bounded key set survivable: the detail that
        # would otherwise want its own key goes here.
        out["discriminator"] = discriminator
    # Carried when the finding earned one, absent when it did not, and absent
    # is the common case: exactly one finding key maps on maltriage's own
    # account. `attack.py` records the rule and the findings it disqualifies,
    # and `mk_finding` has already refused any id the registry does not know.
    if finding.get("mitre"):
        out["mitre"] = list(finding["mitre"])
    return out


def to_envelopes(reports: list[Report]) -> list[dict[str, Any]]:
    return [to_envelope(r) for r in reports]


def _version() -> str:
    from . import __version__
    return __version__
