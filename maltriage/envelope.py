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
directory layout and the username of the machine that produced it - and the
envelope is the artefact most likely to be handed to somebody else, so it is
the one that must not carry that. Subjects are identified by content hash and
by nothing else.

**`report.errors` does cross, as `incomplete`, and so does every extractor's
`parse_errors` and `warnings`, through `Report.thin()`.** The second half was
missing until 0.5.15, which made the sentence below untrue for every parser
that stopped short rather than raising. This is the field that keeps
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

import re
import tempfile
from pathlib import Path
from typing import Any

from .models import Report

#: The version of `findings-envelope.md` this emitter writes to. Moves
#: independently of `SCHEMA_VERSION`: one tracks what a maltriage report looks
#: like, the other tracks what three tools have agreed to say to each other,
#: and they change for different reasons.
#:
#: 0.2 changed what `severity` means for a container, and so it is a new
#: version rather than a quiet fix: the specification tells a consumer to
#: reject a version it does not recognise, which is exactly right for a
#: consumer that would otherwise read a container's `info` as "examined,
#: nothing found" when a member was `high`.
ENVELOPE_VERSION = "0.2"

#: Findings whose substance is a string the subject supplied. Nothing was
#: tested to produce these, so `validated` is false: the emitter transcribed
#: what the file said about itself, and a file can say anything.
#:
#: Everything not listed here is true, because something was compared,
#: counted, walked or computed and could have come back the other way. See
#: `findings-envelope.md` for the three that look like transcription and are
#: not - `ipv4_present` rejects out-of-range octets, `registry_persistence_
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

    The obvious test - did the emitter compute it rather than assume it - is
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


def envelopes_for(report: Report):
    """A report and everything inside it, as envelopes, container first.

    Each member is a subject of its own, identified by its own content hash
    and linked to its container by the container's hash and nothing else: a
    member's name inside an archive is a filename the sample chose, and the
    envelope carries no filenames. Until 0.2 only the outermost report was
    emitted, so a ZIP carrying a disguised PE produced one envelope saying
    `info` with no findings while the scan itself failed on it.
    """
    yield to_envelope(report)
    container = _subject_id(report)
    for child in report.children:
        for envelope in envelopes_for(child):
            if envelope["subject"].get("contained_in") is None:
                envelope["subject"]["contained_in"] = container
            yield envelope


def _subject_id(report: Report) -> str | None:
    sha256 = (report.data.get("hashes") or {}).get("sha256")
    return f"sha256:{sha256}" if sha256 else None


def to_envelope(report: Report) -> dict[str, Any]:
    """One report, as one envelope.

    `severity` is `report.severity`, which counts what is inside. It was the
    worst of this subject's own findings alone, which is the v0.5.5 defect
    in a second place: the exit code and the corpus harness asked the
    propagating property, and this asked something else, so the three
    disagreed about the same file. `contains` names the members whose
    envelopes explain a severity that this one's findings do not.
    """
    hashes = report.data.get("hashes") or {}
    filetype = report.data.get("filetype") or {}
    sha256 = hashes.get("sha256")

    subject: dict[str, Any] = {
        # A content address, algorithm included in the string so the id is a
        # single comparable token. Absent only if hashing itself failed, in
        # which case `incomplete` says so and the subject cannot be correlated
        # - which is the honest answer rather than a fabricated one.
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

    envelope = {
        "envelope_version": ENVELOPE_VERSION,
        "emitter": {"name": "maltriage", "version": _version()},
        "subject": subject,
        "observed_at": report.analyzed_at,
        "severity": report.severity,
        "findings": findings,
        "incomplete": _incomplete(report),
    }
    if report.children:
        envelope["contains"] = [_subject_id(child) for child in report.children]
    return envelope


def _incomplete(report: Report) -> list[dict[str, str]]:
    """Everything that did not run, and everything that ran and came back
    short, with the scanning machine scrubbed out of it.

    Until this, only `report.errors` crossed. A parser that stopped early
    writes to its `parse_errors` instead, and those never reached the
    envelope, so a ZIP refused unopened by `archive_max_directory_bytes`
    went out as `info`, no findings, nothing incomplete: the exact "examined,
    nothing found" this module's docstring says the field exists to prevent.
    `Report.thin()` is the same computation the human report prints.
    """
    entries = sorted(report.errors.items()) + sorted(report.thin().items())
    return [{"source": _scrub(source, report), "reason": _scrub(reason, report)}
            for source, reason in entries]


#: A quoted string with a path separator in it, which is how Python quotes the
#: file in every `OSError`.
_QUOTED_PATH = re.compile(r"""(['"])[^'"\n]*[\\/][^'"\n]*\1""")
#: A drive-letter or UNC path, which may appear unquoted.
_WINDOWS_PATH = re.compile(r"""(?<![\w])(?:[A-Za-z]:[\\/]|\\\\)[^\s'"]*""")
#: A POSIX absolute path of at least two components. `/JS` and `/AA` are
#: PDF names in a YARA message and are one component, so they survive.
_POSIX_PATH = re.compile(r"""(?<![\w.:/\\])/(?:[^\s'"/]+/)+[^\s'"/]*""")


def _scrub(text: str, report: Report) -> str:
    """`text` with every filesystem path and the subject's own name removed.

    The envelope promises no filesystem path and no filename, and `incomplete`
    is the one field built from messages written for a person at the
    scanning machine: exception text quotes the file it failed on, and a
    rule-directory error names the directory. Findings are not scrubbed. A
    Windows path inside a sample is an indicator about the sample, and
    removing it would destroy the finding; what this removes is the machine
    that did the looking.
    """
    known = [str(report.path), str(Path.home()), tempfile.gettempdir(), str(Path.cwd())]
    for value in sorted({k for k in known if k and len(k) > 2}, key=len, reverse=True):
        text = text.replace(value, "<path>")
    text = _QUOTED_PATH.sub("'<path>'", text)
    text = _WINDOWS_PATH.sub("<path>", text)
    text = _POSIX_PATH.sub("<path>", text)
    name = report.filename or ""
    if len(name) >= 3:
        text = re.sub(r"(?<![\w.-])" + re.escape(name) + r"(?![\w.-])", "<file>", text)
    return text


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
    """Every report and every member, as one flat list of envelopes.

    Built on `envelopes_for` rather than `to_envelope`, which is what it was
    until 0.2 and which is how it dropped every archive member too.
    """
    return [envelope for report in reports for envelope in envelopes_for(report)]


def _version() -> str:
    from . import __version__
    return __version__
