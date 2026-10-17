"""
Known-good hashes: files the caller has decided are not worth a verdict.

This is the one place in the project where an answer comes from outside the
bytes. Everything else reads the file and decides; this reads a list somebody
supplied and stops. That is a meaningful difference and the reason the
arrangement below is so cautious about saying what it did.


## Why hashes, and not the signer

The obvious alternative on Windows is "signed by Microsoft", and this project
already extracts Authenticode signer names. It is not usable here, and the
reason is a rule this project set long before the question came up:
Authenticode is reported as presence and signer names only, never validity.
A certificate blob can be copied into any file. Treating an unvalidated
signer name as known-good would mean a sample could nominate itself, which is
worse than having no feature at all.

So the set is hashes, and the caller supplies it. SHA-256 cannot be
nominated by the file.


## What it does, and what it refuses to do

A matched file is still analysed in full and every finding is still reported
at its real severity. What changes is the gate: a file the caller vouched for
does not fail a build. The report says plainly that this happened and how
many files it happened to, because a count that quietly drops files is the
failure this project has now avoided four times by saying so out loud.

Nothing here is a default. With no set supplied, nothing is suppressed.
"""

from __future__ import annotations
import json
from pathlib import Path


def load(path: Path) -> set[str]:
    """A set of lowercase SHA-256 digests, from text or from a manifest.

    Two formats because two things produce them. A text file with one hash
    per line is what every other tool in this space emits, and `#` comments
    and blank lines are skipped so a list can say where it came from. A
    corpus manifest is accepted as well, because `--write-manifest` already
    produces exactly this and asking somebody to convert it would be asking
    them to write a script to delete punctuation.
    """
    raw = path.read_text(encoding="utf-8")
    if raw.lstrip().startswith("{"):
        payload = json.loads(raw)
        if not isinstance(payload, dict) or "labels" not in payload:
            raise ValueError(f"not a hash list or a corpus manifest: {path}")
        digests = [d for group in (payload["labels"] or {}).values() for d in group]
    else:
        digests = [line.split("#", 1)[0].strip() for line in raw.splitlines()]

    out = set()
    for digest in digests:
        value = digest.strip().lower()
        if not value:
            continue
        if len(value) != 64 or not all(c in "0123456789abcdef" for c in value):
            # Refused rather than skipped. A list half of which is MD5 would
            # otherwise load as a working set that silently vouches for
            # nothing, and the caller would never learn their file was wrong.
            raise ValueError(
                f"{path}: {value[:16]!r} is not a SHA-256 digest, and a list "
                f"this tool half-understood is worse than one it refused")
        out.add(value)
    if not out:
        raise ValueError(f"{path}: holds no hashes")
    return out


def normalise(hashes: set[str]) -> set[str]:
    """One lowercase set, built once.

    `load` already lowercases what it reads, but the scanning entry points
    take a set from the caller and nothing obliges them to have used `load`.
    Normalising inside the comparison would rebuild the set for every file in
    the corpus, so it happens here, once, where the set arrives.
    """
    return {digest.strip().lower() for digest in hashes}


def matches(report, hashes: set[str]) -> bool:
    """Whether this file's SHA-256 is in the set, which must be normalised.

    The file's own digest, not any member's. A known-good archive whose
    contents were swapped has a different hash, and an archive holding one
    known-good member is not itself known-good.

    The `.lower()` is defensive rather than demonstrated. The set arrives
    normalised and `hexdigest` is lowercase, so mutation testing confirms no
    test fails without it, and it says so here rather than pretending to be
    pinned. It is kept because the day the hash extractor changes its spelling
    this is the line that would otherwise stop matching, silently and
    everywhere.
    """
    digest = (report.data.get("hashes") or {}).get("sha256")
    return bool(digest) and digest.lower() in hashes


def mark(report, hashes: set[str]) -> bool:
    """Record on the report whether it was vouched for, and say so."""
    matched = matches(report, hashes)
    report.data["known_good"] = {"matched": matched, "entries": len(hashes)}
    return matched
