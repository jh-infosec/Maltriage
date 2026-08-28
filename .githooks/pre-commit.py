#!/usr/bin/env python3
"""Refuse to commit anything that looks like an executable or a container.

A .gitignore keyed on extensions cannot protect a malware project, because
the samples that matter are the ones lying about what they are. `invoice.pdf`
in this repo's own fixtures is a PE. Any rule that trusts the name is
defeated by the first sample that deserves attention.

So this checks the bytes, on the staged content rather than the working tree,
because staged content is what a commit actually records.

Two checks, and the second exists because the first was not enough. Reading
offset 0 catches a file that *is* an executable. It does not catch a file
that *carries* one, and this repository ships a fixture of exactly that
shape: `carrier.pdf` begins with `%PDF` and holds a complete PE at offset
549. Tested against the previous version of this hook, it committed cleanly.
maltriage's own `embedded_pe_header` rule flags it at medium, so the tool
detected what its own guard waved through.

Install, per clone:

    git config core.hooksPath .githooks

Bypass, when you genuinely mean it:

    ALLOW_BINARY=1 git commit ...

This file is deliberately dependency-free and project-agnostic. Copy it into
any repository that must never receive a sample.
"""

import os
import subprocess
import sys

# (magic bytes, what it is). Offset 0 in every case, which is where a real
# loader looks too.
SIGNATURES = [
    (b"MZ", "PE/DOS executable"),
    (b"\x7fELF", "ELF executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O fat binary"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit, big endian"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit, big endian"),
    (b"\xd0\xcf\x11\xe0", "OLE2 compound document"),
    (b"PK\x03\x04", "ZIP archive (or OOXML/JAR/APK)"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"\x1f\x8b", "GZIP stream"),
    (b"\xed\xab\xee\xdb", "RPM package"),
]

# How much of a staged blob to search for a buried executable. A payload put
# past this is a payload in a file large enough to be worth looking at by
# hand anyway, and the cap keeps the hook fast on a big legitimate commit.
SEARCH_BYTES = 4 * 1024 * 1024

# Paths that are allowed to trip the check. Kept explicit and kept short: an
# entry here is a standing exception and should have to justify itself.
ALLOWED = set()


def staged_paths():
    out = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines() if line]


def staged_blob(path, count=SEARCH_BYTES):
    """Staged bytes, not the file on disk. A commit records the former."""
    result = subprocess.run(["git", "show", f":{path}"], capture_output=True)
    return result.stdout[:count] if result.returncode == 0 else b""


def looks_like_a_header(blob):
    """A file that *is* an executable. The cheap, definitive test."""
    for magic, label in SIGNATURES:
        if blob.startswith(magic):
            return f"{label}, first bytes {blob[:8].hex()}"
    return None


def carries_an_executable(blob):
    """A file that *carries* one somewhere other than its start.

    Three parts, all required, because two of them alone match random data
    often enough to matter and this hook must not cry wolf on a compressed
    asset. A payload with the DOS stub stripped will not match, which is the
    price of that: this is a guard, not a detector, and maltriage is the
    detector.
    """
    if blob[:2] != b"MZ":
        mz = blob.find(b"MZ")
        if (mz > 0 and b"PE\x00\x00" in blob
                and b"This program cannot be run in DOS mode" in blob):
            return f"a PE header at offset {mz}, inside a file that is not one"

    # ELF magic plus a plausible identifier: EI_CLASS, EI_DATA, EI_VERSION.
    # The four magic bytes alone occur about once every 4 GB of random data.
    start = 0 if blob[:4] != b"\x7fELF" else 4
    while True:
        found = blob.find(b"\x7fELF", start)
        if found < 0 or found + 7 > len(blob):
            break
        ident = blob[found + 4:found + 7]
        if ident[0] in (1, 2) and ident[1] in (1, 2) and ident[2] == 1:
            return f"an ELF header at offset {found}, inside a file that is not one"
        start = found + 4
    return None


def main():
    if os.environ.get("ALLOW_BINARY"):
        print("pre-commit: ALLOW_BINARY set, magic-byte check skipped")
        return 0

    caught = []
    for path in staged_paths():
        if path in ALLOWED:
            continue
        blob = staged_blob(path)
        if not blob:
            continue
        reason = looks_like_a_header(blob) or carries_an_executable(blob)
        if reason:
            caught.append((path, reason))

    if not caught:
        return 0

    print("pre-commit: refusing to commit, these are staged and are not text",
          file=sys.stderr)
    print(file=sys.stderr)
    for path, reason in caught:
        print(f"  {path}", file=sys.stderr)
        print(f"      {reason}", file=sys.stderr)
    print(file=sys.stderr)
    print("  A file's name does not decide this. Check what it actually is",
          file=sys.stderr)
    print("  before overriding. To unstage:  git restore --staged <path>",
          file=sys.stderr)
    print("  To override deliberately:       ALLOW_BINARY=1 git commit ...",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
