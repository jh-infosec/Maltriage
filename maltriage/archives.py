"""
Archive recursion, and the safety work that has to come with it.

Opening an untrusted container is the first thing this tool does that has an
attack surface of its own. Every other extractor reads bytes and reports what
it saw; this one is handed a structure whose author chose the entry names, the
declared sizes, the nesting depth and the compression ratio, and acts on them.

So the rules are stated here rather than discovered later:

**Nothing an archive says about itself is believed.** A ZIP entry declares an
uncompressed size in its header. That number is a claim by the sample, and a
zip bomb is exactly the case where it is a lie, so every member is read
through a cap and the cap is what stops the read. The declared size is
recorded and never used as a bound.

**No member may land outside the staging directory.** Entry names are
attacker-controlled text: `../../../etc/cron.d/x`, `C:\\Windows\\System32\\x`,
a name that is a symlink to somewhere else. `safe_member_path` resolves the
candidate and refuses anything that escapes, and refusing is reported as a
finding rather than logged and skipped.

**The budget is shared by the whole tree, not by each archive.** A bomb does
not need one enormous member: it can be a thousand archives of a thousand
entries, each individually reasonable. Depth, entry count, total bytes written
and wall-clock time are therefore carried in one `Budget` down the recursion,
and the first one to run out stops the walk and says so.

**The pipeline recurses, not this module.** An extractor that called
`analyse` would import the pipeline that imports it, and would own a budget
that spans files it cannot see. This module stages members into a directory
the pipeline created and will delete, and records what it staged. The walk
belongs to whoever owns the tree.

**Nothing is executed, and nothing is decompressed in place.** Members are
written to a temporary directory under the pipeline's control and removed when
the scan of them finishes, successfully or not.
"""

from __future__ import annotations

import gzip
import tarfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .base import RandomAccessExtractor
from .config import config_bool, config_int
from .models import mk_finding

#: Families this extractor will open. RAR and 7z are recognised by the
#: signature table and deliberately not opened: both need a third-party
#: decompressor, and an optional dependency that unpacks hostile input is a
#: larger decision than an optional dependency that parses it.
ARCHIVE_FAMILIES = ("zip", "gzip", "tar")

#: Recognised, not opened. Reported so the absence of member analysis has a
#: reason attached rather than looking like an archive with nothing in it.
UNSUPPORTED_FAMILIES = ("rar", "7z")

FINDING_KEY = "archive_member"


@dataclass
class Budget:
    """What the whole recursion may spend, not what one archive may.

    One of these is created by the top-level `analyse` call and handed to
    every nested one. A thousand archives of a thousand small entries is the
    same attack as one enormous entry, and a per-archive limit does not see
    it.
    """

    max_depth: int = 3
    max_entries: int = 1000
    max_total_bytes: int = 268435456        # 256 MiB written across the tree
    max_member_bytes: int = 67108864        # 64 MiB for any single member
    min_ratio_bytes: int = 1048576          # below this, ratio is not judged
    max_ratio: int = 200                    # uncompressed:compressed
    deadline: float | None = None

    entries_used: int = 0
    bytes_used: int = 0
    #: Why the walk stopped early, if it did. Carried into the report, because
    #: a scan that ran out of budget is thinner than one that did not and the
    #: reader cannot tell the difference from the findings alone.
    exhausted: list[str] = field(default_factory=list)

    def note(self, reason: str) -> None:
        if reason not in self.exhausted:
            self.exhausted.append(reason)

    def out_of_time(self) -> bool:
        if self.deadline is not None and time.monotonic() > self.deadline:
            self.note("time limit reached")
            return True
        return False

    def take_entry(self) -> bool:
        if self.entries_used >= self.max_entries:
            self.note(f"entry limit of {self.max_entries} reached")
            return False
        self.entries_used += 1
        return True

    def room_for(self, want: int) -> int:
        """How many bytes this member may be given, which may be none."""
        left = self.max_total_bytes - self.bytes_used
        if left <= 0:
            self.note(f"total byte limit of {self.max_total_bytes} reached")
            return 0
        return min(want, left, self.max_member_bytes)

    def spend(self, used: int) -> None:
        self.bytes_used += used


def budget_from(config: dict[str, Any]) -> Budget:
    """A budget built from validated config, with the clock started."""
    seconds = config_int(config, "archive_max_seconds", 60)
    return Budget(
        max_depth=config_int(config, "archive_max_depth", 3),
        max_entries=config_int(config, "archive_max_entries", 1000),
        max_total_bytes=config_int(config, "archive_max_total_bytes", 268435456),
        max_member_bytes=config_int(config, "archive_max_member_bytes", 67108864),
        min_ratio_bytes=config_int(config, "archive_ratio_floor_bytes", 1048576),
        max_ratio=config_int(config, "archive_max_ratio", 200),
        deadline=time.monotonic() + seconds,
    )


def safe_member_path(root: Path, name: str) -> Path | None:
    """Where a member may be written, or `None` if it may not be.

    The third use of a primitive this project keeps rewriting, after
    `loganalysis._safe_path` and claude-recon-agent's wordlist roots, which is
    why it is here rather than inside the one caller.

    Refused: an absolute path in either POSIX or Windows spelling, a drive
    letter, a UNC path, any `..` segment, an empty or dot-only name, and
    anything whose resolved location is not under `root`. The last check is
    the one that matters, because the others can be spelled in ways nobody
    enumerates correctly -- mixed separators, `..` after a symlink, a name
    that is harmless until the filesystem normalises it.
    """
    if not name or name in (".", ".."):
        return None
    # Windows spellings first: a POSIX path parser treats `C:\x` as one
    # relative filename, which is how an absolute path survives a check that
    # only asked PurePosixPath.
    windows = PureWindowsPath(name)
    if windows.is_absolute() or windows.drive or name.startswith("\\\\"):
        return None
    posix = PurePosixPath(name.replace("\\", "/"))
    if posix.is_absolute() or any(part == ".." for part in posix.parts):
        return None

    candidate = (root / posix).resolve()
    root = root.resolve()
    if candidate != root and root not in candidate.parents:
        return None
    return candidate


def _copy_bounded(source, target: Path, budget: Budget,
                  chunk: int = 262144) -> tuple[int, bool]:
    """Write a member out, stopping at whatever the budget allows.

    Returns the bytes written and whether the member was truncated. The cap is
    what ends the read: a declared size is a claim by the sample, and this is
    the function a zip bomb is aimed at.
    """
    allowed = budget.room_for(budget.max_member_bytes)
    if allowed <= 0:
        return 0, True
    written = 0
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as out:
        while written < allowed:
            block = source.read(min(chunk, allowed - written))
            if not block:
                break
            out.write(block)
            written += len(block)
        truncated = bool(source.read(1))
    budget.spend(written)
    return written, truncated


class ArchiveExtractor(RandomAccessExtractor):
    """List and stage the members of a container, under a shared budget.

    Produces no findings about what is *inside* a member: the pipeline
    analyses each staged file and attaches the result as a child report. What
    this extractor reports is the container's own behaviour -- an entry that
    tries to escape, a ratio that only a bomb reaches, an encrypted member
    nothing can read, and everything the budget refused.
    """

    name = "archive"

    def applies_to(self, path: Path, ctx: dict[str, Any],
                   config: dict[str, Any]) -> bool:
        if not config_bool(config, "archive_recursion", True):
            return False
        family = ctx.get("family")
        return family in ARCHIVE_FAMILIES or family in UNSUPPORTED_FAMILIES

    def parse(self, path: Path, ctx: dict[str, Any],
              config: dict[str, Any]) -> dict[str, Any]:
        family = ctx.get("family")
        budget: Budget = ctx.get("budget") or budget_from(config)
        depth = ctx.get("depth", 0)
        staging = ctx.get("staging")

        data: dict[str, Any] = {
            "format": family,
            "entries": [],
            "staged": [],
            "member_count": 0,
            "encrypted_members": 0,
            "refused": [],
            "parse_errors": [],
            "truncated": False,
        }

        if family in UNSUPPORTED_FAMILIES:
            data["parse_errors"].append(
                f"{family}: recognised but not opened, because unpacking it "
                f"needs a third-party decompressor this tool does not take")
            return data

        if depth >= budget.max_depth:
            budget.note(f"depth limit of {budget.max_depth} reached")
            data["parse_errors"].append(
                f"depth: {depth} is at the configured limit, so the members "
                f"of this container were not unpacked")
            return data

        if staging is None:
            data["parse_errors"].append(
                "staging: no directory was provided, so members were listed "
                "and not unpacked")

        try:
            if family == "zip":
                self._zip(path, Path(staging) if staging else None, budget, data)
            elif family == "gzip":
                self._gzip(path, Path(staging) if staging else None, budget, data)
            else:
                self._tar(path, Path(staging) if staging else None, budget, data)
        except Exception as exc:
            # A container that will not open is a fact about the sample, not a
            # failure of the scan: a truncated ZIP and a PE wearing a .zip
            # extension both land here.
            data["parse_errors"].append(f"{family}: {type(exc).__name__}: {exc}")

        if budget.exhausted:
            data["parse_errors"].extend(f"budget: {why}" for why in budget.exhausted)
        return data

    # One reader per format. Each one yields the same shape so the findings
    # below do not have to know which container they came from.

    def _zip(self, path: Path, staging: Path | None, budget: Budget,
             data: dict[str, Any]) -> None:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if budget.out_of_time():
                    data["truncated"] = True
                    return
                if info.is_dir():
                    continue
                data["member_count"] += 1
                encrypted = bool(info.flag_bits & 0x1)
                entry = {
                    "name": _display(info.filename),
                    "declared_size": info.file_size,
                    "compressed_size": info.compress_size,
                    "encrypted": encrypted,
                }
                if encrypted:
                    data["encrypted_members"] += 1
                    entry["staged"] = False
                    data["entries"].append(entry)
                    continue
                self._stage(archive.open(info),  # binary API
                            info.filename, entry,
                            staging, budget, data)
                if data["truncated"]:
                    return

    def _tar(self, path: Path, staging: Path | None, budget: Budget,
             data: dict[str, Any]) -> None:
        with tarfile.open(path) as archive:  # binary API
            for member in archive:
                if budget.out_of_time():
                    data["truncated"] = True
                    return
                if not member.isfile():
                    # Symlinks, hard links, devices and FIFOs. Named rather
                    # than followed: a link is a path the sample chose, and
                    # following one is how an extractor writes outside itself
                    # without any `..` appearing anywhere.
                    if member.issym() or member.islnk():
                        data["refused"].append(
                            {"name": _display(member.name), "reason": "link entry"})
                    continue
                data["member_count"] += 1
                entry = {
                    "name": _display(member.name),
                    "declared_size": member.size,
                    "compressed_size": None,
                    "encrypted": False,
                }
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                self._stage(handle, member.name, entry, staging, budget, data)
                if data["truncated"]:
                    return

    def _gzip(self, path: Path, staging: Path | None, budget: Budget,
              data: dict[str, Any]) -> None:
        # A gzip stream is one member and carries no entry list. The stored
        # name is optional and is a name the sample chose, so it goes through
        # the same path check as any other.
        stored = _gzip_stored_name(path) or (path.stem or "member")
        data["member_count"] += 1
        entry = {
            "name": _display(stored),
            "declared_size": None,
            "compressed_size": path.stat().st_size,
            "encrypted": False,
        }
        with gzip.open(path, "rb") as handle:
            self._stage(handle, stored, entry, staging, budget, data)

    def _stage(self, handle, raw_name: str, entry: dict[str, Any],
               staging: Path | None, budget: Budget, data: dict[str, Any]) -> None:
        if not budget.take_entry():
            data["truncated"] = True
            entry["staged"] = False
            data["entries"].append(entry)
            return

        if staging is None:
            entry["staged"] = False
            data["entries"].append(entry)
            return

        target = safe_member_path(staging, raw_name)
        if target is None:
            data["refused"].append(
                {"name": entry["name"], "reason": "path escapes the container"})
            entry["staged"] = False
            data["entries"].append(entry)
            return

        with handle:
            written, truncated = _copy_bounded(handle, target, budget)
        entry["bytes_staged"] = written
        entry["truncated"] = truncated
        entry["staged"] = written > 0
        if truncated:
            data["truncated"] = True
        if written:
            # Both halves: where the bytes are now, and where they came from.
            # The second is taken from the container rather than from the
            # staging path, because a path is spelled by the filesystem that
            # holds it -- on Windows that produced `lib\thing.bin` for a ZIP
            # entry the archive itself calls `lib/thing.bin`, so the same
            # container described itself differently depending on who scanned
            # it.
            data["staged"].append({"path": str(target), "inside": _inside(raw_name)})
        data["entries"].append(entry)

    def findings(self, data: dict[str, Any],
                 config: dict[str, Any]) -> list[dict[str, Any]]:
        out = []

        for refusal in data.get("refused") or []:
            if refusal["reason"] == "path escapes the container":
                # High, and the second finding in this project to earn it.
                # The argument is `extension_mismatch`'s: content that lies
                # about what it is deserves a human on that alone, and an
                # entry naming a path outside its own container is a lie with
                # no benign reading. A build script that produces one is
                # broken in a way worth knowing about too.
                out.append(mk_finding(
                    self.name, "archive_path_traversal",
                    f"entry {refusal['name']!r} names a path outside the "
                    f"container, which no extractor should honour", "high",
                    evidence=[{"name": "entry_name", "value": refusal["name"]}]))
            else:
                out.append(mk_finding(
                    self.name, "archive_link_entry",
                    f"entry {refusal['name']!r} is a link rather than a file, "
                    f"so it was named and not followed", "low",
                    evidence=[{"name": "entry_name", "value": refusal["name"]}]))

        encrypted = data.get("encrypted_members") or 0
        if encrypted:
            # Low. An encrypted archive is ordinary; what is not ordinary is
            # that nothing inside it can be examined, which is a fact about
            # the scan rather than about the sample.
            out.append(mk_finding(
                self.name, "archive_encrypted",
                f"{encrypted} encrypted member(s), which cannot be read and "
                f"were not analysed", "low",
                evidence=[{"name": "encrypted_members", "value": encrypted}]))

        ratio = _expansion_ratio(data)
        floor = config_int(config, "archive_ratio_floor_bytes", 1048576)
        limit = config_int(config, "archive_max_ratio", 200)
        staged = sum(e.get("bytes_staged") or 0 for e in data.get("entries") or [])
        if ratio is not None and staged >= floor and ratio >= limit:
            out.append(mk_finding(
                self.name, "archive_expansion_ratio",
                f"members expand to {ratio:.0f} times the container's size, "
                f"which compression of ordinary content does not reach",
                "medium",
                evidence=[{"name": "expansion_ratio", "value": round(ratio, 1)},
                          {"name": "threshold", "value": limit},
                          {"name": "bytes_staged", "value": staged}]))

        return out


def _expansion_ratio(data: dict[str, Any]) -> float | None:
    """Staged bytes over compressed bytes, from what was actually read.

    Computed from bytes written rather than from declared sizes, for the
    reason the module docstring gives: the declared size is the number a bomb
    lies about.
    """
    staged = sum(e.get("bytes_staged") or 0 for e in data.get("entries") or [])
    compressed = sum(e.get("compressed_size") or 0 for e in data.get("entries") or [])
    if not compressed or not staged:
        return None
    return staged / compressed


def _gzip_stored_name(path: Path) -> str | None:
    """The original filename a gzip header may carry, if it is usable."""
    try:
        with path.open("rb") as handle:
            head = handle.read(10)
            if len(head) < 10 or head[:2] != b"\x1f\x8b" or not head[3] & 0x08:
                return None
            name = bytearray()
            while len(name) < 256:
                byte = handle.read(1)
                if not byte or byte == b"\x00":
                    break
                name += byte
        return name.decode("utf-8", "replace") or None
    except OSError:
        return None


def _inside(raw_name: str) -> str:
    """A member's name as the container spells it.

    Forward slashes, because every format here uses them internally: the ZIP
    specification requires it, and TAR and GZIP are POSIX formats. A name is
    sanitised the same way the displayed one is, since this reaches a report.
    """
    return _display(raw_name.replace("\\", "/").lstrip("./"))


def _display(name: str) -> str:
    """An entry name as it appears in a report.

    Entry names are sample-supplied text and reach a terminal, so they are
    sanitised on the way out like every other string this project reports.
    """
    from .base import safe_text
    return safe_text(name, limit=256)
