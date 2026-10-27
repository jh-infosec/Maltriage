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
import html
import re
import struct
import tarfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .base import RandomAccessExtractor
from .config import config_bool, config_int, config_list
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
    #: Entries looked at, of any kind, across the tree. `max_entries` bounds
    #: what is unpacked; this bounds what is merely listed. They are two
    #: limits because the first one never saw a directory, an encrypted
    #: member or a tar link, and an archive made of nothing else walked past
    #: it: 3,000 encrypted entries against a cap of 10 were all recorded, and
    #: `truncated` stayed false.
    max_listed: int = 10000
    #: The largest ZIP central directory opened at all. `zipfile` parses the
    #: whole directory inside its own constructor, before any loop or budget
    #: here runs: 200,000 empty entries in a 17 MB file cost 114 MB to open.
    max_directory_bytes: int = 4194304
    deadline: float | None = None

    entries_used: int = 0
    listed_used: int = 0
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

    def take_listing(self) -> bool:
        """Whether one more entry of any kind may be looked at."""
        if self.listed_used >= self.max_listed:
            self.note(f"listing limit of {self.max_listed} entries reached")
            return False
        self.listed_used += 1
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
        max_listed=config_int(config, "archive_max_listed_entries", 10000),
        max_directory_bytes=config_int(config, "archive_max_directory_bytes", 4194304),
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
    enumerates correctly - mixed separators, `..` after a symlink, a name
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


#: Names Windows maps to a device rather than a file, in any case and with any
#: extension. A member written as `NUL` was discarded by the device, then
#: failed `is_file()`, and was skipped without a word.
_WINDOWS_DEVICES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{n}" for n in range(1, 10)} | {f"LPT{n}" for n in range(1, 10)}
    | {f"COM{n}" for n in "\u00b9\u00b2\u00b3"} | {f"LPT{n}" for n in "\u00b9\u00b2\u00b3"})

#: Characters no Windows filename may hold. `:` is the one that matters most:
#: `a.pdf:hidden` writes an alternate data stream onto `a.pdf`.
_WINDOWS_FORBIDDEN = set('<>:"|?*') | {chr(c) for c in range(32)}


def staging_name(raw_name: str, limit: int = 120) -> str:
    """The base name a member is written under, safe on any filesystem.

    Only the last component of the sample's name, because each member already
    has a directory of its own. The extension survives, since
    `extension_mismatch` reads it and a member renamed to `member` would hide
    exactly the disguise that rule exists to find. Everything a filesystem
    would reinterpret is neutralised: forbidden characters, a trailing dot or
    space that Windows silently strips, and device names.
    """
    base = raw_name.replace("\\", "/").rsplit("/", 1)[-1]
    base = "".join("_" if ch in _WINDOWS_FORBIDDEN else ch for ch in base)
    base = base.rstrip(". ")
    if not base:
        return "member"
    if base.split(".", 1)[0].upper() in _WINDOWS_DEVICES:
        base = "_" + base
    if len(base) > limit:
        stem, dot, suffix = base.rpartition(".")
        if dot and 0 < len(suffix) <= 16:
            base = stem[: limit - len(suffix) - 1] + "." + suffix
        else:
            base = base[:limit]
    return base


def central_directory_bytes(path: Path) -> int | None:
    """How large a ZIP says its central directory is, read without opening it.

    `zipfile` parses the whole directory in its constructor, so this has to
    run first and has to agree with it exactly: a check that read a different
    end record from the one `zipfile` then uses would guard nothing. So it
    asks `zipfile`'s own end-record reader, and falls back to a minimal
    parser only if a future Python removes that private function. A test
    holds the two to the same answer. `None` means no end record was found,
    in which case `zipfile` will refuse the file itself.

    The size is a claim by the sample, and that is safe here in one
    direction: `zipfile` reads exactly this many bytes of directory, so a
    file that understates it is parsed less, not more.
    """
    try:
        with path.open("rb") as handle:  # binary API
            reader = getattr(zipfile, "_EndRecData", None)
            if reader is not None:
                record = reader(handle)
                return None if record is None else int(record[zipfile._ECD_SIZE])
            return _central_directory_bytes_fallback(handle)
    except (OSError, struct.error, IndexError, ValueError):
        return None


def _central_directory_bytes_fallback(handle) -> int | None:
    """The end-record search, for a Python whose `zipfile` no longer exposes it."""
    handle.seek(0, 2)
    size = handle.tell()
    start = max(size - 65535 - 22, 0)
    handle.seek(start)
    tail = handle.read()
    at = tail.rfind(b"PK\x05\x06")
    if at < 0 or len(tail) - at < 22:
        return None
    directory = struct.unpack_from("<L", tail, at + 12)[0]
    locator = at - 20
    if locator >= 0 and tail[locator:locator + 4] == b"PK\x06\x07":
        offset = struct.unpack_from("<Q", tail, locator + 8)[0]
        handle.seek(offset)
        record = handle.read(56)
        if len(record) == 56 and record[:4] == b"PK\x06\x06":
            directory = struct.unpack_from("<Q", record, 40)[0]
    return directory


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
    this extractor reports is the container's own behaviour - an entry that
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

        # What kind of container this turned out to be, read from the member
        # names rather than from the extension. A DOCX, a JAR and an APK are
        # all ZIP files, and the magic number cannot tell them apart - which
        # is why a corpus of 58 real documents reported `zip 58` and nothing
        # more useful.
        data["container_kind"] = _container_kind(data["entries"])
        data["duplicate_names"], data["case_collisions"] = _name_collisions(data["entries"])
        data["macro_project"] = _has_macro_project(data["entries"])
        if data["container_kind"] == "ooxml":
            # Read now, while the parts are still staged: the directory is
            # deleted once the members have been analysed.
            data["relationships"] = external_relationships(data["staged"])
            data["dde"] = dde_fields(data["staged"])
            if data["dde"]["partial_parts"]:
                data["parse_errors"].append(
                    f"fields: {data['dde']['partial_parts']} part(s) larger than "
                    "was read, so a DDE field past that point would not be seen")
            if data["dde"]["truncated"]:
                data["parse_errors"].append(
                    "fields: more DDE fields than were kept, so the list is partial")
            if data["truncated"] and not data["dde"]["fields"]:
                data["parse_errors"].append(
                    "fields: the listing stopped at the budget, so finding no "
                    "DDE field is not evidence that there is none")
            if data["relationships"]["truncated"]:
                data["parse_errors"].append(
                    "relationships: more external relationships than were kept, "
                    "so the list is partial")
            if data["truncated"] and not data["relationships"]["external"]:
                # The macro caveat's reasoning: a document built to put the
                # part that carries its remote template after the point the
                # budget stops would otherwise read as having none.
                data["parse_errors"].append(
                    "relationships: the listing stopped at the budget, so finding "
                    "no external relationship is not evidence that there is none")
        data["macro_capable_name"] = (
            path.suffix.lower() in config_list(config, "macro_capable_extensions", []))
        if data["truncated"] and not data["macro_project"]:
            # Absence of evidence. The listing stopped early, so "no macro
            # project" means "none among the members we got to", and a
            # container built to put its VBA last would read as clean.
            data["parse_errors"].append(
                "members: the listing stopped at the budget, so finding no "
                "macro project is not evidence that there is none")
        return data

    # One reader per format. Each one yields the same shape so the findings
    # below do not have to know which container they came from.

    def _zip(self, path: Path, staging: Path | None, budget: Budget,
             data: dict[str, Any]) -> None:
        # Before `zipfile` is constructed, because construction is where the
        # cost is: it parses the whole central directory into memory, and no
        # loop below can take that back.
        directory = central_directory_bytes(path)
        if directory is not None and directory > budget.max_directory_bytes:
            budget.note(f"central directory larger than "
                        f"{budget.max_directory_bytes} bytes")
            data["truncated"] = True
            data["parse_errors"].append(
                f"zip: central directory of {directory} bytes is larger than "
                f"archive_max_directory_bytes ({budget.max_directory_bytes}), "
                "so the archive was not opened")
            return
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if budget.out_of_time() or not budget.take_listing():
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
                # `TarFile` keeps every member it has read in a list, so the
                # listing limit is also what bounds its memory.
                if budget.out_of_time() or not budget.take_listing():
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

        if safe_member_path(staging, raw_name) is None:
            data["refused"].append(
                {"name": entry["name"], "reason": "path escapes the container"})
            entry["staged"] = False
            data["entries"].append(entry)
            return

        # Checked above, and then not used. The name decides whether a member
        # may be written; it no longer decides where. Two entries both called
        # `invoice.pdf` used to share one file, the second overwrote the
        # first, and recursion analysed the second payload twice and the
        # first not at all. On a case-insensitive filesystem `Payload.exe`
        # and `payload.exe` collided the same way without even matching. Each
        # member now gets a slot of its own, and keeps only its base name, so
        # its extension still means what `extension_mismatch` needs it to.
        # Every reader counts a member before staging it, so the count is
        # unique within this container, and each container stages into a
        # directory of its own.
        slot = staging / f"{data['member_count']:06d}"
        slot.mkdir(exist_ok=False)
        target = slot / staging_name(raw_name)

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
            # holds it - on Windows that produced `lib\thing.bin` for a ZIP
            # entry the archive itself calls `lib/thing.bin`, so the same
            # container described itself differently depending on who scanned
            # it.
            data["staged"].append({"path": str(target), "inside": _inside(raw_name)})
        data["entries"].append(entry)

    def findings(self, data: dict[str, Any],
                 config: dict[str, Any]) -> list[dict[str, Any]]:
        out = []

        duplicates = (data.get("duplicate_names") or 0) + (data.get("case_collisions") or 0)
        if duplicates:
            # Every one of them was analysed; that is the fix. The finding is
            # the ambiguity that remains: an extractor writes one file per
            # name, so what a person gets by opening this archive depends on
            # which entry their tool keeps, and that need not be the one that
            # looked harmless here. `low`, because appending to a ZIP without
            # rewriting it produces the same shape for an innocent reason.
            out.append(mk_finding(
                self.name, "archive_duplicate_entry",
                f"{duplicates} entr{'y' if duplicates == 1 else 'ies'} share a name "
                f"with another ({data.get('duplicate_names') or 0} exactly, "
                f"{data.get('case_collisions') or 0} by case only); each was "
                "analysed, and an extractor will keep only one", "low",
                evidence=[{"name": "duplicate_names", "value": data.get("duplicate_names") or 0},
                          {"name": "case_collisions", "value": data.get("case_collisions") or 0}]))

        relationships = data.get("relationships") or {}
        by_type: dict[str, list[dict[str, Any]]] = {}
        for relation in relationships.get("external") or []:
            by_type.setdefault(relation["type"], []).append(relation)
        for kind, relations in sorted(by_type.items()):
            first = relations[0]
            more = f", and {len(relations) - 1} more" if len(relations) > 1 else ""
            hashes = any(r["scheme"] in ("unc", "file") for r in relations)
            if kind == "attachedTemplate":
                key, what = "ooxml_remote_template", "fetches its template from"
            else:
                key, what = "ooxml_external_reference", f"loads an external {kind} from"
            # `low`, every one, for the reason the macro keys are `low`. A
            # corporate template on SharePoint and a linked image on a file
            # share are ordinary, so neither reaches the gate without a
            # measurement. What does not load by itself is `info`.
            out.append(mk_finding(
                self.name, key,
                f"the document {what} {first['target']}{more}"
                + ("; Windows authenticates to a UNC or file target, which hands "
                   "a password hash to whoever serves it" if hashes else ""),
                "low" if first["autoloads"] else "info",
                evidence=[{"name": "count", "value": len(relations)},
                          {"name": "scheme", "value": first["scheme"]},
                          {"name": "part", "value": first["part"]}],
                discriminator=kind))

        by_field: dict[str, list[dict[str, Any]]] = {}
        for field_ in (data.get("dde") or {}).get("fields") or []:
            by_field.setdefault(field_["field"], []).append(field_)
        for kind, fields in sorted(by_field.items()):
            commands = sorted({f["command"] for f in fields if f["command"]})
            more = f", {len(fields)} in all" if len(fields) > 1 else ""
            where = "a DDE link" if kind == "ddeLink" else f"a {kind} field"
            if commands:
                # The one ooxml key above `low`. A DDE field that names a
                # workbook is a document linking to data; one that names a
                # command interpreter starts it, and there is no ordinary
                # document that does that. Predicted to fire on none of the
                # v0.5.16 document corpus, and the counterfactual will say.
                out.append(mk_finding(
                    self.name, "ooxml_dde_command",
                    f"the document carries {where} that starts "
                    f"{', '.join(commands)}{more}; Office asks before it runs, "
                    "and that prompt is the only thing between opening and execution",
                    "medium",
                    evidence=[{"name": "count", "value": len(fields)},
                              {"name": "part", "value": fields[0]["part"]}],
                    discriminator=kind))
            else:
                out.append(mk_finding(
                    self.name, "ooxml_dde",
                    f"the document carries {where} naming {fields[0]['server'] or 'no server'}"
                    f"{more}; DDE starts the application it names and talks to it",
                    "low",
                    evidence=[{"name": "count", "value": len(fields)},
                              {"name": "part", "value": fields[0]["part"]}],
                    discriminator=kind))

        if data.get("macro_project"):
            # Both at `low`, and that is a decision rather than an oversight.
            # A macro-enabled document is ordinary in most organisations, and
            # this project does not put a key at the gate without a false
            # positive rate behind it. The counterfactual over a document
            # corpus is what should raise either of these, not an argument
            # about how bad macros are.
            if data.get("macro_capable_name"):
                out.append(mk_finding(
                    self.name, "ooxml_macros",
                    "the document carries a compiled VBA project, which its "
                    "extension already says it may", "low"))
            else:
                # The more interesting half. `extension_mismatch` is high in
                # this project because content that lies about what it is
                # deserves a human on that alone, and this is the same shape
                # one layer in: the name promises a document that cannot run
                # code and the content carries code. Held at `low` until a
                # corpus says what it costs, which is the same restraint
                # every other key here was given.
                out.append(mk_finding(
                    self.name, "ooxml_macros_unexpected",
                    "the document carries a compiled VBA project, and its "
                    "extension says it should not be able to", "low"))

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


#: The member that makes a ZIP an Office Open XML document. Every OOXML file
#: has one at the root: it is the part map the format is built around, and
#: nothing else puts a file at that name.
OOXML_MARKER = "[content_types].xml"

#: The same question for a Java archive, which is the other thing a ZIP in an
#: ordinary corpus usually turns out to be.
JAR_MARKER = "meta-inf/manifest.mf"

#: The compiled VBA project. Its presence is what "this document carries
#: macros" means structurally, whatever the extension claims.
MACRO_MEMBER = "vbaproject.bin"


def _name_collisions(entries: list[dict[str, Any]]) -> tuple[int, int]:
    """Entries that share a name with an earlier one, exactly and by case.

    Both counts are of the later entries, so one pair is one collision. Case
    is counted separately because it is a different claim: two identical
    names collide on every filesystem, two names differing only in case
    collide where the person opening the archive is most likely to be,
    which is Windows.
    """
    seen, folded = set(), set()
    exact = by_case = 0
    for entry in entries:
        name = str(entry.get("name") or "").replace("\\", "/")
        if name in seen:
            exact += 1
        elif name.casefold() in folded:
            by_case += 1
        seen.add(name)
        folded.add(name.casefold())
    return exact, by_case


#: Relationship types that make Office fetch the target by itself, on open.
#: A hyperlink is also an external relationship, and every document with a
#: link in it has one, so the rule is about what loads without a click.
#: `attachedTemplate` is remote template injection; `oleObject` is how the
#: Follina chain reached its `mhtml:` payload; `frame` and `subDocument` pull
#: whole documents in; `externalLinkPath` is Excel's linked workbook; an
#: external `image` is fetched to render, which is how a UNC path leaks an
#: NTLM hash to whoever serves it.
AUTOLOADING_RELATIONSHIPS = ("attachedTemplate", "oleObject", "frame", "subDocument",
                             "externalLinkPath", "image")

_RELATIONSHIP = re.compile(rb"<(?:[A-Za-z_][\w.-]*:)?Relationship\b([^>]*)>")
_ATTRIBUTE = re.compile(r"""([A-Za-z_][\w.:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')""")
_RELS_READ_LIMIT = 1048576
_RELATIONSHIPS_KEPT = 256


def external_relationships(staged: list[dict[str, Any]]) -> dict[str, Any]:
    """Every external relationship in a document's `.rels` parts.

    Read with a pattern rather than an XML parser, which keeps an
    attacker-shaped XML document away from a parser here, and so it has to
    do itself what Word's parser would do before acting: decode character
    references (`Ext&#101;rnal` is `External` to Word), accept either quote,
    accept a namespace prefix on the element, and honour a UTF-16 byte order
    mark. Each of those was a way past the first version of this sketch.

    Hyperlinks are counted and not listed: one in a document is ordinary,
    and a rule that reported them would fire on every document with a link.
    """
    out: dict[str, Any] = {"external": [], "hyperlinks": 0, "truncated": False}
    for member in staged:
        if not str(member.get("inside", "")).lower().endswith(".rels"):
            continue
        try:
            with open(member["path"], "rb") as handle:  # binary API
                raw = handle.read(_RELS_READ_LIMIT)
        except OSError:
            continue
        for found in _RELATIONSHIP.finditer(_as_utf8(raw)):
            attributes = {}
            for name, double, single in _ATTRIBUTE.findall(
                    found.group(1).decode("utf-8", "replace")):
                # Exact names. `foo:TargetMode` is a different attribute from
                # `TargetMode` to Word, so stripping the prefix would only
                # invent external relationships that Word treats as internal.
                attributes[name] = html.unescape(
                    double if double or not single else single)
            if attributes.get("TargetMode") != "External":
                continue
            kind = attributes.get("Type", "").rstrip("/").rsplit("/", 1)[-1]
            if kind == "hyperlink":
                out["hyperlinks"] += 1
                continue
            if len(out["external"]) >= _RELATIONSHIPS_KEPT:
                out["truncated"] = True
                continue
            target = attributes.get("Target", "")
            out["external"].append({
                "type": _display(kind or "unknown"),
                "target": _display(target),
                "scheme": _target_scheme(target),
                "part": _inside(str(member["inside"])),
                "autoloads": kind in AUTOLOADING_RELATIONSHIPS,
            })
    return out


#: Applications that, named as a DDE server, mean the field runs a command.
#: A DDE field that links a document to a range in a workbook names `Excel`;
#: one that names a command interpreter has no reading but the one the 2017
#: DDE campaigns gave it.
DDE_COMMAND_SERVERS = ("cmd", "powershell", "pwsh", "mshta", "wscript", "cscript",
                       "rundll32", "regsvr32", "msiexec", "certutil", "bitsadmin",
                       "msdt", "conhost", "forfiles", "wmic", "schtasks")
_DDE_FIELDS = ("DDE", "DDEAUTO")
_PREFIX = rb"(?:[A-Za-z_][\w.-]*:)?"
#: One pass over a part, in document order. Each alternative is one thing a
#: field is made of: the marks that open, divide and close a complex field,
#: the pieces of its instruction, the runs of its cached result, a simple
#: field, and Excel's DDE link. The self-closing forms come first so an empty
#: element cannot swallow everything up to the next one's closing tag.
_FIELD_TOKEN = re.compile(
    rb"<" + _PREFIX + rb"fldChar\b(?P<char>[^>]*)>"
    rb"|<" + _PREFIX + rb"instrText\b[^>]*/>"
    rb"|<" + _PREFIX + rb"instrText\b[^>]*>(?P<instr>.*?)</" + _PREFIX + rb"instrText\s*>"
    rb"|<" + _PREFIX + rb"t\b[^>]*/>"
    rb"|<" + _PREFIX + rb"t\b[^>]*>(?P<text>.*?)</" + _PREFIX + rb"t\s*>"
    rb"|<" + _PREFIX + rb"fldSimple\b(?P<simple>[^>]*)>"
    rb"|<" + _PREFIX + rb"ddeLink\b(?P<dde>[^>]*)>",
    re.DOTALL)
_FIELD_READ_LIMIT = 8 * 1048576
_FIELDS_KEPT = 256


def _local_attributes(raw: bytes) -> dict[str, str]:
    """Attributes by local name, decoded the way Word decodes them.

    By local name, unlike `.rels`. There the attributes are unprefixed and a
    prefixed one is a different attribute; here they live in the
    WordprocessingML namespace under whatever prefix the author bound to it,
    and `w:` is a convention, not a requirement.
    """
    out = {}
    for name, double, single in _ATTRIBUTE.findall(raw.decode("utf-8", "replace")):
        out[name.rsplit(":", 1)[-1]] = html.unescape(
            double if double or not single else single)
    return out


def _field_words(instruction: str) -> list[str]:
    """A field instruction split as Word splits it: on spaces, quotes kept
    together, and the quotes themselves dropped."""
    return [double if double or not single else single
            for double, single in re.findall(r'"([^"]*)"|(\S+)', instruction)]


def _quote_result(words: list[str]) -> str | None:
    """What a `QUOTE` field of character codes evaluates to, or `None`.

    `{ QUOTE 68 68 69 }` is `DDE`. A field name built that way never appears
    in the instruction text at all, so reading the instruction alone sees a
    field with no name. Only the all-numeric form is evaluated; anything else
    falls back to the result Word cached when the document was saved.
    """
    if len(words) < 2 or words[0].upper() != "QUOTE":
        return None
    try:
        return "".join(chr(int(word)) for word in words[1:])
    except (ValueError, OverflowError):
        return None


def _command_server(server: str) -> str | None:
    """The interpreter a DDE server names, from this module's own list.

    Returned from the list rather than from the sample, so the finding says
    which interpreter without carrying the bytes that named it.
    """
    base = re.split(r"[\\/]+", server.strip().strip('"'))[-1].lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base if base in DDE_COMMAND_SERVERS else None


def dde_fields(staged: list[dict[str, Any]]) -> dict[str, Any]:
    """Every DDE field in a document, and every DDE link in a workbook.

    A DDE field asks Office to start an application and talk to it. Word
    updates a `DDEAUTO` field when the document opens; Excel does the same
    for a `ddeLink`. Both ask first, and both were used in 2017 to run
    `cmd.exe` from a document with no macros in it.

    Every part is read, not only `word/document.xml`. OPC finds the main
    document through a relationship, so its name is the author's choice, and
    a rule that read one name would be a rule about filenames.

    A complex field's instruction is the concatenation of every `instrText`
    between its opening and dividing marks, because Word builds it that way
    and splitting `DDE` and `AUTO` across two runs is the first thing an
    author tries. A nested field contributes its value, as it does in Word:
    a numeric `QUOTE` evaluated here, anything else its cached result.
    """
    out: dict[str, Any] = {"fields": [], "truncated": False, "partial_parts": 0}
    for member in staged:
        inside = str(member.get("inside", ""))
        if inside.lower().endswith(".rels"):
            continue
        try:
            with open(member["path"], "rb") as handle:  # binary API
                raw = handle.read(_FIELD_READ_LIMIT + 1)
        except OSError:
            continue
        if len(raw) > _FIELD_READ_LIMIT:
            raw = raw[:_FIELD_READ_LIMIT]
            out["partial_parts"] += 1
        text = _as_utf8(raw)
        if b"instr" not in text and b"ddeLink" not in text:
            continue

        found: list[tuple[str, str, str]] = []
        #: Open complex fields, innermost last: [instruction, result, state].
        stack: list[list[str]] = []
        for token in _FIELD_TOKEN.finditer(text):
            if token.group("char") is not None:
                kind = _local_attributes(token.group("char")).get("fldCharType")
                if kind == "begin":
                    stack.append(["", "", "instr"])
                elif kind == "separate" and stack:
                    stack[-1][2] = "result"
                elif kind == "end" and stack:
                    instruction, result, _ = stack.pop()
                    words = _field_words(instruction)
                    if words:
                        found.append(("field", words[0], " ".join(words[1:2])))
                    value = _quote_result(words)
                    if stack and stack[-1][2] == "instr":
                        stack[-1][0] += value if value is not None else result
            elif token.group("instr") is not None:
                if stack and stack[-1][2] == "instr":
                    stack[-1][0] += html.unescape(token.group("instr").decode("utf-8", "replace"))
            elif token.group("text") is not None:
                if stack and stack[-1][2] == "result":
                    stack[-1][1] += html.unescape(token.group("text").decode("utf-8", "replace"))
            elif token.group("simple") is not None:
                words = _field_words(_local_attributes(token.group("simple")).get("instr", ""))
                if words:
                    found.append(("field", words[0], " ".join(words[1:2])))
            elif token.group("dde") is not None:
                attributes = _local_attributes(token.group("dde"))
                found.append(("link", "ddeLink", attributes.get("ddeService", "")))

        for kind, name, server in found:
            if kind == "field" and name.upper() not in _DDE_FIELDS:
                continue
            if len(out["fields"]) >= _FIELDS_KEPT:
                out["truncated"] = True
                continue
            out["fields"].append({
                "field": "ddeLink" if kind == "link" else name.upper(),
                "server": _display(server),
                "command": _command_server(server),
                "part": _inside(inside),
            })
    return out


def _as_utf8(raw: bytes) -> bytes:
    """`.rels` as UTF-8 bytes, honouring a UTF-16 byte order mark.

    XML may be UTF-16, and a pattern written for UTF-8 sees nothing in it but
    alternate NUL bytes, which is the cheapest evasion there is.
    """
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace").encode("utf-8")
    return raw


def _target_scheme(target: str) -> str:
    """What kind of place the target is, which is most of what it means.

    A UNC path or a `file:` URL makes Windows authenticate to whoever serves
    it, so an external image pointing at one leaks a hash with no click.
    """
    lowered = target.strip().lower()
    if lowered.startswith("\\\\") or lowered.startswith("//"):
        return "unc"
    for scheme in ("https", "http", "file", "mhtml", "ftp", "ms-msdt", "search-ms"):
        if lowered.startswith(scheme + ":"):
            return scheme
    return "other"


def _member_names(entries: list[dict[str, Any]]) -> list[str]:
    return [str(entry.get("name") or "").replace("\\", "/").lower()
            for entry in entries]


def _container_kind(entries: list[dict[str, Any]]) -> str | None:
    """What this ZIP actually is, or `None` when it is just a ZIP.

    Read from member names, which is the only place the answer lives: the
    magic number of a DOCX, a JAR, an APK and a backup are the same four
    bytes.
    """
    names = _member_names(entries)
    if OOXML_MARKER in names:
        return "ooxml"
    if JAR_MARKER in names:
        return "jar"
    return None


def _has_macro_project(entries: list[dict[str, Any]]) -> bool:
    return any(name.rsplit("/", 1)[-1] == MACRO_MEMBER
               for name in _member_names(entries))


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
