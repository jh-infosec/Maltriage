"""
OLE2 compound files: the container behind `.doc`, `.xls`, `.ppt`, `.msg`,
`.msi`, and the `vbaProject.bin` inside every macro-enabled OOXML document.

A compound file is a small FAT file system in one file. A header names the
sectors that hold the allocation table; the table chains sectors into
streams; one of those streams is a directory of 128-byte entries arranged as
a red-black tree per storage. Small streams live in a second, smaller file
system inside a stream of the first. Everything a reader needs is a number
the file supplies, and every one of them is a way to make a reader loop,
allocate, or read somewhere it should not.

So this module parses with `struct` over a read-only mapping, like the ELF
extractor, and trusts nothing it reads:

  * The allocation table is never built. A header can claim a billion FAT
    sectors, and a table held as Python integers costs about thirty times the
    file. Each entry is read from the mapping when a chain needs it, so memory
    tracks what is walked, not what is claimed.
  * Every chain is walked with a visited set, and every walk spends from one
    budget sized from the file, not from the header. A valid file uses each
    sector once, so a budget of the sectors that exist (plus slack) bounds
    the whole parse however the chains are wired.
  * The directory tree is walked with a visited set and a depth limit. A
    sibling pointer back to an ancestor is a cycle, and reaching one entry
    twice is reported, not followed.

What this reads in v0.5.19 is structure: which streams exist, where, and
how big they claim to be. It does not read stream content. The VBA project
is detected by its storages and streams, as OOXML's is by its member name;
reading the source out of it is the next release, and it will use the chain
walker here.
"""

from __future__ import annotations

import logging
import mmap
import struct
from pathlib import Path
from typing import Any

from .base import RandomAccessExtractor, safe_text
from .config import config_int
from .models import mk_finding

log = logging.getLogger(__name__)

OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")

MAXREGSECT = 0xFFFFFFFA
DIFSECT = 0xFFFFFFFC
FATSECT = 0xFFFFFFFD
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
NOSTREAM = 0xFFFFFFFF

TYPE_STORAGE, TYPE_STREAM, TYPE_ROOT = 1, 2, 5

_HEADER = struct.Struct("<8s16sHHHHH6sIIIIIIIII")
_ENTRY = struct.Struct("<64sHBBIII16sIQQIQ")
_DIRECTORY_ENTRY_SIZE = 128
_MINI_SECTOR_SIZE = 64
_MAX_DEPTH = 64
_PROBLEMS_KEPT = 50

#: Root class ids of a Windows Installer package and patch. An MSI is a
#: compound file whose stream names are encoded, so its streams say nothing readable about
#: what it is and the class identifier is the only honest way to tell.
_MSI_CLSIDS = (
    bytes.fromhex("8410 0c00 0000 0000 c000 0000 0000 0046".replace(" ", "")),
    bytes.fromhex("8610 0c00 0000 0000 c000 0000 0000 0046".replace(" ", "")),
)


class OleFormatError(ValueError):
    """The file is not a compound file this reader can address at all."""


class _Budget:
    """Sector visits left for the whole parse."""

    def __init__(self, sectors: int):
        self.left = sectors
        self.spent_out = False

    def take(self) -> bool:
        if self.left <= 0:
            self.spent_out = True
            return False
        self.left -= 1
        return True


class CompoundFile:
    """A compound file addressed through a mapping, read only on demand."""

    def __init__(self, data, max_entries: int):
        self.data = data
        self.size = len(data)
        self.problems: list[str] = []
        if self.size < 512 or bytes(data[:8]) != OLE_MAGIC:
            raise OleFormatError("not a compound file: the signature is wrong")

        (_, _, self.minor, self.major, byte_order, sector_shift, mini_shift, _,
         self.dir_sectors, self.fat_sectors, self.first_dir, _,
         self.mini_cutoff, self.first_minifat, self.minifat_sectors,
         self.first_difat, self.difat_sectors) = _HEADER.unpack_from(data, 0)
        if byte_order != 0xFFFE:
            raise OleFormatError(f"byte order mark {byte_order:#06x} is not 0xfffe")
        if sector_shift not in (9, 12):
            raise OleFormatError(f"sector shift {sector_shift} is neither 9 nor 12")
        if self.major not in (3, 4):
            self.problems.append(f"header: major version {self.major} is neither 3 nor 4")
        elif (self.major == 3) != (sector_shift == 9):
            # Office never writes this and most readers accept it. Noted
            # because a mismatch is a file built by hand.
            self.problems.append(
                f"header: version {self.major} with {1 << sector_shift} byte sectors")
        if mini_shift != 6:
            self.problems.append(f"header: mini sector shift {mini_shift} is not 6")
        if self.mini_cutoff != 4096:
            self.problems.append(f"header: mini stream cutoff {self.mini_cutoff} is not 4096")

        self.sector_size = 1 << sector_shift
        self.per_sector = self.sector_size // 4
        # Sectors that exist, from the file's size rather than any header
        # field. A trailing partial sector is still addressable, so it counts.
        self.sector_count = max(0, -(-(self.size - self.sector_size) // self.sector_size))
        # Every regular sector once, and every mini sector once: a valid file
        # walks no more than that however its chains are arranged.
        self.budget = _Budget(self.sector_count * (2 + self.sector_size // _MINI_SECTOR_SIZE)
                              + 4096)
        self.max_entries = max_entries
        self._fat = self._fat_sector_ids()

    # sectors and chains

    def _offset(self, sid: int) -> int:
        return (sid + 1) * self.sector_size

    def _u32(self, offset: int) -> int | None:
        if offset < 0 or offset + 4 > self.size:
            return None
        return struct.unpack_from("<I", self.data, offset)[0]

    def _fat_sector_ids(self) -> list[int]:
        """Where the allocation table lives, from the header and DIFAT chain.

        Capped at the number of FAT sectors the file's size could need, so a
        header claiming a billion of them costs nothing.
        """
        needed = -(-self.sector_count // self.per_sector) + 1
        wanted = min(self.fat_sectors, needed)
        ids = [sid for sid in struct.unpack_from("<109I", self.data, 76)[:min(wanted, 109)]]
        sid, seen = self.first_difat, set()
        while len(ids) < wanted and sid < MAXREGSECT:
            if sid in seen or sid >= self.sector_count or not self.budget.take():
                self.problems.append("difat: the chain loops or leaves the file")
                break
            seen.add(sid)
            base = self._offset(sid)
            for index in range(self.per_sector - 1):
                if len(ids) >= wanted:
                    break
                value = self._u32(base + index * 4)
                if value is None:
                    break
                ids.append(value)
            sid = self._u32(base + (self.per_sector - 1) * 4)
            if sid is None:
                break
        if self.fat_sectors > needed:
            self.problems.append(
                f"header: claims {self.fat_sectors} FAT sectors and the file could "
                f"use {needed}")
        return ids

    def _next(self, sid: int, table: list[int], per: int) -> int | None:
        index, slot = divmod(sid, per)
        if index >= len(table) or table[index] >= self.sector_count:
            return None
        return self._u32(self._offset(table[index]) + slot * 4)

    def chain(self, start: int, label: str, limit: int | None = None) -> list[int]:
        """Sector ids of one regular chain, in order, or as much as is sane.

        Stops at end of chain, at a sector outside the file, at a loop, at
        `limit`, or when the parse budget is spent, and says which.
        """
        return self._walk(start, label, limit, self.sector_count,
                          lambda sid: self._next(sid, self._fat, self.per_sector))

    def _walk(self, start, label, limit, count, step) -> list[int]:
        out: list[int] = []
        seen: set[int] = set()
        sid = start
        while sid != ENDOFCHAIN:
            if limit is not None and len(out) >= limit:
                break
            if sid == FREESECT and not out:
                break  # an empty stream: nothing allocated
            if sid >= count:
                self.problems.append(f"{label}: the chain points past the end at {sid:#x}")
                break
            if sid in seen:
                self.problems.append(f"{label}: the chain loops")
                break
            if not self.budget.take():
                break
            seen.add(sid)
            out.append(sid)
            following = step(sid)
            if following is None:
                self.problems.append(f"{label}: the allocation table does not cover it")
                break
            sid = following
        return out

    # directory

    def entries(self) -> list[dict[str, Any]]:
        sectors = self.chain(self.first_dir, "directory")
        per = self.sector_size // _DIRECTORY_ENTRY_SIZE
        out: list[dict[str, Any]] = []
        for sid in sectors:
            base = self._offset(sid)
            for slot in range(per):
                if len(out) >= self.max_entries:
                    self.problems.append(
                        f"directory: more than {self.max_entries} entries; the rest "
                        "were not read")
                    return out
                offset = base + slot * _DIRECTORY_ENTRY_SIZE
                if offset + _DIRECTORY_ENTRY_SIZE > self.size:
                    return out
                (raw_name, name_length, kind, _, left, right, child, clsid, _,
                 _, _, start, size) = _ENTRY.unpack_from(self.data, offset)
                if self.major == 3:
                    # The high half is undefined in version 3 and real files
                    # carry garbage there, so reading it would invent sizes.
                    size &= 0xFFFFFFFF
                length = max(0, min(name_length, 64) - 2)
                name = raw_name[:length - length % 2].decode("utf-16-le", "replace")
                out.append({"name": name, "type": kind, "left": left, "right": right,
                            "child": child, "clsid": clsid, "start": start, "size": size})
        return out


def _tree(entries: list[dict[str, Any]], problems: list[str]) -> list[tuple[str, int]]:
    """(path, entry index) for every entry reachable from the root.

    Iterative, with a visited set and a depth limit, because every pointer is
    a field in the file and a recursive walk is a stack overflow on request.
    """
    found: list[tuple[str, int]] = []
    if not entries or entries[0]["type"] != TYPE_ROOT:
        problems.append("directory: the first entry is not the root")
        return found
    visited = {0}
    # (sibling-tree node, path of the storage it is in, depth)
    pending = [(entries[0]["child"], "", 1)]
    while pending:
        node, parent, depth = pending.pop()
        if node == NOSTREAM:
            continue
        if node >= len(entries):
            problems.append("directory: a pointer leaves the directory")
            continue
        if node in visited:
            problems.append("directory: an entry is reachable twice")
            continue
        if depth > _MAX_DEPTH:
            problems.append(f"directory: storages nested deeper than {_MAX_DEPTH}")
            continue
        visited.add(node)
        entry = entries[node]
        path = f"{parent}/{entry['name']}" if parent else entry["name"]
        found.append((path, node))
        pending.append((entry["left"], parent, depth))
        pending.append((entry["right"], parent, depth))
        if entry["type"] == TYPE_STORAGE:
            pending.append((entry["child"], path, depth + 1))
    return found


def _kind(root: dict[str, Any], top: set[str]) -> str | None:
    """What the compound file is, from its root-level names and class id.

    Names compare without case, as the format specifies.
    """
    if "encryptedpackage" in top:
        # An encrypted OOXML document: the real file is the encrypted stream.
        return "encrypted_ooxml"
    if "worddocument" in top:
        return "word"
    if "workbook" in top or "book" in top:
        return "excel"
    if "powerpoint document" in top:
        return "powerpoint"
    if "__properties_version1.0" in top:
        return "outlook"
    if root.get("clsid") in _MSI_CLSIDS:
        return "msi"
    if "vba" in top and "project" in top:
        return "vba_project"
    return None


def describe(data, config: dict[str, Any] | None = None) -> dict[str, Any]:
    """The structure of a compound file held in `data`, which may be a map."""
    config = config or {}
    max_entries = config_int(config, "ole_max_directory_entries", 8192)
    max_listed = config_int(config, "ole_max_listed_streams", 256)
    compound = CompoundFile(data, max_entries)
    entries = compound.entries()
    problems = compound.problems
    reachable = _tree(entries, problems)

    root = entries[0] if entries else {}
    top = {entries[i]["name"].lower() for path, i in reachable if "/" not in path}
    out: dict[str, Any] = {
        "version": compound.major,
        "sector_size": compound.sector_size,
        "kind": _kind(root, top),
        "streams": [],
        "stream_count": 0,
        "storage_count": 0,
        "unreachable": 0,
        "vba_project": None,
        "packages": 0,
        "encrypted": "encryptedpackage" in top and "encryptioninfo" in top,
        "truncated": False,
        "parse_errors": problems,
    }

    mini_stream = (compound.chain(root.get("start", ENDOFCHAIN), "mini stream")
                   if root else [])
    minifat = compound.chain(compound.first_minifat, "mini FAT")
    mini_count = len(mini_stream) * (compound.sector_size // _MINI_SECTOR_SIZE)

    def mini_next(sid: int) -> int | None:
        return compound._next(sid, minifat, compound.per_sector)

    children: dict[str, set[str]] = {}
    visited = {0}
    for path, index in reachable:
        visited.add(index)
        entry = entries[index]
        parent, _, leaf = path.rpartition("/")
        children.setdefault(parent.lower(), set()).add(leaf.lower())
        if entry["type"] == TYPE_STORAGE:
            out["storage_count"] += 1
            continue
        if entry["type"] != TYPE_STREAM:
            continue
        out["stream_count"] += 1
        if entry["name"] == "\x01Ole10Native":
            out["packages"] += 1

        # The claim against the allocation. Walking the chain is what any
        # later read of the stream would do, so a stream whose chain is
        # shorter than its claimed size is found here rather than then.
        size = entry["size"]
        label = f"stream {safe_text(path, 128)!r}"
        if size < compound.mini_cutoff:
            unit = _MINI_SECTOR_SIZE
            held = len(compound._walk(entry["start"], label, -(-size // unit),
                                      mini_count, mini_next))
        else:
            unit = compound.sector_size
            held = len(compound.chain(entry["start"], label, -(-size // unit)))
        if held * unit < size:
            problems.append(f"{label}: claims {size} bytes and its chain holds "
                            f"{held * unit}")

        if len(out["streams"]) < max_listed:
            out["streams"].append({"path": safe_text(path, 256), "size": size})
        else:
            out["truncated"] = True

    for storage, names in children.items():
        if storage.rsplit("/", 1)[-1] == "vba" and {"dir", "_vba_project"} <= names:
            # The location as the file spells it, for the finding.
            for path, _ in reachable:
                if path.lower() == storage:
                    out["vba_project"] = safe_text(path, 256)
                    break

    out["unreachable"] = sum(1 for index, entry in enumerate(entries)
                             if index not in visited
                             and entry["type"] in (TYPE_STORAGE, TYPE_STREAM))
    if out["encrypted"]:
        # Recorded as analysis that came back short, so the envelope says
        # `incomplete` and a clean result is not read as a clean document.
        problems.append("content: the document is encrypted, so nothing inside "
                        "it was examined")
    if compound.budget.spent_out:
        problems.append("budget: the chains visit more sectors than the file has, "
                        "so the walk stopped")
    if out["truncated"]:
        problems.append(f"streams: more than {max_listed} streams; the list is partial")
    if len(problems) > _PROBLEMS_KEPT:
        # One line per broken stream is right for a damaged file and wrong
        # for a file built to have eight thousand of them.
        extra = len(problems) - _PROBLEMS_KEPT
        problems[:] = problems[:_PROBLEMS_KEPT] + [f"and {extra} more problems like these"]
    return out


class OleExtractor(RandomAccessExtractor):
    """Compound file structure, parsed with `struct` and nothing else.

    No dependency, for the ELF extractor's reason: the format is a handful of
    fixed records, and the hostility is in the numbers, which a bounded
    reader handles as well as a library would. `olefile` is the reference
    this was checked against, and it is not imported.
    """

    name = "ole"

    def applies_to(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> bool:
        return ctx.get("family") == "ole"

    def parse(self, path: Path, ctx: dict[str, Any],
              config: dict[str, Any]) -> dict[str, Any]:
        with path.open("rb") as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
                return describe(data, config)

    def findings(self, data: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        kind = data.get("kind")
        document = kind in ("word", "excel", "powerpoint")

        if data.get("vba_project") and document:
            # `low`, for the reason `ooxml_macros` is: a macro-enabled
            # workbook is ordinary in most organisations. Not reported for a
            # bare `vbaProject.bin`, which is a VBA project by definition and
            # whose container already said so.
            out.append(mk_finding(
                self.name, "ole_macros",
                f"the {kind} document carries a VBA project at {data['vba_project']}",
                "low", discriminator=kind))

        packages = data.get("packages") or 0
        if packages:
            # An `Ole10Native` stream is Packager's: it carries an arbitrary
            # file, with a name and a path, shown as an icon in the document.
            # A double click runs it. The classic way to put an executable or
            # a script inside a document with no macro at all.
            out.append(mk_finding(
                self.name, "ole_embedded_package",
                f"{packages} embedded package object(s): a file of any kind, "
                "shown as an icon and run by opening it", "low",
                evidence=[{"name": "count", "value": packages}]))

        if data.get("encrypted"):
            # Not suspicious by itself, and not nothing: an encrypted document
            # is one this tool, and every scanner, cannot see inside, which is
            # why a password in the body of an email is a delivery technique.
            out.append(mk_finding(
                self.name, "ole_encrypted",
                "the document is encrypted, so its content was not examined", "low"))
        return out
