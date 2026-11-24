"""
Windows shortcuts: what a `.lnk` would start, and with what command line.

Since Office began blocking macros in files from the internet in 2022, a
shortcut has been one of the commonest first stages: an attachment or an
archive member that looks like a document and starts
`powershell -w hidden -enc ...` when opened. Until this module a shortcut
was `unrecognised_format` and nothing else.

A shortcut is a small binary structure (MS-SHLLINK): a 76 byte header, then
optionally a list of shell items naming the target, a `LinkInfo` block with
its path, five counted strings (description, relative path, working
directory, arguments, icon location), and a chain of extra data blocks, one
of which can hold the target again as a path with environment variables in
it. A shortcut can name its target in three places at once, and they need
not agree. Every one present is read and every one is reported, because a
reader that trusted one would be a reader told which to trust.

What it does is the target and the arguments, read as one command line. The
script reader from v0.7.2 already knows what a dropper looks like in one, so
the command line is handed to it rather than given rules of its own, and a
shortcut that runs `powershell -enc` reaches the gate for the same reason a
batch file does. Whitespace in the command line is collapsed first: padding
the arguments with spaces or line breaks is the documented way to push the
real command out of the Properties dialog, and it must not also push the
parts of a shape out of each other's reach.

The arguments never reach a report, for the reason a script's text does not.
Paths do, through `safe_text`: a target, a working directory and an icon
location are what an analyst pivots on, the way a member name is.
"""

from __future__ import annotations

import re
import struct
import uuid
from typing import Any

from . import scripts
from .base import StreamExtractor, safe_text
from .config import config_int
from .models import mk_finding

HEADER_SIZE = 0x4C
LINK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
MAGIC = struct.pack("<I", HEADER_SIZE) + LINK_CLSID

FLAG_NAMES = (
    "HasLinkTargetIDList", "HasLinkInfo", "HasName", "HasRelativePath",
    "HasWorkingDir", "HasArguments", "HasIconLocation", "IsUnicode",
    "ForceNoLinkInfo", "HasExpString", "RunInSeparateProcess", "Unused1",
    "HasDarwinID", "RunAsUser", "HasExpIcon", "NoPidlAlias", "Unused2",
    "RunWithShimLayer", "ForceNoLinkTrack", "EnableTargetMetadata",
    "DisableLinkPathTracking", "DisableKnownFolderTracking",
    "DisableKnownFolderAlias", "AllowLinkToLink", "UnaliasOnSave",
    "PreferEnvironmentPath", "KeepLocalIDListForUNCTarget",
)
HAS_ID_LIST, HAS_LINK_INFO, IS_UNICODE = 0x1, 0x2, 0x80
#: The five strings, in the order the format stores them.
STRINGS = (("name", 0x4), ("relative_path", 0x8), ("working_dir", 0x10),
           ("arguments", 0x20), ("icon_location", 0x40))

SHOW_COMMANDS = {1: "normal", 3: "maximised", 7: "minimised"}

EXTRA_BLOCKS = {
    0xA0000001: "environment", 0xA0000002: "console", 0xA0000003: "tracker",
    0xA0000004: "console_codepage", 0xA0000005: "special_folder",
    0xA0000006: "darwin", 0xA0000007: "icon_environment", 0xA0000008: "shim",
    0xA0000009: "property_store", 0xA000000B: "known_folder",
    0xA000000C: "vista_id_list",
}
ENVIRONMENT, TRACKER, ICON_ENVIRONMENT = 0xA0000001, 0xA0000003, 0xA0000007

_MAX_ITEMS = 256
_MAX_BLOCKS = 64
_PATH_LIMIT = 520

#: Programs that run what they are given. Reported as capability, at `low`:
#: every Start Menu has a PowerShell shortcut.
INTERPRETERS = frozenset({
    "powershell.exe", "pwsh.exe", "powershell_ise.exe", "cmd.exe", "mshta.exe",
    "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe",
    "certutil.exe", "bitsadmin.exe", "forfiles.exe", "conhost.exe", "wmic.exe",
    "schtasks.exe", "hh.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
    "regsvcs.exe", "cmstp.exe", "odbcconf.exe", "pcalua.exe", "curl.exe",
    "bash.exe", "wsl.exe", "msxsl.exe", "scriptrunner.exe",
})

#: Icons that make a shortcut look like a document: a document's own
#: extension, or a program that opens documents. On a shortcut that starts
#: an interpreter, borrowing one is the disguise.
DOCUMENT_ICON_EXTENSIONS = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".txt",
    ".jpg", ".jpeg", ".png", ".gif", ".htm", ".html", ".zip",
})
DOCUMENT_ICON_PROGRAMS = frozenset({
    "msedge.exe", "acrord32.exe", "acrobat.exe", "winword.exe", "excel.exe",
    "powerpnt.exe", "wordpad.exe", "notepad.exe", "chrome.exe", "firefox.exe",
    "iexplore.exe", "mspaint.exe",
})

#: A run of whitespace this long in the arguments is padding: nobody types
#: it, and the Properties dialog shows the first 260 characters of a target.
PADDING_RUN = 64
_WHITESPACE_RUN = re.compile(r"[ \t\r\n\v\f]+")
_LINE_BREAK = re.compile(r"[\r\n\v\f]")


def _u16(data: bytes, at: int) -> int:
    return struct.unpack_from("<H", data, at)[0]


def _u32(data: bytes, at: int) -> int:
    return struct.unpack_from("<I", data, at)[0]


def _cstring(data: bytes, at: int, end: int | None = None) -> str:
    end = len(data) if end is None else min(end, len(data))
    if at >= end:
        return ""
    stop = data.find(b"\0", at, end)
    return data[at:end if stop < 0 else stop].decode("cp1252", "replace")


def _wstring(data: bytes, at: int, end: int | None = None) -> str:
    """A NUL-terminated UTF-16 string, found on a two byte boundary."""
    end = len(data) if end is None else min(end, len(data))
    stop = at
    while stop + 1 < end and data[stop:stop + 2] != b"\0\0":
        stop += 2
    return data[at:stop].decode("utf-16-le", "replace")


def _long_name(item: bytes, at: int) -> str | None:
    """The long name in a file entry's 0xBEEF0004 extension block.

    Its position depends on the block's version (libfwsi, and pylnk3 reads
    it the same way). The primary name can be an 8.3 name, `POWERS~1.EXE`
    for `powershell.exe`, which is useless for knowing what runs, so the
    long name is preferred whenever it reads as a name. It is not checked
    against the primary name: the two can be made to disagree, and the
    long one is the one the shell shows and resolves.
    """
    if at + 8 > len(item) or _u32(item, at + 4) != 0xBEEF0004:
        return None
    size, version = _u16(item, at), _u16(item, at + 2)
    end = min(at + size, len(item))
    if version < 3:
        return None
    offset = at + (38 if version >= 7 else 20)
    offset += 4 if version >= 9 else 0
    offset += 4 if version >= 8 else 0
    name = _wstring(item, offset, end)
    if name and name.isprintable() and "\ufffd" not in name:
        return name
    return None


#: Root folders whose place in a path is known. Any other root is written
#: the way the shell writes a parsing name, `::{GUID}`.
ROOT_FOLDERS = {
    "20d04fe0-3aea-1069-a2d8-08002b30309d": "",                          # This PC
    "59031a47-3f72-44a7-89c5-5595fe6b30ee": "%USERPROFILE%",             # the user's folder
    "450d8fba-ad25-11d0-98a8-0800361b1103": "%USERPROFILE%\\Documents",  # Documents
    "871c5380-42a0-1069-a2ea-08002b30309d": "",                          # Internet
    "208d2c60-3aea-1069-a2d7-08002b30309d": "",                          # Network
}
_EXTENSION = struct.pack("<I", 0xBEEF0004)
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]{1,31}:\S")


def _guid(raw: bytes) -> str:
    return str(uuid.UUID(bytes_le=raw)) if len(raw) == 16 else ""


def _entry_name(entry: bytes, outer: bytes) -> str:
    """A file entry's name: the long one if it can be found, else the primary.

    `entry` is the file entry item; `outer` is the item that carries its
    extension block, which is the same item except inside a delegate. The
    block is looked for where the outer item's last two bytes point, then
    just after the padded primary name, then by its signature.
    """
    kind = entry[2]
    if kind & 0x04:
        primary = _wstring(entry, 14)
        name_end = 14 + 2 * len(primary) + 2
    else:
        primary = _cstring(entry, 14)
        name_end = 14 + len(primary.encode("cp1252", "replace")) + 1
    name_end += name_end & 1
    pointer = _u16(outer, len(outer) - 2) if len(outer) >= 4 else 0
    found = outer.find(_EXTENSION)
    return ((_long_name(outer, pointer) if 14 <= pointer < len(outer) - 2 else None)
            or _long_name(entry, name_end)
            or (_long_name(outer, found - 4) if found >= 4 else None)
            or primary)


def _uri(item: bytes) -> str | None:
    """The URI in a URI item (class 0x61).

    It follows a four byte data size and that many bytes of data, in UTF-16
    when the item's flags say so. v0.7.4 read the size as two bytes and the
    URI from offset 6, after libfwsi; on 588 real items the size was zero and
    the URI was at 8 in every one, and only the search below had found them. Accepted only if it reads as a URI; otherwise the
    item is searched for one, and if there is none it was not read.
    """
    if len(item) < 8:
        return None
    flags, data_size = item[3], _u32(item, 4)
    at = 8 + data_size
    wide = bool(flags & 0x80)
    candidate = _wstring(item, at) if wide else _cstring(item, at)
    if _SCHEME.match(candidate or ""):
        return candidate
    for text in (item.decode("utf-16-le", "replace"), item[1:].decode("utf-16-le", "replace"),
                 item.decode("cp1252", "replace")):
        found = re.search(r"[A-Za-z][A-Za-z0-9+.-]{1,31}:[^\x00\ufffd]+", text)
        if found and _SCHEME.match(found.group()):
            return found.group()
    return None


def _id_list_path(idl: bytes, problems: list[str],
                  unread: list[str] | None = None) -> str | None:
    """The path a list of shell items spells, as far as it can be read.

    Read: root folders this module knows, volumes with a name (`C:\\`),
    file entries, the delegate items Explorer wraps file entries in under
    the user's folder (`CFSF`), and URI items. Anything else (a control
    panel item, a portable device, a volume known only by its GUID) ends
    what the list can say. Its class goes into `unread`, and the caller
    decides whether that matters: it does not when another part of the
    shortcut names the target.
    """
    unread = [] if unread is None else unread
    parts: list[str] = []
    at = items = 0
    while at + 2 <= len(idl):
        size = _u16(idl, at)
        if size == 0:
            break
        items += 1
        if size < 3 or at + size > len(idl) or items > _MAX_ITEMS:
            problems.append("lnk: the shell item list is malformed; the target it names is partial")
            break
        item = idl[at:at + size]
        kind = item[2]
        if kind in (0x1E, 0x1F) and size >= 20:
            guid = _guid(item[4:20])
            root = ROOT_FOLDERS.get(guid, "::{" + guid.upper() + "}")
            parts = [root] if root else []
        elif kind & 0x70 == 0x20 and kind & 0x01:
            parts.append(_cstring(item, 3, 23).rstrip("\\"))
        elif kind & 0x70 == 0x30 and size > 14:
            parts.append(_entry_name(item, item))
        elif kind == 0x74 and size > 14 and item[6:10] == b"CFSF":
            inner = item[10:10 + _u16(item, 10)]
            if len(inner) > 14 and inner[2] & 0x70 == 0x30:
                parts.append(_entry_name(inner, item))
            else:
                unread.append(f"{kind:02x}")
                break
        elif kind == 0x61:
            uri = _uri(item)
            if not uri:
                unread.append(f"{kind:02x}")
                break
            parts = [uri]
        else:
            unread.append(f"{kind:02x}")
            break
        at += size
    return "\\".join(parts) if parts else None


def _link_info(info: bytes, problems: list[str]) -> str | None:
    if len(info) < 0x1C:
        problems.append("lnk: the LinkInfo block is too short to read")
        return None
    header, flags = _u32(info, 4), _u32(info, 8)
    base_offset, network_offset, suffix_offset = _u32(info, 16), _u32(info, 20), _u32(info, 24)
    unicode = header >= 0x24 and len(info) >= 0x24
    suffix = _cstring(info, suffix_offset) if suffix_offset else ""
    if unicode and _u32(info, 32):
        suffix = _wstring(info, _u32(info, 32))
    if flags & 0x1:
        base = _cstring(info, base_offset) if base_offset else ""
        if unicode and _u32(info, 28):
            base = _wstring(info, _u32(info, 28))
        return base + suffix if base else None
    if flags & 0x2 and network_offset + 0x14 <= len(info):
        net_name = _cstring(info, network_offset + _u32(info, network_offset + 8))
        if net_name:
            return net_name.rstrip("\\") + ("\\" + suffix if suffix else "")
    return None


def parse(data: bytes) -> dict[str, Any]:
    """Everything the shortcut says, with the arguments kept apart.

    `arguments` is in the result for the caller to scan and must never be
    put in a report. Every offset and count the file supplies is checked
    against what was read.
    """
    problems: list[str] = []
    out: dict[str, Any] = {"problems": problems, "targets": {}, "extra_blocks": [],
                           "unread_items": []}
    if len(data) < HEADER_SIZE or data[:20] != MAGIC:
        problems.append("lnk: no shell link header")
        return out
    flags = _u32(data, 20)
    out["flags"] = [name for bit, name in enumerate(FLAG_NAMES) if flags >> bit & 1]
    show = _u32(data, 60)
    out["show_command"] = SHOW_COMMANDS.get(show, f"other ({show})")
    unicode = bool(flags & IS_UNICODE)
    at = HEADER_SIZE
    short = "lnk: the file ends inside a structure the header says is there"

    if flags & HAS_ID_LIST:
        if at + 2 > len(data):
            problems.append(short)
            return out
        size = _u16(data, at)
        if at + 2 + size > len(data):
            problems.append(short)
        target = _id_list_path(data[at + 2:at + 2 + size], problems, out["unread_items"])
        if target:
            out["targets"]["id_list"] = target
        at += 2 + size

    if flags & HAS_LINK_INFO:
        if at + 4 > len(data):
            problems.append(short)
            return out
        size = _u32(data, at)
        if size < 4 or at + size > len(data):
            problems.append(short)
            return out
        target = _link_info(data[at:at + size], problems)
        if target:
            out["targets"]["link_info"] = target
        at += size

    for name, bit in STRINGS:
        if not flags & bit:
            continue
        if at + 2 > len(data):
            problems.append(short)
            return out
        count = _u16(data, at)
        width = 2 if unicode else 1
        raw = data[at + 2:at + 2 + count * width]
        if len(raw) < count * width:
            problems.append(short)
        out[name] = raw.decode("utf-16-le" if unicode else "cp1252", "replace")
        at += 2 + count * width
        if at > len(data):
            return out

    blocks = 0
    while True:
        if at + 4 > len(data):
            problems.append("lnk: no terminal block; the file ends inside the extra data")
            break
        size = _u32(data, at)
        if size < 4:
            at += 4
            break
        blocks += 1
        if size < 8 or at + size > len(data) or blocks > _MAX_BLOCKS:
            problems.append("lnk: an extra data block is malformed; the rest were not read")
            break
        block = data[at:at + size]
        signature = _u32(block, 4)
        out["extra_blocks"].append(EXTRA_BLOCKS.get(signature, f"0x{signature:08x}"))
        if signature in (ENVIRONMENT, ICON_ENVIRONMENT) and size >= 0x314:
            path = _wstring(block, 268, 788) or _cstring(block, 8, 268)
            if path and signature == ENVIRONMENT:
                out["targets"]["environment"] = path
            elif path:
                out["icon_environment"] = path
        elif signature == TRACKER and size >= 0x60:
            out["machine_id"] = _cstring(block, 16, 32)
        at += size
    out["end"] = at
    # An item this reader does not spell out is a gap only when nothing
    # else in the shortcut names the target: the item list's own path then
    # stops short, or never starts. 588 of 1,290 shortcuts on one
    # machine were Recent entries for web documents, whose LinkInfo-less
    # item list ends in a URI item, and every one was "came back short" in
    # v0.7.3 although most had been read in full.
    if out["unread_items"] and not {"link_info", "environment"} & set(out["targets"]):
        problems.append(f"lnk: the shell item list ends in an item of class 0x{out['unread_items'][0]} "
                        "that this reader does not spell out, and nothing else in the "
                        "shortcut names the target")
    return out


def basename(path: str) -> str:
    return re.split(r"[\\/]", path.strip().strip('"'))[-1].lower()


def command_lines(parsed: dict[str, Any]) -> list[str]:
    """Each distinct target with the arguments, as one line each.

    Whitespace collapsed to one space, so padding hides nothing from the
    shapes. For a `cmd.exe` target its escape character is removed too:
    `p^o^w^e^r^s^h^e^l^l` is `powershell` to cmd, and should be to this.
    """
    arguments = parsed.get("arguments") or ""
    lines = []
    for target in dict.fromkeys(parsed.get("targets", {}).values()) or [""]:
        line = f"{target} {arguments}"
        if basename(target) == "cmd.exe":
            line = line.replace("^", "")
        lines.append(_WHITESPACE_RUN.sub(" ", line).strip())
    return lines


def assess(parsed: dict[str, Any]) -> dict[str, Any]:
    """What the shortcut does, said in names from this module's lists."""
    arguments = parsed.get("arguments") or ""
    shapes: list[str] = []
    execution: list[str] = []
    download: list[str] = []
    hidden = False
    for line in command_lines(parsed):
        found = scripts.scan(line)
        shapes += [s for s in found["shapes"] if s not in shapes]
        execution += [e for e in found["execution"] if e not in execution]
        download += [d for d in found["download"] if d not in download]
        hidden = hidden or found["hidden"]
    targets = parsed.get("targets", {})
    interpreters = sorted({basename(t) for t in targets.values()} & INTERPRETERS)
    runs = [len(m.group()) for m in _WHITESPACE_RUN.finditer(arguments)]
    icon = parsed.get("icon_location") or parsed.get("icon_environment") or ""
    icon_name = basename(icon) if icon else ""
    disguise = bool(interpreters) and bool(icon_name) and (
        any(icon_name.endswith(ext) for ext in DOCUMENT_ICON_EXTENSIONS)
        or icon_name in DOCUMENT_ICON_PROGRAMS)
    return {
        "shapes": shapes,
        "execution": execution,
        "download": download,
        "hidden": hidden,
        "interpreters": interpreters,
        "arguments_length": len(arguments),
        "longest_whitespace_run": max(runs, default=0),
        "line_breaks_in_arguments": bool(_LINE_BREAK.search(arguments)),
        "document_icon": icon_name if disguise else None,
    }


class LnkExtractor(StreamExtractor):
    """A shortcut, read from the one pass every stream extractor shares.

    Keeps at most `lnk_max_bytes` and counts the rest: a shortcut is a few
    kilobytes, and what follows its terminal block is not part of it. Data
    appended to a shortcut is how one carries its own payload, for a
    command line that reads the shortcut back and cuts the payload out.
    """

    name = "lnk"

    def applies_to(self, path, ctx, config) -> bool:
        return ctx.get("family") == "lnk"

    def begin(self, path, ctx, config) -> None:
        self._cap = config_int(config, "lnk_max_bytes", 1048576)
        self._buffer = bytearray()
        self._seen = 0

    def feed(self, chunk: bytes) -> None:
        self._seen += len(chunk)
        room = self._cap - len(self._buffer)
        if room > 0:
            self._buffer += chunk[:room]

    def finish(self, path, ctx, config) -> dict[str, Any]:
        parsed = parse(bytes(self._buffer))
        self._buffer = bytearray()
        problems = list(parsed.get("problems", []))
        if self._seen > self._cap:
            problems.append(f"lnk: read the first {self._cap} bytes of a longer file")
        data: dict[str, Any] = {
            "flags": parsed.get("flags", []),
            "show_command": parsed.get("show_command"),
            "targets": {k: safe_text(v, _PATH_LIMIT) for k, v in parsed.get("targets", {}).items()},
            "extra_blocks": parsed.get("extra_blocks", []),
            "unread_items": parsed.get("unread_items", []),
        }
        for key in ("relative_path", "working_dir", "icon_location", "icon_environment",
                    "machine_id"):
            if parsed.get(key):
                data[key] = safe_text(parsed[key], _PATH_LIMIT)
        # The description is free text the author wrote; whether there is
        # one is the observation, as with a script's comments.
        data["has_description"] = bool(parsed.get("name"))
        if "end" in parsed:
            data["appended_bytes"] = max(0, self._seen - parsed["end"])
        data.update(assess(parsed))
        if problems:
            data["parse_errors"] = problems
        return data

    def findings(self, data, config) -> list[dict[str, Any]]:
        out = []
        shapes = data.get("shapes") or []
        interpreters = data.get("interpreters") or []
        runs = ", ".join(interpreters) if interpreters else "its target"
        if shapes:
            # At the gate, for the reason a script with the same shape is:
            # each is a dropper's, and an ordinary shortcut does not take one.
            out.append(mk_finding(
                self.name, "lnk_dropper",
                f"a shortcut whose command line has the shape of a dropper: {', '.join(shapes)}",
                "medium",
                evidence=[{"name": "shapes", "value": shapes},
                          {"name": "interpreters", "value": interpreters}]))
        if interpreters:
            out.append(mk_finding(
                self.name, "lnk_interpreter_target",
                f"a shortcut that starts {runs}, which runs whatever it is given",
                "low", evidence=[{"name": "interpreters", "value": interpreters}]))
        if (data.get("longest_whitespace_run", 0) >= PADDING_RUN
                or data.get("line_breaks_in_arguments")):
            out.append(mk_finding(
                self.name, "lnk_padded_arguments",
                "a shortcut whose arguments are padded with whitespace or line breaks, "
                "which pushes the command out of what the Properties dialog shows",
                "low", evidence=[{"name": "longest_whitespace_run",
                                  "value": data.get("longest_whitespace_run", 0)},
                                 {"name": "arguments_length",
                                  "value": data.get("arguments_length", 0)}]))
        if data.get("document_icon"):
            out.append(mk_finding(
                self.name, "lnk_document_icon",
                f"a shortcut that starts {runs} wearing the icon of {data['document_icon']}",
                "low", evidence=[{"name": "icon", "value": data["document_icon"]}]))
        if data.get("hidden") or (interpreters and data.get("show_command") == "minimised"):
            out.append(mk_finding(
                self.name, "lnk_hidden_window",
                f"a shortcut that starts {runs} with no window, or minimised",
                "low"))
        if data.get("appended_bytes"):
            out.append(mk_finding(
                self.name, "lnk_appended_data",
                f"{data['appended_bytes']} byte(s) after the end of the shortcut, "
                "which nothing that reads a shortcut uses",
                "low", evidence=[{"name": "appended_bytes", "value": data["appended_bytes"]}]))
        return out
