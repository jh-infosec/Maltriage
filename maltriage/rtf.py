"""
RTF: the objects embedded in a rich text document.

RTF has no macros, so an embedded object is the mechanism it has. Since
2017 that has meant three things above all: an Equation Editor object
built to exploit it (CVE-2017-11882, CVE-2018-0802), an `OLE2Link` object
that fetches a remote document when the file opens (CVE-2017-0199), and a
Packager object carrying a file someone will be asked to double-click.

An object is written in the text as hex, in an `\\objdata` destination
inside an `\\object` group, with its class in `\\objclass`. The hex is an
OLE1 object (MS-OLEDS 2.2): a class name, then native data, which for most
classes is an OLE2 compound file and for Packager is a file and its name.

Attackers mangle all of this, because Word is forgiving and analysers were
not. The reader here does what Word does with each trick rather than what a
regular expression would:

  * a document starts `{\\rt`, not `{\\rtf1`: Word opens it either way;
  * whitespace, line breaks and stray characters inside the hex are skipped;
  * control words inside the hex are skipped, and `\\binN` inserts N raw
    bytes where it stands;
  * a nested group inside the hex is part of it unless it is itself a
    destination (`{\\*...}` or a known destination word), which is skipped;
  * an odd hex digit at the end is dropped;
  * `\\objdata` is read wherever it appears, inside an `\\object` group or
    not.

The objects are not analysed here. Each one's payload is handed back as a
member, staged by `archives.py` under the same budget as a ZIP's members,
and analysed as a child: an embedded Word document by the OLE reader, a
packaged executable by the PE reader, a packaged shortcut by the shortcut
reader. What this module reports is what the container says about them.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Iterator

#: The compound file's own magic. `ole.py` is imported where it is used,
#: not here: it imports `msdoc.py`, which imports `archives.py`, which
#: imports this module.
OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")

#: Destinations whose text is never object data, inside `\objdata` or out.
_DESTINATIONS = {
    b"pict", b"fonttbl", b"colortbl", b"stylesheet", b"info", b"header", b"footer",
    b"footnote", b"field", b"fldinst", b"fldrslt", b"bkmkstart", b"bkmkend",
    b"datastore", b"themedata", b"colorschememapping", b"latentstyles",
    b"listtable", b"listoverridetable", b"rsidtbl", b"generator", b"xmlnstbl",
    b"result", b"objclass", b"objname", b"objalias", b"objsect", b"objtime",
}
_TOKEN = re.compile(
    rb"\\([a-zA-Z]{1,32})(-?\d{1,10})? ?"   # control word, optional parameter
    rb"|\\'([0-9a-fA-F]{2})"                 # hex escape
    rb"|\\(.)"                               # control symbol
    rb"|([{}])"                              # group
    rb"|([^\\{}]+)",                         # text
    re.DOTALL)
_HEX = re.compile(rb"[0-9a-fA-F]")
_MAX_OBJECTS = 64
_MAX_DEPTH = 4096
_LIMIT = "rtf: object data past the limit was not read"

#: Classes of objects that only an exploit has a use for today. Equation
#: Editor was removed from Office in January 2018; `OLE2Link` in an RTF is
#: the CVE-2017-0199 shape.
EQUATION_CLASSES = ("equation",)
EQUATION_CLSIDS = {bytes.fromhex("02ce020000000000c000000000000046"),
                   bytes.fromhex("02ce030000000000c000000000000046")}
LINK_CLASSES = ("ole2link",)


@dataclass
class RtfObject:
    """One embedded object, and what its RTF and its OLE1 header say."""

    number: int
    rtf_class: str = ""
    update: bool = False
    linked: bool = False
    data: bytearray = field(default_factory=bytearray)
    ole1_class: str = ""
    format_id: int | None = None
    native: bytes = b""
    package_name: str = ""
    package_data: bytes = b""
    compound_clsid: bytes = b""
    problems: list[str] = field(default_factory=list)

    @property
    def class_name(self) -> str:
        return self.ole1_class or self.rtf_class

    def describe(self) -> dict:
        from .base import safe_text
        out = {
            "class": safe_text(self.class_name, 64) or None,
            "rtf_class": safe_text(self.rtf_class, 64) or None,
            "format": {1: "linked", 2: "embedded"}.get(self.format_id or 0,
                                                       "linked" if self.linked else None),
            "autoupdate": self.update,
            "objdata_bytes": len(self.data),
            "native_bytes": len(self.native),
            "compound_file": self.native[:8] == OLE_MAGIC,
            "equation": is_equation(self),
            "ole2link": is_link(self),
        }
        if self.package_name:
            out["package_name"] = safe_text(self.package_name, 256)
            out["package_bytes"] = len(self.package_data)
        return out


def is_equation(obj: RtfObject) -> bool:
    return (any(obj.class_name.lower().startswith(c) for c in EQUATION_CLASSES)
            or any(obj.rtf_class.lower().startswith(c) for c in EQUATION_CLASSES)
            or obj.compound_clsid in EQUATION_CLSIDS)


def is_link(obj: RtfObject) -> bool:
    return any(name.lower().startswith(c) for name in (obj.class_name, obj.rtf_class)
               for c in LINK_CLASSES)


def objects(data: bytes, max_bytes: int, problems: list[str]) -> list[RtfObject]:
    """Every embedded object in the document, its hex decoded.

    One pass over the tokens, tracking group depth. An `\\object` group
    collects its class and flags; an `\\objdata` destination collects hex
    until its group closes. `max_bytes` bounds the decoded data of all
    objects together.
    """
    found: list[RtfObject] = []
    depth = 0
    current: RtfObject | None = None      # the \object group being read
    object_depth = -1
    reading: RtfObject | None = None      # the object whose \objdata is open
    data_depth = -1
    pending_nibble: int | None = None
    class_depth = -1                       # inside {\*\objclass ...}
    skip_depth = -1                        # inside a destination to ignore
    group_start = False                    # the last token opened a group
    spent = 0
    at = 0
    end = len(data)
    while at < end:
        match = _TOKEN.match(data, at)
        if match is None:                   # a lone backslash at the very end
            break
        at = match.end()
        word, param, escaped, symbol, brace, text = match.groups()
        opened = group_start
        group_start = False

        if brace == b"{":
            depth += 1
            group_start = True
            if depth > _MAX_DEPTH:
                problems.append(f"rtf: groups nested deeper than {_MAX_DEPTH}; the rest was not read")
                break
            continue
        if brace == b"}":
            if skip_depth == depth:
                skip_depth = -1
            if class_depth == depth:
                class_depth = -1
            if reading is not None and depth == data_depth:
                reading, data_depth, pending_nibble = None, -1, None
            if current is not None and depth == object_depth:
                current, object_depth = None, -1
            depth = max(0, depth - 1)
            continue

        if skip_depth != -1:
            # Inside a destination being skipped; only `\binN` needs care,
            # because its bytes are raw and could hold a brace.
            if word == b"bin" and param:
                at += max(0, min(int(param), end - at))
            continue

        if word is not None:
            name = word.lower()
            if name == b"bin":
                length = max(0, min(int(param or 0), end - at))
                if reading is not None:
                    raw = data[at:at + length]
                    take = max(0, min(len(raw), max_bytes - spent))
                    reading.data += raw[:take]
                    spent += take
                    if take < len(raw) and _LIMIT not in problems:
                        problems.append(_LIMIT)
                at += length
                continue
            if reading is not None:
                if opened and name in _DESTINATIONS:
                    skip_depth = depth
                # Any other control word inside the hex is ignored, as Word does.
                continue
            if name == b"object":
                if len(found) >= _MAX_OBJECTS:
                    problems.append(f"rtf: more than {_MAX_OBJECTS} objects; the rest were not read")
                    break
                current = RtfObject(number=len(found) + 1)
                found.append(current)
                object_depth = depth
            elif name == b"objdata":
                target = current
                if target is None or target.data:
                    # `\objdata` outside an object, or a second one in it:
                    # read as an object of its own rather than not at all.
                    if len(found) >= _MAX_OBJECTS:
                        problems.append(f"rtf: more than {_MAX_OBJECTS} objects; the rest were not read")
                        break
                    target = RtfObject(number=len(found) + 1)
                    found.append(target)
                reading, data_depth, pending_nibble = target, depth, None
            elif name == b"objclass" and current is not None:
                class_depth = depth
            elif name == b"objupdate" and current is not None:
                current.update = True
            elif name in (b"objlink", b"objautlink") and current is not None:
                current.linked = True
            elif opened and name in _DESTINATIONS:
                skip_depth = depth
            continue

        if symbol == b"*":
            if reading is not None and opened:
                skip_depth = depth
            continue

        chunk = bytes([int(escaped, 16)]) if escaped is not None else (text or b"")
        if class_depth != -1 and current is not None and depth >= class_depth:
            current.rtf_class = (current.rtf_class + chunk.decode("cp1252", "replace")).strip()[:256]
            continue
        if reading is not None and chunk:
            digits = b"".join(_HEX.findall(chunk))
            if pending_nibble is not None:
                digits = bytes([pending_nibble]) + digits
                pending_nibble = None
            if len(digits) % 2:
                pending_nibble, digits = digits[-1], digits[:-1]
            room = max_bytes - spent
            if digits and room > 0:
                decoded = bytes.fromhex(digits[:2 * room].decode("ascii"))
                reading.data += decoded
                spent += len(decoded)
            if len(digits) > 2 * max(room, 0) and _LIMIT not in problems:
                problems.append(_LIMIT)
    for obj in found:
        _ole1(obj)
        problems.extend(f"rtf: object {obj.number}: {note}" for note in obj.problems)
    return found


def _string(data: bytes, at: int) -> tuple[str, int] | None:
    """An OLE1 length-prefixed ANSI string, and where it ends."""
    if at + 4 > len(data):
        return None
    length = struct.unpack_from("<I", data, at)[0]
    if length > 4096 or at + 4 + length > len(data):
        return None
    text = data[at + 4:at + 4 + length].split(b"\0", 1)[0].decode("cp1252", "replace")
    return text, at + 4 + length


def _ole1(obj: RtfObject) -> None:
    """Read the OLE1 header off the decoded data: class, format, native data."""
    data = bytes(obj.data)
    if not data:
        return
    if len(data) < 8:
        obj.problems.append("the object data is too short for an OLE1 header")
        return
    obj.format_id = struct.unpack_from("<I", data, 4)[0]
    read = _string(data, 8)
    if read is None:
        obj.problems.append("the OLE1 class name runs past the object data")
        return
    obj.ole1_class, at = read
    for _ in ("topic", "item"):
        read = _string(data, at)
        if read is None:
            obj.problems.append("the OLE1 header runs past the object data")
            return
        at = read[1]
    if obj.format_id != 2:
        return                              # a linked object carries no native data
    if at + 4 > len(data):
        obj.problems.append("the object has no native data size")
        return
    size = struct.unpack_from("<I", data, at)[0]
    native = data[at + 4:at + 4 + size]
    if len(native) < size:
        obj.problems.append(f"the native data claims {size} bytes and has {len(native)}")
    obj.native = native
    if native[:8] == OLE_MAGIC:
        try:
            from .ole import CompoundFile
            entries = CompoundFile(native, 1024).entries()
            obj.compound_clsid = (entries[0].get("clsid") or b"") if entries else b""
        except Exception as exc:                  # a damaged compound file is a fact, not a crash
            obj.problems.append(f"the embedded compound file does not open: {type(exc).__name__}")
    if obj.class_name.lower().startswith("package"):
        _package(obj)


def _package(obj: RtfObject) -> None:
    """Packager's native data: a label, a source path, a temp path, the file.

    Written with or without a leading total size, so both are tried.
    """
    for start in (0, 4):
        native = obj.native[start:]
        if len(native) < 2 or struct.unpack_from("<H", native, 0)[0] != 2:
            continue
        at = 2
        label_end = native.find(b"\0", at)
        if label_end < 0:
            continue
        label = native[at:label_end].decode("cp1252", "replace")
        path_end = native.find(b"\0", label_end + 1)
        if path_end < 0:
            continue
        at = path_end + 1 + 4                   # the source path, then two reserved words
        if at + 4 > len(native):
            continue
        temp_length = struct.unpack_from("<I", native, at)[0]
        at += 4 + temp_length
        if temp_length > 4096 or at + 4 > len(native):
            continue
        size = struct.unpack_from("<I", native, at)[0]
        payload = native[at + 4:at + 4 + size]
        if len(payload) < size:
            obj.problems.append(f"the packaged file claims {size} bytes and has {len(payload)}")
        obj.package_name = label
        obj.package_data = payload
        return
    obj.problems.append("a Package object whose native data is not a package")


def members(data: bytes, max_bytes: int, problems: list[str]) -> tuple[list[RtfObject], Iterator[tuple[str, bytes]]]:
    """The objects, and each one's payload as a member to stage."""
    found = objects(data, max_bytes, problems)

    def payloads() -> Iterator[tuple[str, bytes]]:
        for obj in found:
            if obj.package_data:
                # The label is the name Packager drops the file under; only
                # its last part, so a label of `..\\..\\x.exe` stages as
                # `x.exe` rather than reading as a container escaping itself.
                leaf = re.split(r"[\\/]", obj.package_name)[-1]
                yield leaf or f"object {obj.number}", obj.package_data
            elif obj.native:
                yield f"object {obj.number}", obj.native

    return found, payloads()
