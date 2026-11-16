"""
Excel 4.0 macros: macro sheets, and whether one runs when the workbook opens.

Before VBA, Excel's macros were formulas on a sheet of their own, and Excel
still runs them. From 2020 they were how a large share of malicious
workbooks ran, because a scanner that looks for a VBA project finds none:
the code is cells. Three facts say most of what matters, and none needs the
formulas evaluated:

  * **A macro sheet exists.** In a `.xls` the sheet table marks its type; in
    a `.xlsm` or `.xlsb` the workbook's relationships point at a
    `macrosheets/` part.
  * **It is hidden, or very hidden.** Very hidden is a state Excel's own
    interface cannot undo, and it is what a sheet nobody is meant to see is
    set to.
  * **A name starting `Auto_Open` points into the workbook.** Excel runs it on
    open, as Word runs `AutoOpen`. Excel matches the prefix, so
    `Auto_Open2` and `auto_openXYZ` run too, and droppers use exactly that.

The formulas themselves never reach a report, for the reason VBA source
does not: they are the sample's content.

Three containers, one answer. `.xls` is BIFF records in the `Workbook`
stream (`Book` for Excel 5); `.xlsm` is XML; `.xlsb` is BIFF12, binary
records with variable-length headers. Each reader returns the same shape,
and one function turns that shape into findings, so a workbook says the same
thing whichever way it was saved.
"""

from __future__ import annotations

import html
import re
import struct
from typing import Any, Callable

from .base import safe_text
from .models import mk_finding

STATES = {0: "visible", 1: "hidden", 2: "very hidden"}

# BIFF (.xls)
_BOF, _EOF, _BOUNDSHEET, _NAME, _FILEPASS = 0x0809, 0x000A, 0x0085, 0x0018, 0x002F
_BOF_MACRO_SHEET = 0x0040
_SHEET_MACRO = 0x01
_BUILTIN_AUTO_OPEN = 0x01
_MAX_RECORDS = 1_000_000

# BIFF12 (.xlsb)
_BRT_BUNDLE_SH, _BRT_NAME = 0x009C, 0x0027

_MACRO_RELATIONSHIPS = ("xlmacrosheet", "xlintlmacrosheet")
_READ_LIMIT = 16 * 1048576


def _empty() -> dict[str, Any]:
    return {"macro_sheets": [], "auto_open": False, "encrypted": False, "problems": []}


def _runs_on_open(name: str) -> bool:
    lowered = name.lower()
    return lowered.startswith("auto_open") or lowered.startswith("_xlnm.auto_open")


# .xls

def from_biff(stream: bytes) -> dict[str, Any]:
    """Macro sheets and `Auto_Open` from a `Workbook` or `Book` stream.

    Only the workbook globals are walked, up to their EOF: the sheet table
    and the names live there. A sheet counts as a macro sheet when the
    table says so or when the sheet's own BOF does, because the two are
    separate fields and a reader that trusted one would miss a file that
    set only the other.
    """
    out = _empty()
    position, records, biff8 = 0, 0, True
    while position + 4 <= len(stream):
        kind, size = struct.unpack_from("<HH", stream, position)
        body = stream[position + 4:position + 4 + size]
        position += 4 + size
        records += 1
        if records > _MAX_RECORDS:
            out["problems"].append(f"xlm: more than {_MAX_RECORDS} records in the globals")
            break
        if kind == _BOF and len(body) >= 2:
            biff8 = struct.unpack_from("<H", body, 0)[0] >= 0x0600
        elif kind == _FILEPASS:
            # Everything after it is encrypted, the sheet table included, so
            # nothing past this point means what it seems to.
            out["encrypted"] = True
            break
        elif kind == _BOUNDSHEET and len(body) >= 6:
            offset, state, sheet_type = struct.unpack_from("<IBB", body, 0)
            if sheet_type == _SHEET_MACRO or _bof_type(stream, offset) == _BOF_MACRO_SHEET:
                out["macro_sheets"].append({"state": STATES.get(state & 0x03, "visible")})
        elif kind == _NAME and len(body) >= 14:
            flags, _, length = struct.unpack_from("<HBB", body, 0)
            # BIFF8 puts a one-byte encoding flag before the name; BIFF5 does
            # not, so the name starts one byte earlier there.
            start = 15 if biff8 else 14
            if flags & 0x0020:
                # A built-in name is stored as one code, and 1 is Auto_Open.
                if len(body) > start and body[start] == _BUILTIN_AUTO_OPEN:
                    out["auto_open"] = True
                continue
            wide = biff8 and body[14] & 0x01
            raw = body[start:start + length * (2 if wide else 1)]
            name = raw.decode("utf-16-le" if wide else "latin-1", "replace")
            if _runs_on_open(name):
                out["auto_open"] = True
        elif kind == _EOF:
            break
    return out


def _bof_type(stream: bytes, offset: int) -> int | None:
    if offset + 8 > len(stream):
        return None
    kind, size = struct.unpack_from("<HH", stream, offset)
    if kind != _BOF or size < 4:
        return None
    return struct.unpack_from("<H", stream, offset + 6)[0]


# .xlsm, .xltm, .xlsx

_ATTRIBUTE = re.compile(r"""([A-Za-z_][\w.:-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')""")
_ELEMENT = r"<(?:[A-Za-z_][\w.-]*:)?{name}\b([^>]*)>"
_RELATIONSHIP = re.compile(_ELEMENT.format(name="Relationship"))
_SHEET = re.compile(_ELEMENT.format(name="sheet"))
_DEFINED = re.compile(_ELEMENT.format(name="definedName"))


def _attributes(raw: str) -> dict[str, str]:
    """Attributes by local name, decoded as Excel decodes them."""
    return {name.rsplit(":", 1)[-1]: html.unescape(double if double or not single else single)
            for name, double, single in _ATTRIBUTE.findall(raw)}


def _text(raw: bytes) -> str:
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", "replace")
    return raw.decode("utf-8", "replace")


def from_parts(read: Callable[[str], bytes | None], names: list[str]) -> dict[str, Any]:
    """Macro sheets and `Auto_Open` from an OOXML workbook's parts.

    `names` are the member names as the container spells them; `read` maps
    one to its bytes. The workbook is found through its relationships, not
    by name, because OPC lets the author call it anything.
    """
    out = _empty()
    lowered = {name.lower(): name for name in names}
    for rels in [n for n in names if n.lower().endswith(".rels")]:
        raw = read(rels)
        if raw is None:
            continue
        macro_ids = {}
        for found in _RELATIONSHIP.finditer(_text(raw)):
            attributes = _attributes(found.group(1))
            kind = attributes.get("Type", "").rstrip("/").rsplit("/", 1)[-1].lower()
            if kind in _MACRO_RELATIONSHIPS:
                macro_ids[attributes.get("Id", "")] = attributes.get("Target", "")
        if not macro_ids:
            continue
        # `xl/_rels/workbook.xml.rels` describes `xl/workbook.xml`.
        folder, _, leaf = rels.rpartition("/")
        source = f"{folder.rpartition('/')[0]}/{leaf[:-len('.rels')]}".lstrip("/")
        part = lowered.get(source.lower())
        body = read(part) if part else None
        if body is None:
            out["macro_sheets"].extend({"state": "unknown"} for _ in macro_ids)
            out["problems"].append("xlm: a macro sheet's workbook part was not read")
            continue
        if source.lower().endswith(".bin"):
            sheets, names_found = _biff12(body, out["problems"])
        else:
            text = _text(body)
            sheets = {}
            for found in _SHEET.finditer(text):
                attributes = _attributes(found.group(1))
                state = attributes.get("state", "visible")
                sheets[attributes.get("id", "")] = {"veryHidden": "very hidden"}.get(state, state)
            names_found = [_attributes(found.group(1)).get("name", "")
                           for found in _DEFINED.finditer(text)]
        for relation_id in macro_ids:
            out["macro_sheets"].append({"state": sheets.get(relation_id, "unknown")})
        if any(_runs_on_open(name) for name in names_found):
            out["auto_open"] = True
    return out


def _varint(data: bytes, position: int, width: int) -> tuple[int, int] | None:
    value = 0
    for index in range(width):
        if position >= len(data):
            return None
        byte = data[position]
        position += 1
        value |= (byte & 0x7F) << (7 * index)
        if not byte & 0x80:
            return value, position
    return value, position


def _wide(data: bytes, position: int) -> tuple[str | None, int]:
    if position + 4 > len(data):
        return None, len(data)
    count = struct.unpack_from("<I", data, position)[0]
    position += 4
    if count == 0xFFFFFFFF:
        return None, position
    end = position + count * 2
    if end > len(data):
        return None, len(data)
    return data[position:end].decode("utf-16-le", "replace"), end


def _biff12(body: bytes, problems: list[str]) -> tuple[dict[str, str], list[str]]:
    """Sheet states by relationship id, and defined names, from workbook.bin.

    BIFF12 records have a type of one or two bytes and a size of up to four,
    each a run of 7-bit groups with the high bit saying another follows.
    """
    sheets: dict[str, str] = {}
    names: list[str] = []
    for kind, record in records(body, problems, "workbook.bin"):
        if kind == _BRT_BUNDLE_SH and len(record) >= 8:
            state = struct.unpack_from("<I", record, 0)[0]
            relation_id, _ = _wide(record, 8)
            if relation_id is not None:
                sheets[relation_id] = STATES.get(state & 0x03, "visible")
        elif kind == _BRT_NAME and len(record) >= 9:
            name, _ = _wide(record, 9)
            if name:
                names.append(name)
    return sheets, names


_BRT_BEGIN_SUPBOOK = 0x0168
_SUPBOOK_DDE = 0x0001


def records(body: bytes, problems: list[str], label: str):
    """(type, record) for each BIFF12 record in `body`, bounded."""
    position, count = 0, 0
    while position < len(body):
        kind = _varint(body, position, 2)
        size = _varint(body, kind[1], 4) if kind else None
        if size is None:
            return
        count += 1
        if count > _MAX_RECORDS:
            problems.append(f"xlm: more than {_MAX_RECORDS} records in {label}")
            return
        start, end = size[1], size[1] + size[0]
        if end > len(body):
            problems.append(f"xlm: a {label} record runs past the end")
            return
        yield kind[0], body[start:end]
        position = end


def dde_servers(body: bytes, problems: list[str]) -> list[str]:
    """The DDE server of every DDE link in a `.xlsb` external link part.

    BrtBeginSupBook opens each linked book; a type of 1 makes it a DDE link,
    and its first string is the application Excel starts. The second, the
    topic, is the command line, and stays in the sample.
    """
    servers = []
    for kind, record in records(body, problems, "external link"):
        if kind == _BRT_BEGIN_SUPBOOK and len(record) >= 2:
            if struct.unpack_from("<H", record, 0)[0] == _SUPBOOK_DDE:
                server, _ = _wide(record, 2)
                servers.append(server or "")
    return servers


# findings, one computation for every container

def findings(extractor: str, data: dict[str, Any]) -> list[dict[str, Any]]:
    sheets = data.get("macro_sheets") or []
    if not sheets:
        return []
    states = [sheet["state"] for sheet in sheets]
    hidden = sum(1 for state in states if state == "hidden")
    very = sum(1 for state in states if state == "very hidden")
    shown = []
    if very:
        shown.append(f"{very} very hidden, a state Excel's own menus cannot undo")
    if hidden:
        shown.append(f"{hidden} hidden")
    tail = f" ({'; '.join(shown)})" if shown else ""
    evidence = [{"name": "count", "value": len(sheets)},
                {"name": "hidden", "value": hidden},
                {"name": "very_hidden", "value": very}]
    out = [mk_finding(
        extractor, "xlm_macro_sheet",
        f"{len(sheets)} Excel 4.0 macro sheet(s){tail}; its cells are code, and no "
        "VBA project is needed to run them", "low", evidence=evidence)]
    if data.get("auto_open"):
        # At the gate, by the reasoning that put `vba_autorun_execution`
        # there: a macro sheet in an old finance workbook is ordinary, and
        # one Excel runs because the file was opened is what the 2020 to
        # 2022 campaigns shipped. Predicted quiet on the document corpus.
        out.append(mk_finding(
            extractor, "xlm_auto_open",
            "an Excel 4.0 macro sheet runs when the workbook opens: a name "
            f"starting Auto_Open points into it{tail}", "medium", evidence=evidence))
    return out


def describe(data: dict[str, Any]) -> dict[str, Any]:
    """What a report carries: counts and states, never cell content."""
    return {"macro_sheets": [{"state": safe_text(s["state"], 16)} for s in data["macro_sheets"]],
            "auto_open": data["auto_open"], "encrypted": data["encrypted"]}
