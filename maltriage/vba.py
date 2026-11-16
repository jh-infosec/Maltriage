"""
VBA projects: the `dir` stream, the module source, and what the source says
it does when the document opens.

A VBA project is a storage in a compound file. Its `dir` stream lists the
modules, and each module stream holds compiled p-code followed by the source
text, compressed with the run length scheme of MS-OVBA section 2.4.1. The
source is what Office shows in the editor and, in every version but the one
that compiled it, what Office runs.

Three rules apply here, and they are this project's rules everywhere else:

  * **Bounded.** Decompression can expand a chunk to 4096 bytes from three,
    so the output is capped per module and per project, and a module or
    project that reaches the cap says so instead of reading as complete.
  * **The source never reaches a report.** It is sample content, and this
    tool reports offsets and names, never matched bytes. What a module is
    reported as is its name, its size, a hash of its source, and which
    entries from this module's own lists it declares or calls. A finding
    quotes the list, not the sample.
  * **Names are sample text.** Every module name goes through `safe_text`.
"""

from __future__ import annotations

import hashlib
import re
import struct
from typing import Any, Callable

from .base import safe_text

CHUNK = 4096

#: Procedures Office runs by itself, by name. Word's automatic macros, the
#: document and workbook events, and PowerPoint's one legacy hook. Matched as
#: a declaration (`Sub AutoOpen`), never as a mention, so a comment saying
#: "do not add an AutoOpen" is not one.
AUTO_EXEC = (
    "AutoExec", "AutoOpen", "AutoNew", "AutoClose", "AutoExit",
    "Auto_Open", "Auto_Close", "Auto_Activate", "Auto_Deactivate",
    "Document_Open", "Document_Close", "Document_New", "Document_BeforeClose",
    "DocumentOpen", "DocumentBeforeClose", "NewDocument",
    "Workbook_Open", "Workbook_Activate", "Workbook_BeforeClose",
    "Workbook_Deactivate", "Workbook_SheetActivate",
    "Auto_Open_Presentation",
)

#: Calls that start something outside the document. Each is a fixed token
#: from this list, and the finding names the token, not the line it was on.
EXECUTION = (
    ("Shell", re.compile(r"\bShell\s*[\(\s]", re.I)),
    ("WScript.Shell", re.compile(r"WScript\.Shell", re.I)),
    ("Shell.Application", re.compile(r"Shell\.Application", re.I)),
    ("ShellExecute", re.compile(r"\bShellExecute", re.I)),
    ("CreateProcess", re.compile(r"\bCreateProcess", re.I)),
    ("Win32_Process", re.compile(r"Win32_Process", re.I)),
    ("MacScript", re.compile(r"\bMacScript\b", re.I)),
    ("ExecuteExcel4Macro", re.compile(r"\bExecuteExcel4Macro\b", re.I)),
    ("powershell", re.compile(r"powershell", re.I)),
    ("mshta", re.compile(r"\bmshta\b", re.I)),
    ("cmd.exe", re.compile(r"\bcmd(?:\.exe)?\s+/[ck]\b", re.I)),
)

#: Calls that fetch or write files, or reach native code. Reported as
#: capability, not as intent: a macro that saves a report uses half of these.
CAPABILITY = (
    ("URLDownloadToFile", re.compile(r"URLDownloadToFile", re.I)),
    ("XMLHTTP", re.compile(r"XMLHTTP", re.I)),
    ("WinHttpRequest", re.compile(r"WinHttp\.WinHttpRequest", re.I)),
    ("ADODB.Stream", re.compile(r"ADODB\.Stream", re.I)),
    ("SaveToFile", re.compile(r"\.SaveToFile\b", re.I)),
    ("Declare Lib", re.compile(r"^\s*(?:Public\s+|Private\s+)?Declare\s+(?:PtrSafe\s+)?"
                               r"(?:Sub|Function)\b[^\n]*\bLib\b", re.I | re.M)),
    ("VirtualAlloc", re.compile(r"\bVirtualAlloc", re.I)),
    ("RtlMoveMemory", re.compile(r"\bRtlMoveMemory\b", re.I)),
    ("CreateThread", re.compile(r"\bCreateThread\b", re.I)),
    ("CallByName", re.compile(r"\bCallByName\b", re.I)),
)

#: Events an ActiveX control raises by being drawn or loaded, with nobody
#: touching it. A handler for one runs when the document opens, which is why
#: `InkPicture1_Painted` and `Frame1_Layout` replaced `AutoOpen` once
#: scanners learned that name. Events a person causes (`Click`, `Change`,
#: `MouseMove`) are left out: a form with a button is not a trigger.
ACTIVEX_EVENTS = (
    "Painted", "Painting", "Layout", "Resize", "GotFocus",
    "DocumentComplete", "NavigateComplete2", "BeforeNavigate2",
    "DownloadBegin", "DownloadComplete", "ProgressChange",
    "StatusTextChange", "TitleChange", "NavigateError",
)
_ACTIVEX = {name.lower(): name for name in ACTIVEX_EVENTS}

#: Objects whose events are not a control's. `UserForm_Resize` runs when a
#: form is shown, which needs a macro to show it; `Document_` and
#: `Workbook_` are in `AUTO_EXEC` already.
_NOT_CONTROLS = {"userform", "document", "workbook", "worksheet", "chart", "app",
                 "application", "presentation"}

_DECLARATION = re.compile(
    r"^[ \t]*(?:(?:Public|Private|Friend)[ \t]+)?(?:Static[ \t]+)?(?:Sub|Function)[ \t]+"
    r"([A-Za-z_][A-Za-z0-9_]*)", re.I | re.M)
_AUTO = {name.lower(): name for name in AUTO_EXEC}


class DecompressionError(ValueError):
    """The bytes are not an MS-OVBA compressed container."""


def decompress(data: bytes, cap: int) -> tuple[bytes, bool]:
    """MS-OVBA 2.4.1 decompression, stopping at `cap` output bytes.

    Returns the output and whether the cap cut it short. Every length and
    offset comes from the input and is checked before it is used: a copy
    token pointing before the start of its chunk is an error, not a read of
    whatever happens to be there.
    """
    if not data or data[0] != 0x01:
        raise DecompressionError("no compressed container signature")
    out = bytearray()
    position = 1
    while position < len(data):
        if position + 2 > len(data):
            break
        header = struct.unpack_from("<H", data, position)[0]
        size = (header & 0x0FFF) + 3
        if (header >> 12) & 0x7 != 0b011:
            raise DecompressionError(f"chunk signature wrong at {position}")
        compressed = bool(header & 0x8000)
        end = min(position + size, len(data))
        position += 2
        start = len(out)
        if not compressed:
            take = data[position:position + CHUNK]
            room = cap - len(out)
            out += take[:room]
            if len(take) > room:
                return bytes(out), True
            position += CHUNK
            continue
        while position < end:
            flags = data[position]
            position += 1
            for bit in range(8):
                if position >= end:
                    break
                if len(out) >= cap:
                    return bytes(out), True
                if not flags & (1 << bit):
                    out.append(data[position])
                    position += 1
                    continue
                if position + 2 > end:
                    raise DecompressionError(f"copy token cut short at {position}")
                token = struct.unpack_from("<H", data, position)[0]
                position += 2
                difference = len(out) - start
                bits = max((difference - 1).bit_length(), 4)
                length = (token & (0xFFFF >> bits)) + 3
                offset = (token >> (16 - bits)) + 1
                if offset > difference:
                    raise DecompressionError(f"copy token reaches before its chunk at {position}")
                for _ in range(length):
                    if len(out) >= cap:
                        return bytes(out), True
                    out.append(out[-offset])
        position = end
    return bytes(out), False


def parse_dir(raw: bytes) -> dict[str, Any]:
    """The project's code page and its modules, from a decompressed `dir`.

    Read as a sequence of (id, size, data) records, which every record is but
    one: PROJECTVERSION states a size of 4 and carries 6 bytes. That quirk is
    in the specification, and a reader that trusts the size field reads the
    rest of the stream two bytes out of step.
    """
    out: dict[str, Any] = {"code_page": None, "modules": [], "problems": []}
    position = 0
    module: dict[str, Any] | None = None
    while position + 6 <= len(raw):
        ident, size = struct.unpack_from("<HI", raw, position)
        position += 6
        if ident == 0x0009:
            size = 6
        if position + size > len(raw):
            out["problems"].append(f"dir: record {ident:#06x} runs past the end")
            break
        body = raw[position:position + size]
        position += size
        if ident == 0x0003 and size >= 2:
            out["code_page"] = struct.unpack_from("<H", body)[0]
        elif ident == 0x0019:
            module = {"name": body, "name_unicode": None, "stream": None,
                      "stream_unicode": None, "offset": None, "kind": "procedural"}
        elif module is None:
            continue
        elif ident == 0x0047:
            module["name_unicode"] = body
        elif ident == 0x001A:
            module["stream"] = body
        elif ident == 0x0032:
            module["stream_unicode"] = body
        elif ident == 0x0031 and size >= 4:
            module["offset"] = struct.unpack_from("<I", body)[0]
        elif ident == 0x0022:
            module["kind"] = "document"
        elif ident == 0x002B:
            out["modules"].append(module)
            module = None
        elif ident == 0x0010:
            break
    if module is not None:
        out["problems"].append("dir: the last module has no terminator")
        out["modules"].append(module)
    return out


def _codec(code_page: int | None) -> str:
    if code_page == 65001:
        return "utf-8"
    if code_page:
        try:
            name = f"cp{code_page}"
            "".encode(name)
            return name
        except LookupError:
            pass
    return "latin-1"


def _text(raw: bytes | None, unicode: bytes | None, codec: str) -> str | None:
    if unicode:
        return unicode.decode("utf-16-le", "replace")
    if raw:
        return raw.decode(codec, "replace")
    return None


def scan_source(source: str, kind: str = "procedural") -> dict[str, list[str]]:
    """Which entries of this module's lists the source declares or calls.

    Returns names from the lists only. The source itself goes nowhere: a
    control handler is reported as `ActiveX Painted`, never by the control's
    name, which the sample chose.

    Control handlers count only in a document module. A control on a
    document raises its events in that document's module (`ThisDocument`, a
    sheet), and a procedure called `Frame1_Layout` in an ordinary module is
    a procedure with an underscore in its name.
    """
    declared = {match.group(1).lower() for match in _DECLARATION.finditer(source)}
    auto = {_AUTO[name] for name in declared if name in _AUTO}
    if kind == "document":
        for name in declared:
            control, _, event = name.rpartition("_")
            if control and control not in _NOT_CONTROLS and event in _ACTIVEX:
                auto.add(f"ActiveX {_ACTIVEX[event]}")
    return {
        "auto_exec": sorted(auto),
        "execution": [name for name, pattern in EXECUTION if pattern.search(source)],
        "capability": [name for name, pattern in CAPABILITY if pattern.search(source)],
    }


#: `_VBA_PROJECT` versions below this are VBA5 (Office 97), whose module
#: header is laid out differently; their p-code is not judged.
_VBA6 = 0x6B
#: The version a writer stores to say "recompile from source": Office then
#: ignores the p-code, so it cannot be what runs and cannot be stomped.
_RECOMPILE = 0xFFFF


def project_version(raw: bytes | None) -> int | None:
    """The VBA version `_VBA_PROJECT` was compiled by, or `None`."""
    if raw is None or len(raw) < 4 or struct.unpack_from("<H", raw, 0)[0] != 0x61CC:
        return None
    return struct.unpack_from("<H", raw, 2)[0]


def pcode_lines(pcode: bytes, version: int | None) -> int | None:
    """How many lines the compiled code of a module holds, or `None` when
    there is no compiled code this can read.

    The layout is the one `pcodedmp` documents for VBA6 and VBA7, 32 and 64
    bit alike: a dword at 0x19 locates a line table that opens with the
    magic 0xCAFE, and the word four bytes after it counts the lines. Byte
    order is the module's own (a Mac project is big-endian), told by the
    word at offset 2.
    """
    if version is None or version == _RECOMPILE or version < _VBA6 or len(pcode) < 0x1D:
        return None
    endian = "<" if struct.unpack_from("<H", pcode, 2)[0] <= 0xFF else ">"
    table = struct.unpack_from(f"{endian}I", pcode, 0x19)[0] + 0x3C
    if table + 6 > len(pcode) or struct.unpack_from(f"{endian}H", pcode, table)[0] != 0xCAFE:
        return None
    return struct.unpack_from(f"{endian}H", pcode, table + 4)[0]


_MIN_LITERAL = 4
_LITERALS_KEPT = 4096


def pcode_literals(pcode: bytes, version: int | None) -> list[str] | None:
    """The string literals and comments in a module's compiled lines, or
    `None` when there is no line table to read.

    Each entry of the line table gives a line's length and its offset from
    the end of the table, and inside a line a string is a two-byte length
    followed by that many bytes, padded to even. Opcodes are not decoded:
    their numbers change between VBA versions, and `pcodedmp`, which knows
    them, is GPL. Without them, a printable run behind a length that fits
    exactly is what is taken, and only inside a line, never from the
    module header, whose structures were measured to hold printable noise.

    Measured on eight real Office modules (versions 0x97 and 0xAF, one of
    them out of a `.ppt`): three literals found, a comment and two strings,
    each present in its source, and nothing else.
    """
    if version is None or version == _RECOMPILE or version < _VBA6 or len(pcode) < 0x1D:
        return None
    endian = "<" if struct.unpack_from("<H", pcode, 2)[0] <= 0xFF else ">"
    table = struct.unpack_from(f"{endian}I", pcode, 0x19)[0] + 0x3C
    if table + 6 > len(pcode) or struct.unpack_from(f"{endian}H", pcode, table)[0] != 0xCAFE:
        return None
    count = struct.unpack_from(f"{endian}H", pcode, table + 4)[0]
    start = table + 6 + count * 12 + 10
    found: list[str] = []
    for index in range(count):
        entry = table + 6 + index * 12
        if entry + 12 > len(pcode):
            break
        length = struct.unpack_from(f"{endian}H", pcode, entry + 4)[0]
        offset = struct.unpack_from(f"{endian}I", pcode, entry + 8)[0]
        body = pcode[start + offset:start + offset + length]
        for position in range(0, len(body) - 2, 2):
            size = struct.unpack_from(f"{endian}H", body, position)[0]
            if _MIN_LITERAL <= size <= len(body) - position - 2:
                text = body[position + 2:position + 2 + size]
                if all(0x20 <= byte < 0x7F for byte in text):
                    found.append(text.decode("ascii"))
                    if len(found) >= _LITERALS_KEPT:
                        return found
    return found


def source_lines(source: str) -> tuple[int, int, bool]:
    """The range of line counts the compiled code could honestly have for
    this source, and whether the source holds any code at all.

    A range, because two things are not known from documentation alone:
    whether a continued line (`_` at the end) is one line or several in the
    p-code, and whether attributes inside a procedure and trailing blank
    lines are counted. On every real module measured the count was the
    plain one, with the header attributes left out; the range is the
    margin for the cases nobody has measured, and it is the safe direction
    to be wrong in.
    """
    lines = source.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    # Sliced, not popped one at a time from the front: each pop shifts the
    # whole list, and a module of nothing but attribute lines made that
    # quadratic (a 2 MiB module took 0.8 s before v0.6.8).
    first = 0
    while first < len(lines) and lines[first].startswith("Attribute "):
        first += 1
    lines = lines[first:]
    high = len(lines)
    plain = [line for line in lines if not line.lstrip().startswith("Attribute ")]
    while plain and not plain[-1].strip():
        plain.pop()
    logical = 0
    continued = False
    for line in plain:
        if not continued:
            logical += 1
        continued = line.rstrip().endswith(" _")
    has_code = any(line.strip() for line in plain)
    return logical, max(high, len(plain)), has_code


#: Substring searches allowed per module for strings the tokenizer did not
#: find. Each one reads the whole source, so this is what bounds the check.
_FALLBACK_SEARCHES = 64


def source_strings(source: str) -> set[str]:
    """Every string literal and comment in the source, as the p-code holds
    them: a literal unescaped (`""` is one quote), a comment from after its
    apostrophe to the end of the line. One pass, so checking a compiled
    string against them is a set lookup rather than a search of the source.
    """
    found: set[str] = set()
    index, size = 0, len(source)
    while index < size:
        char = source[index]
        if char == '"':
            end = index + 1
            pieces = []
            while end < size:
                if source[end] == '"':
                    if end + 1 < size and source[end + 1] == '"':
                        pieces.append('"')
                        end += 2
                        continue
                    break
                if source[end] in "\r\n":
                    break
                pieces.append(source[end])
                end += 1
            found.add("".join(pieces))
            index = end + 1
        elif char == "'":
            end = index + 1
            while end < size and source[end] not in "\r\n":
                end += 1
            found.add(source[index + 1:end])
            index = end
        else:
            index += 1
    return found


def stomped(compiled: int | None, source: str,
            literals: list[str] | None = None,
            problems: list[str] | None = None) -> str | None:
    """Why the compiled code is not the source shown, or `None`.

    Only when there is compiled code with lines in it. A module whose
    p-code holds no lines is one Office has not compiled since it was last
    edited, which is ordinary; it is the other direction, code that runs
    with nothing or something else shown, that is the technique.
    """
    if not compiled:
        return None
    low, high, has_code = source_lines(source)
    if not has_code:
        return "source missing"
    if not low <= compiled <= high:
        return "line count differs"
    # A decoy with as many lines as the code it replaced passes the count.
    # What it cannot keep without keeping the payload is the payload's
    # strings: the URL, the command line, the encoded blob. A literal is
    # checked as written in the source too, with its quotes doubled.
    #
    # The source is tokenized once and most strings are found in that set.
    # A string the tokenizer missed (a `Rem` comment, say) falls back to a
    # search of the source, and those are capped: in v0.6.7 every string
    # searched the whole source, and 4,096 strings against a 4 MiB module
    # took 8.9 s. Past the cap the check says it came back short rather
    # than guessing either way.
    if literals:
        known = source_strings(source)
        searches = 0
        for literal in dict.fromkeys(literals):
            if literal in known:
                continue
            searches += 1
            if searches > _FALLBACK_SEARCHES:
                if problems is not None:
                    problems.append(f"vba: more compiled strings than {_FALLBACK_SEARCHES} "
                                    "could be checked against the source")
                return None
            if literal not in source and literal.replace('"', '""') not in source:
                return "literals differ"
    return None


def extract(read: Callable[[str], bytes | None], config_caps: dict[str, int]) -> dict[str, Any]:
    """Read a VBA project through `read`, which maps a stream name in the
    project's `VBA` storage to its bytes, or `None` when there is none.

    The caller owns the compound file and its bounds; this owns the format
    inside it.
    """
    module_cap = config_caps["module"]
    total_cap = config_caps["total"]
    max_modules = config_caps["modules"]
    out: dict[str, Any] = {"modules": [], "auto_exec": [], "execution": [],
                           "capability": [], "truncated": False, "problems": []}
    raw_dir = read("dir")
    if raw_dir is None:
        out["problems"].append("vba: the project has no dir stream")
        return out
    try:
        directory, cut = decompress(raw_dir, 1048576)
    except DecompressionError as exc:
        out["problems"].append(f"vba: dir stream: {exc}")
        return out
    if cut:
        out["problems"].append("vba: the dir stream decompresses past 1 MiB; read that far")
    project = parse_dir(directory)
    out["problems"].extend(project["problems"])
    codec = _codec(project["code_page"])
    out["code_page"] = project["code_page"]
    version = project_version(read("_VBA_PROJECT"))
    out["version"] = version
    out["stomped"] = []

    spent = 0
    found = {"auto_exec": set(), "execution": set(), "capability": set()}
    for index, module in enumerate(project["modules"]):
        if index >= max_modules:
            out["truncated"] = True
            out["problems"].append(f"vba: more than {max_modules} modules; the rest were not read")
            break
        name = _text(module["name"], module["name_unicode"], codec) or "?"
        stream = _text(module["stream"], module["stream_unicode"], codec) or name
        record: dict[str, Any] = {"name": safe_text(name, 128), "kind": module["kind"],
                                  "source_bytes": 0, "sha256": None}
        out["modules"].append(record)
        body = read(stream)
        label = f"vba: module {safe_text(name, 64)!r}"
        if body is None:
            out["problems"].append(f"{label}: no stream of that name")
            continue
        offset = module["offset"]
        if offset is None or offset > len(body):
            out["problems"].append(f"{label}: the source offset is outside the stream")
            continue
        room = min(module_cap, total_cap - spent)
        if room <= 0:
            out["truncated"] = True
            out["problems"].append(f"vba: source past {total_cap} bytes was not read")
            break
        try:
            source, cut = decompress(body[offset:], room)
        except DecompressionError as exc:
            out["problems"].append(f"{label}: {exc}")
            continue
        if cut:
            out["truncated"] = True
            out["problems"].append(f"{label}: source cut at {len(source)} bytes")
        spent += len(source)
        record["source_bytes"] = len(source)
        record["sha256"] = hashlib.sha256(source).hexdigest()
        text = source.decode(codec, "replace")
        hits = scan_source(text, module["kind"])
        record.update(hits)
        compiled = pcode_lines(body[:offset], version)
        literals = pcode_literals(body[:offset], version)
        record["pcode_lines"] = compiled
        # A count, never the strings: they are the sample's content.
        record["pcode_literals"] = None if literals is None else len(literals)
        # A source cut at the cap has fewer lines than it should, which is
        # not the same thing as a source that was replaced.
        reason = None if cut else stomped(compiled, text, literals, out["problems"])
        record["stomped"] = reason
        if reason:
            out["stomped"].append(reason)
        for key, names in hits.items():
            found[key].update(names)
    for key, names in found.items():
        out[key] = sorted(names)
    return out
