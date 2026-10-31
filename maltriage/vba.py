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


def scan_source(source: str) -> dict[str, list[str]]:
    """Which entries of this module's lists the source declares or calls.

    Returns names from the lists only. The source itself goes nowhere.
    """
    declared = {match.group(1).lower() for match in _DECLARATION.finditer(source)}
    return {
        "auto_exec": sorted(_AUTO[name] for name in declared if name in _AUTO),
        "execution": [name for name, pattern in EXECUTION if pattern.search(source)],
        "capability": [name for name, pattern in CAPABILITY if pattern.search(source)],
    }


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
        hits = scan_source(source.decode(codec, "replace"))
        record.update(hits)
        for key, names in hits.items():
            found[key].update(names)
    for key, names in found.items():
        out[key] = sorted(names)
    return out
