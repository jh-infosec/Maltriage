"""
Word 97-2003 documents: the text of a `.doc`, and the fields in it.

A `.doc` keeps its text in the `WordDocument` stream, but not in order and
not in one encoding. The file information block at the start of the stream
says which of two table streams is live (`0Table` or `1Table`) and where in
it the piece table is. The piece table maps runs of character positions to
offsets in `WordDocument`, each run either UTF-16 or compressed to one byte
per character. Reading the stream front to back sees fragments in the order
they were last saved, which is not the order a reader sees them.

Fields are in the text itself. Character 0x13 opens one, 0x14 divides its
instruction from its cached result, 0x15 closes it, and fields nest. So a
DDE field is found the way the OOXML reader finds one: build the instruction
from what sits between the opening and dividing marks, let a nested numeric
`QUOTE` contribute its value and any other nested field its cached result,
and read the first word. The helpers that read an instruction are the OOXML
reader's, so the two formats cannot disagree about what a field is.

Bounded like everything else here: the piece count, the text length and the
streams read are capped, and every offset the file supplies is checked
against the stream it points into.
"""

from __future__ import annotations

import re
import struct
from typing import Any, Callable

from .archives import (_DDE_FIELDS, _command_server, _display, _field_words,
                       _quote_result)

WORD_IDENT = 0xA5EC
F_ENCRYPTED = 0x0100
F_WHICH_TABLE = 0x0200
F_OBFUSCATED = 0x8000
FC_CLX_INDEX = 33
FIELD_BEGIN, FIELD_SEPARATE, FIELD_END = "\x13", "\x14", "\x15"
_FIELDS_KEPT = 256
_MAX_NESTING = 64
_FIELD_MARKS = re.compile("([\x13\x14\x15])")


def _piece_table(table: bytes, fc_clx: int, lcb_clx: int,
                 problems: list[str]) -> bytes | None:
    """The PlcPcd inside the Clx, skipping any property runs before it."""
    end = min(fc_clx + lcb_clx, len(table))
    if fc_clx >= end:
        problems.append("doc: the piece table is outside the table stream")
        return None
    position = fc_clx
    while position < end:
        kind = table[position]
        if kind == 0x01 and position + 3 <= end:
            size = struct.unpack_from("<h", table, position + 1)[0]
            if size < 0:
                break
            position += 3 + size
        elif kind == 0x02 and position + 5 <= end:
            length = struct.unpack_from("<I", table, position + 1)[0]
            start = position + 5
            if start + length > end:
                problems.append("doc: the piece table runs past the table stream")
                length = end - start
            return table[start:start + length]
        else:
            break
    problems.append("doc: no piece table where the file says it is")
    return None


def text(word: bytes, read: Callable[[str], bytes | None], max_chars: int,
         max_pieces: int) -> dict[str, Any]:
    """The document's text in reading order, or as much of it as is sane."""
    out: dict[str, Any] = {"text": "", "encrypted": False, "pieces": 0,
                           "truncated": False, "problems": []}
    problems = out["problems"]
    if len(word) < 34 or struct.unpack_from("<H", word, 0)[0] != WORD_IDENT:
        problems.append("doc: the WordDocument stream has no Word header")
        return out
    flags = struct.unpack_from("<H", word, 0x0A)[0]
    if flags & (F_ENCRYPTED | F_OBFUSCATED):
        # The header stays readable and everything after it does not, so
        # this is said rather than parsed into nonsense.
        out["encrypted"] = True
        return out

    position = 32
    csw = struct.unpack_from("<H", word, position)[0]
    position += 2 + csw * 2
    if position + 2 > len(word):
        problems.append("doc: the file information block is cut short")
        return out
    cslw = struct.unpack_from("<H", word, position)[0]
    position += 2 + cslw * 4
    if position + 2 > len(word):
        problems.append("doc: the file information block is cut short")
        return out
    pairs = struct.unpack_from("<H", word, position)[0]
    position += 2
    if pairs <= FC_CLX_INDEX or position + (FC_CLX_INDEX + 1) * 8 > len(word):
        problems.append("doc: the file information block has no piece table entry")
        return out
    fc_clx, lcb_clx = struct.unpack_from("<II", word, position + FC_CLX_INDEX * 8)

    table_name = "1Table" if flags & F_WHICH_TABLE else "0Table"
    table = read(table_name)
    if table is None:
        problems.append(f"doc: the {table_name} stream the header names is missing")
        return out
    plc = _piece_table(table, fc_clx, lcb_clx, problems)
    if plc is None:
        return out

    count = (len(plc) - 4) // 12 if len(plc) >= 16 else 0
    if count > max_pieces:
        problems.append(f"doc: {count} pieces; the first {max_pieces} were read")
        out["truncated"] = True
        count = max_pieces
    positions = struct.unpack_from(f"<{count + 1}I", plc, 0) if count else ()
    descriptors = 4 * (count + 1)
    pieces: list[str] = []
    total = 0
    for index in range(count):
        start, stop = positions[index], positions[index + 1]
        if stop < start:
            problems.append(f"doc: piece {index} ends before it starts")
            continue
        length = stop - start
        # Its own flag. Sharing `truncated` with the piece cap above stopped
        # the walk after one piece whenever there were too many pieces.
        cut = total + length > max_chars
        if cut:
            length = max_chars - total
            out["truncated"] = True
        fc_raw = struct.unpack_from("<I", plc, descriptors + index * 8 + 2)[0]
        compressed = bool(fc_raw & 0x40000000)
        fc = fc_raw & 0x3FFFFFFF
        if compressed:
            offset, size = fc // 2, length
        else:
            offset, size = fc, length * 2
        if offset + size > len(word):
            problems.append(f"doc: piece {index} points past the WordDocument stream")
            size = max(0, len(word) - offset)
        raw = word[offset:offset + size]
        pieces.append(raw.decode("cp1252" if compressed else "utf-16-le", "replace"))
        total += length
        out["pieces"] += 1
        if cut:
            problems.append(f"doc: text past {max_chars} characters was not read")
            break
    out["text"] = "".join(pieces)
    return out


def fields(document_text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Every DDE field in the text, in the shape the OOXML reader returns,
    and what got in the way of reading them.

    Walked a run of text at a time, not a character at a time, and with the
    pieces of each instruction kept as a list until the field closes:
    appending to a string one character at a time is quadratic, and sixteen
    million characters inside one unclosed field is a file anybody can make.
    Nesting is capped for the same reason, since every open field holds one
    entry on the stack.
    """
    found: list[tuple[str, str]] = []
    notes: list[str] = []
    #: Open fields, innermost last: [instruction pieces, result pieces, state].
    stack: list[list[Any]] = []
    ignored = 0
    for token in _FIELD_MARKS.split(document_text):
        if token == FIELD_BEGIN:
            if len(stack) >= _MAX_NESTING:
                ignored += 1
                continue
            stack.append([[], [], "instr"])
        elif token == FIELD_SEPARATE:
            if stack:
                stack[-1][2] = "result"
        elif token == FIELD_END:
            if ignored:
                ignored -= 1
                continue
            if not stack:
                continue
            pieces, result, _ = stack.pop()
            words = _field_words("".join(pieces))
            if words:
                found.append((words[0], " ".join(words[1:2])))
            value = _quote_result(words)
            if stack and stack[-1][2] == "instr":
                stack[-1][0].append(value if value is not None else "".join(result))
        elif token and stack:
            stack[-1][0 if stack[-1][2] == "instr" else 1].append(token)
    if ignored or len(stack) >= _MAX_NESTING:
        notes.append(f"fields: nested deeper than {_MAX_NESTING}; the deeper ones were not read")
    out = []
    for name, server in found:
        if name.upper() not in _DDE_FIELDS:
            continue
        if len(out) >= _FIELDS_KEPT:
            notes.append("fields: more DDE fields than were kept, so the list is partial")
            break
        out.append({"field": name.upper(), "server": _display(server),
                    "command": _command_server(server), "part": "WordDocument"})
    return out, notes
