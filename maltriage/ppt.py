"""
PowerPoint 97-2003: the compound files hidden inside a `.ppt`.

A `.ppt` keeps nearly everything in one stream, `PowerPoint Document`, as a
tree of records: an eight byte header (version and instance packed into one
word, a type, a length), with version 0xF marking a container whose body is
more records. Two things this tool already reads elsewhere live there as
records too, which is why v0.6.4 could not see either in a `.ppt`:

  * **the VBA project**, and
  * **embedded objects**, Packager's `Ole10Native` among them.

Both are `ExOleObjStg` records, and each holds a compound file, usually
zlib-compressed behind a four byte declared size. So the reader here finds
those records, inflates them, and hands each compound file back to the OLE2
reader, which already knows what a VBA project and a package look like.

PowerPoint writes the zlib stream without its end marker. The oletools
`sample_with_vba.ppt` decompresses to exactly its declared 10,240 bytes and
then stops with no end, so reaching the declared size is success, and the
size is capped before it is trusted.
"""

from __future__ import annotations

import struct
import zlib
from typing import Any

EX_OLE_OBJ_STG = 0x1011
CONTAINER = 0x0F
COMPRESSED = 0x001
OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
_MAX_RECORDS = 1_000_000
_MAX_DEPTH = 32


def objects(stream: bytes, max_objects: int, max_bytes: int,
            problems: list[str]) -> list[bytes]:
    """Every compound file stored in an `ExOleObjStg` record, inflated.

    Walked iteratively, with a depth limit and a record budget: container
    lengths are fields in the file, and a container that claims to hold
    itself is a recursion on request.
    """
    found: list[bytes] = []
    pending = [(0, len(stream), 0)]
    records = 0
    while pending:
        start, end, depth = pending.pop()
        position = start
        while position + 8 <= end:
            records += 1
            if records > _MAX_RECORDS:
                problems.append(f"ppt: more than {_MAX_RECORDS} records; the walk stopped")
                return found
            packed, kind, length = struct.unpack_from("<HHI", stream, position)
            body_start = position + 8
            body_end = min(body_start + length, end)
            if packed & 0x0F == CONTAINER:
                if depth + 1 > _MAX_DEPTH:
                    problems.append(f"ppt: containers nested deeper than {_MAX_DEPTH}")
                else:
                    pending.append((body_start, body_end, depth + 1))
            elif kind == EX_OLE_OBJ_STG:
                if len(found) >= max_objects:
                    problems.append(f"ppt: more than {max_objects} embedded objects; "
                                    "the rest were not read")
                    return found
                data = _inflate(stream[body_start:body_end], packed >> 4,
                                max_bytes, problems)
                if data is not None and data[:8] == OLE_MAGIC:
                    found.append(data)
            # Always at least the header, so a zero length cannot stall.
            position = body_start + length
    return found


def _inflate(body: bytes, instance: int, max_bytes: int,
             problems: list[str]) -> bytes | None:
    if not instance & COMPRESSED:
        return body
    if len(body) < 4:
        problems.append("ppt: a compressed object has no declared size")
        return None
    declared = struct.unpack_from("<I", body, 0)[0]
    want = min(declared, max_bytes)
    try:
        # `max_length` bounds the output whatever the ratio: the declared
        # size is a field in the file and is not trusted with memory.
        data = zlib.decompressobj().decompress(body[4:], want)
    except zlib.error as exc:
        problems.append(f"ppt: an embedded object does not inflate: {exc}")
        return None
    if declared > max_bytes:
        problems.append(f"ppt: an embedded object declares {declared} bytes; "
                        f"the first {max_bytes} were read")
    elif len(data) < declared:
        problems.append(f"ppt: an embedded object inflates to {len(data)} of its "
                        f"declared {declared} bytes")
    return data
