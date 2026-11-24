"""
Windows icons: the image frames an `.ico` declares.

An icon is a six byte header, a directory of sixteen byte entries, and the
images the entries point at. Since Vista the large frames are PNG files, so
an icon is a mostly plain bitmap file with compressed regions in it, which
is the shape `entropy_hotspot` looks for. Install media carries one in its
root as `autorun.ico`, and two of four real ISOs measured in v0.7.6 were held
at the gate by nothing else.

Its magic number is four bytes, `00 00 01 00`, too weak to call a file an
icon on, so `is_icon` checks the directory against the file before the
signature counts: a count of frames, a zero reserved byte in every entry,
and every frame inside the file. The frames are then published as regions
the format declares, and a hot window inside one is the frame's compression,
not a payload's.
"""

from __future__ import annotations

import struct

_MAX_FRAMES = 255


def frames(header: bytes, size: int) -> list[tuple[int, int]] | None:
    """Every frame's (offset, length), or `None` if this is not an icon."""
    if len(header) < 6:
        return None
    reserved, kind, count = struct.unpack_from("<HHH", header, 0)
    if reserved != 0 or kind != 1 or not 1 <= count <= _MAX_FRAMES:
        return None
    table_end = 6 + 16 * count
    if len(header) < table_end:
        return None
    out = []
    for index in range(count):
        entry = header[6 + 16 * index:6 + 16 * (index + 1)]
        planes, length, offset = struct.unpack_from("<H", entry, 4)[0], *struct.unpack_from("<II", entry, 8)
        if entry[3] != 0 or planes > 1 or length == 0:
            return None
        if offset < table_end or offset + length > size:
            return None
        out.append((offset, length))
    return out


def is_icon(header: bytes, size: int) -> bool:
    return frames(header, size) is not None
