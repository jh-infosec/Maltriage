"""
Disk images: the files inside an `.iso` or an `.img`.

When Windows started marking files from the internet, a disk image was the
way round it. Windows mounts one on a double-click, and before November
2022 the files inside did not inherit the mark, so a shortcut or a DLL in an
image ran without the warning it would have had in a ZIP. The shape that
followed was so regular it has a name in every vendor's write-ups: an image
whose one visible file is a shortcut, with the DLL or script it starts
beside it, hidden.

Two formats are opened here, both by reading their own structures and
nothing else:

  * **ISO 9660**, with the Joliet extension Windows writes long names in.
    Volume descriptors from sector 16, then a walk of the directory tree.
    A file whose "existence" flag is set is one Explorer does not show.
  * **FAT12, FAT16 and FAT32**, the `.img` a floppy or a USB stick image
    is. The boot sector's parameters, the allocation table, and directories
    with their long names. The hidden attribute is the same one Explorer
    reads.

Three more are recognised and not opened: UDF (a pure UDF image has no ISO
9660 tree to fall back on), VHD and VHDX. Each would need a reader of its own,
NTFS for most VHDs, and saying so is better than an image that looks empty.

Nothing a volume says about itself is believed. Every offset, size, cluster
number and count is checked against the image before it is used, cluster
chains and directory trees are walked with a visited set and a cap, and the
bytes of a member are read through `ExtentReader`, which can only reach the
image's own extents. Members are handed to `archives.py`, which stages them
under the same budget as a ZIP's.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Callable, Iterator

SECTOR = 2048
ISO_START = 16 * SECTOR
_MAX_DESCRIPTORS = 64
_MAX_DIRECTORIES = 4096
_MAX_DIRECTORY_BYTES = 1 << 20
_MAX_DEPTH = 32
_MAX_FAT_BYTES = 32 << 20
_JOLIET = (b"%/@", b"%/C", b"%/E")

Reader = Callable[[int, int], bytes]


@dataclass
class Member:
    """One file in an image, and where its bytes are."""

    name: str
    size: int
    extents: list[tuple[int, int]] = field(default_factory=list)
    hidden: bool = False


class ExtentReader:
    """A file-like view of a member's extents in an open image.

    `read` never goes past the extents it was given or past the image, and
    closing it leaves the image open: every member of one image is read
    through the one handle.
    """

    def __init__(self, handle, extents: list[tuple[int, int]], image_size: int):
        self._handle = handle
        self._extents = [(start, max(0, min(length, image_size - start)))
                         for start, length in extents if 0 <= start < image_size]
        self._index = 0
        self._offset = 0

    def read(self, size: int = -1) -> bytes:
        out = bytearray()
        while self._index < len(self._extents) and (size < 0 or len(out) < size):
            start, length = self._extents[self._index]
            left = length - self._offset
            if left <= 0:
                self._index += 1
                self._offset = 0
                continue
            want = left if size < 0 else min(left, size - len(out))
            self._handle.seek(start + self._offset)
            block = self._handle.read(want)
            if not block:
                self._index = len(self._extents)
                break
            out += block
            self._offset += len(block)
        return bytes(out)

    def close(self) -> None:
        """The image stays open; it belongs to whoever opened it."""

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _u16(data: bytes, at: int) -> int:
    return struct.unpack_from("<H", data, at)[0]


def _u32(data: bytes, at: int) -> int:
    return struct.unpack_from("<I", data, at)[0]


# ISO 9660


def _iso_name(raw: bytes, joliet: bool) -> str:
    text = raw.decode("utf-16-be", "replace") if joliet else raw.decode("ascii", "replace")
    if ";" in text:
        text = text[:text.rindex(";")]
    return text.rstrip(".") if not joliet else text


def iso_members(read: Reader, size: int, problems: list[str]) -> Iterator[Member]:
    """Every file in an ISO 9660 image, from the Joliet tree when there is one."""
    primary = joliet = None
    for index in range(_MAX_DESCRIPTORS):
        at = ISO_START + index * SECTOR
        if at + SECTOR > size:
            break
        block = read(at, SECTOR)
        if len(block) < SECTOR or block[1:6] != b"CD001":
            break
        if block[0] == 1 and primary is None:
            primary = block
        elif block[0] == 2 and block[88:91] in _JOLIET and joliet is None:
            joliet = block
        elif block[0] == 255:
            break
    chosen = joliet or primary
    if chosen is None:
        problems.append("iso: no primary volume descriptor")
        return
    block_size = _u16(chosen, 128)
    if block_size not in (512, 1024, 2048):
        problems.append(f"iso: a logical block of {block_size} bytes; 2048 was assumed")
        block_size = SECTOR
    root = chosen[156:156 + 34]
    yield from _iso_tree(read, size, block_size, _u32(root, 2), _u32(root, 10),
                         joliet is not None, problems)


def _iso_tree(read: Reader, size: int, block_size: int, root_lba: int, root_length: int,
              joliet: bool, problems: list[str]) -> Iterator[Member]:
    pending = [("", root_lba, root_length, 0)]
    seen: set[int] = set()
    directories = 0
    while pending:
        prefix, lba, length, depth = pending.pop()
        if lba in seen:
            problems.append("iso: a directory appears twice in the tree; it was read once")
            continue
        seen.add(lba)
        directories += 1
        if directories > _MAX_DIRECTORIES or depth > _MAX_DEPTH:
            problems.append(f"iso: more than {_MAX_DIRECTORIES} directories, or nested deeper "
                            f"than {_MAX_DEPTH}; the rest were not read")
            return
        start = lba * block_size
        if length > _MAX_DIRECTORY_BYTES:
            problems.append(f"iso: a directory of {length} bytes; the first "
                            f"{_MAX_DIRECTORY_BYTES} were read")
            length = _MAX_DIRECTORY_BYTES
        if start >= size:
            problems.append("iso: a directory points past the end of the image")
            continue
        data = read(start, min(length, size - start))
        at = 0
        while at < len(data):
            record = data[at]
            if record == 0:
                # Records do not cross a sector; the rest of this one is padding.
                at = (at // SECTOR + 1) * SECTOR
                continue
            if record < 34 or at + record > len(data):
                problems.append("iso: a malformed directory record; the rest of the directory was not read")
                break
            entry = data[at:at + record]
            at += record
            name_length = entry[32]
            raw = entry[33:33 + name_length]
            if name_length == 1 and raw in (b"\x00", b"\x01"):
                continue
            name = _iso_name(raw, joliet)
            extent, data_length, flags = _u32(entry, 2), _u32(entry, 10), entry[25]
            if flags & 0x02:
                pending.append((prefix + name + "/", extent, data_length, depth + 1))
                continue
            offset = extent * block_size
            if offset + data_length > size:
                problems.append(f"iso: {prefix + name!r} runs past the end of the image")
            yield Member(prefix + name, data_length, [(offset, data_length)],
                         hidden=bool(flags & 0x01))


# FAT


def _short_name(entry: bytes) -> str:
    """An 8.3 name, in the case Windows shows it: byte 12 carries two flags
    for a stem and an extension stored upper case but meant lower."""
    stem = entry[0:8].rstrip(b" ")
    if stem[:1] == b"\x05":
        stem = b"\xe5" + stem[1:]
    ext = entry[8:11].rstrip(b" ")
    text = stem.decode("cp437", "replace")
    suffix = ext.decode("cp437", "replace")
    if entry[12] & 0x08:
        text = text.lower()
    if entry[12] & 0x10:
        suffix = suffix.lower()
    return text + ("." + suffix if suffix else "")


def _lfn_checksum(entry: bytes) -> int:
    total = 0
    for byte in entry[0:11]:
        total = (((total & 1) << 7) + (total >> 1) + byte) & 0xFF
    return total


class _Fat:
    def __init__(self, read: Reader, size: int, problems: list[str]):
        self.read, self.size, self.problems = read, size, problems
        boot = read(0, 512)
        if len(boot) < 512:
            raise ValueError("fat: the boot sector is cut short")
        self.bps = _u16(boot, 11)
        self.spc = boot[13]
        reserved, fats, root_entries = _u16(boot, 14), boot[16], _u16(boot, 17)
        total = _u16(boot, 19) or _u32(boot, 32)
        fat_sectors = _u16(boot, 22) or _u32(boot, 36)
        if (self.bps not in (512, 1024, 2048, 4096) or self.spc == 0
                or self.spc & (self.spc - 1) or not 1 <= fats <= 4 or reserved == 0
                or fat_sectors == 0 or total == 0):
            raise ValueError("fat: the boot sector's parameters are not a FAT volume")
        root_sectors = (root_entries * 32 + self.bps - 1) // self.bps
        self.data_start = (reserved + fats * fat_sectors + root_sectors) * self.bps
        clusters = max(0, (total - reserved - fats * fat_sectors - root_sectors) // self.spc)
        self.clusters = clusters
        self.bits = 12 if clusters < 4085 else 16 if clusters < 65525 else 32
        self.cluster_bytes = self.bps * self.spc
        fat_start, fat_length = reserved * self.bps, fat_sectors * self.bps
        if fat_length > _MAX_FAT_BYTES:
            problems.append(f"fat: an allocation table of {fat_length} bytes; the first "
                            f"{_MAX_FAT_BYTES} were read, so chains past it end early")
            fat_length = _MAX_FAT_BYTES
        self.table = read(fat_start, fat_length)
        if self.bits == 32:
            self.root = None
            self.root_cluster = _u32(boot, 44)
        else:
            root_start = (reserved + fats * fat_sectors) * self.bps
            self.root = read(root_start, root_entries * 32)
            self.root_cluster = 0

    def next(self, cluster: int) -> int | None:
        if self.bits == 12:
            at = cluster + cluster // 2
            if at + 2 > len(self.table):
                return None
            pair = _u16(self.table, at)
            value = pair >> 4 if cluster & 1 else pair & 0xFFF
            end = 0xFF8
        elif self.bits == 16:
            at = cluster * 2
            if at + 2 > len(self.table):
                return None
            value, end = _u16(self.table, at), 0xFFF8
        else:
            at = cluster * 4
            if at + 4 > len(self.table):
                return None
            value, end = _u32(self.table, at) & 0x0FFFFFFF, 0x0FFFFFF8
        # A value past the last cluster is caught by `chain`, which checks
        # every cluster it is given, not only the ones this returns.
        if value < 2 or value >= end:
            return None
        return value

    def chain(self, first: int, limit: int) -> list[int]:
        """The clusters of a chain, stopping at its end, a loop, a cluster
        outside the volume, or `limit`, whichever comes first."""
        out: list[int] = []
        seen: set[int] = set()
        cluster: int | None = first
        while cluster is not None and 2 <= cluster < self.clusters + 2 and len(out) < limit:
            if cluster in seen:
                self.problems.append("fat: a cluster chain loops; it was followed once")
                break
            seen.add(cluster)
            out.append(cluster)
            cluster = self.next(cluster)
        return out

    def offset(self, cluster: int) -> int:
        return self.data_start + (cluster - 2) * self.cluster_bytes

    def extents(self, clusters: list[int], length: int) -> list[tuple[int, int]]:
        out: list[tuple[int, int]] = []
        left = length
        for cluster in clusters:
            if left <= 0:
                break
            take = min(self.cluster_bytes, left)
            start = self.offset(cluster)
            if out and out[-1][0] + out[-1][1] == start:
                out[-1] = (out[-1][0], out[-1][1] + take)
            else:
                out.append((start, take))
            left -= take
        return out

    def directory(self, cluster: int) -> bytes:
        if cluster == 0 and self.root is not None:
            return self.root
        limit = max(1, _MAX_DIRECTORY_BYTES // self.cluster_bytes)
        clusters = self.chain(cluster, limit)
        return b"".join(self.read(start, length)
                        for start, length in self.extents(clusters, len(clusters) * self.cluster_bytes))


def fat_members(read: Reader, size: int, problems: list[str]) -> Iterator[Member]:
    """Every file in a FAT volume, under its long name when it has one."""
    try:
        volume = _Fat(read, size, problems)
    except ValueError as exc:
        problems.append(str(exc))
        return
    pending = [("", volume.root_cluster, 0)]
    seen: set[int] = set()
    directories = 0
    while pending:
        prefix, cluster, depth = pending.pop()
        if cluster in seen:
            problems.append("fat: a directory appears twice in the tree; it was read once")
            continue
        seen.add(cluster)
        directories += 1
        if directories > _MAX_DIRECTORIES or depth > _MAX_DEPTH:
            problems.append(f"fat: more than {_MAX_DIRECTORIES} directories, or nested deeper "
                            f"than {_MAX_DEPTH}; the rest were not read")
            return
        data = volume.directory(cluster)
        long_parts: list[tuple[int, int, bytes]] = []
        for at in range(0, len(data) - 31, 32):
            entry = data[at:at + 32]
            first, attributes = entry[0], entry[11]
            if first == 0:
                break
            if first == 0xE5:
                long_parts = []
                continue
            if attributes & 0x3F == 0x0F:
                if first & 0x40:
                    long_parts = []
                long_parts.append((first & 0x1F, entry[13],
                                   entry[1:11] + entry[14:26] + entry[28:32]))
                continue
            if attributes & 0x08:
                long_parts = []
                continue
            name = _short_name(entry)
            checksum = _lfn_checksum(entry)
            if long_parts and all(part[1] == checksum for part in long_parts):
                raw = b"".join(part[2] for part in sorted(long_parts))
                text = raw.decode("utf-16-le", "replace")
                text = text.split("\x00", 1)[0].replace("￿", "")
                if text:
                    name = text
            long_parts = []
            if name in (".", ".."):
                continue
            start = _u16(entry, 26) | (_u16(entry, 20) << 16 if volume.bits == 32 else 0)
            if attributes & 0x10:
                if start >= 2:
                    pending.append((prefix + name + "/", start, depth + 1))
                continue
            length = _u32(entry, 28)
            needed = (length + volume.cluster_bytes - 1) // volume.cluster_bytes
            clusters = volume.chain(start, needed) if length else []
            if len(clusters) < needed:
                problems.append(f"fat: the cluster chain of {prefix + name!r} ends before its size")
            yield Member(prefix + name, length, volume.extents(clusters, length),
                         hidden=bool(attributes & 0x02))


READERS = {"iso": iso_members, "fat": fat_members}
