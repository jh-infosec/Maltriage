"""
ELF structure: segments, sections, dynamic linkage and trailing data.

Standard library only. The header, the program header table and the section
header table are fixed-layout records that `struct` reads, and there is no
equivalent of pefile's accumulated knowledge of malformed real-world files to
buy. Pay a dependency where the format is genuinely hostile, not where it is
merely binary.
"""

from __future__ import annotations
import logging
import mmap
import struct
from pathlib import Path
from typing import Any

from .base import (RandomAccessExtractor, _share_budget, region_entropy,
                   safe_text)
from .config import config_int, config_list, config_ratio
from .models import mk_finding

log = logging.getLogger(__name__)


# ELF

ELF_MAGIC = b"\x7fELF"

ELF_TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
ELF_MACHINES = {
    0x02: "SPARC", 0x03: "386", 0x08: "MIPS", 0x14: "PPC", 0x15: "PPC64",
    0x16: "S390", 0x28: "ARM", 0x2A: "SUPERH", 0x32: "IA_64", 0x3E: "X86_64",
    0xB7: "AARCH64", 0xF3: "RISCV",
}
ELF_OSABI = {0: "SYSV", 1: "HPUX", 2: "NETBSD", 3: "LINUX", 6: "SOLARIS",
             9: "FREEBSD", 12: "OPENBSD"}
SEGMENT_TYPES = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE",
                 6: "PHDR", 7: "TLS", 0x6474E550: "GNU_EH_FRAME",
                 0x6474E551: "GNU_STACK", 0x6474E552: "GNU_RELRO"}
SECTION_TYPES = {0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
                 5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
                 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY"}

SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 0x1, 0x2, 0x4
PF_X, PF_W, PF_R = 0x1, 0x2, 0x4
PT_INTERP, PT_DYNAMIC, PT_LOAD, PT_NOTE = 3, 2, 1, 4
PT_GNU_STACK = 0x6474E551
SHT_SYMTAB, SHT_STRTAB, SHT_DYNAMIC, SHT_NOBITS, SHT_NOTE = 2, 3, 6, 8, 7

DT_NULL, DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH = 0, 1, 14, 15, 29

# Section-name families a mainstream toolchain emits, matched by prefix
# because each is an open set: one per DWARF section, one per relocated
# section, one per note, one per Go runtime structure. Enumerating them in
# config would mean a list that goes stale every toolchain release, and the
# cost of getting this wrong is `nonstandard_section_name` firing on
# essentially every binary in existence, which is a finding carrying no
# information at all.
SECTION_NAME_FAMILIES = (".debug", ".zdebug", ".rela", ".rel", ".note", ".gnu",
                         ".data.rel.ro", ".go.", ".llvm")
NT_GNU_BUILD_ID = 3


class ElfExtractor(RandomAccessExtractor):
    """ELF structure, parsed with `struct` and nothing else.

    The asymmetry with the PE extractor is deliberate and is argued in
    `architecture.md`: pay a dependency where the format is genuinely hostile,
    not where it is merely binary. An ELF header, a program header table and a
    section header table are fixed-layout records, and there is no equivalent
    of pefile's accumulated knowledge of malformed real-world files to buy.
    So this one has no optional import, never reports a missing parser, and
    works on a bare checkout.

    That also means every bound is this module's own. Nothing here trusts a
    count, an offset or a size read out of the file: the header supplies
    `e_phnum` and `e_shnum` as sixteen-bit numbers, `sh_offset` and `sh_size`
    as full words, and `e_shstrndx` as an index into a table it also
    describes. Each is clipped against the mapping and capped by config, and
    the section entropy budget is shared across the table rather than granted
    per section, for the reason the PE extractor learned: a per-item ceiling
    is not a bound when the item count is also a field in the file.
    """

    name = "elf"

    def applies_to(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> bool:
        return ctx.get("family") == "elf"

    def parse(self, path: Path, ctx: dict[str, Any],
              config: dict[str, Any]) -> dict[str, Any]:
        with path.open("rb") as handle:
            # Mapped rather than read. The random-access contract permits the
            # extractor to address the file; it does not permit holding it.
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
                return self._parse(data, ctx, config)

    # extraction

    def _parse(self, data, ctx: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
        problems: list[str] = []

        def attempt(label, fn, default):
            try:
                return fn()
            except Exception as exc:
                log.debug("elf %s failed: %s", label, exc)
                problems.append(f"{label}: {type(exc).__name__}: {exc}")
                return default

        size = len(data)
        if size < 64 or data[:4] != ELF_MAGIC:
            raise ValueError("not an ELF: the identification bytes are wrong")

        elf_class, elf_data, version, osabi = data[4], data[5], data[6], data[7]
        if elf_class not in (1, 2):
            raise ValueError(f"unknown ELF class {elf_class}")
        if elf_data not in (1, 2):
            raise ValueError(f"unknown ELF byte order {elf_data}")

        wide = elf_class == 2
        endian = "<" if elf_data == 1 else ">"
        header_fmt = f"{endian}16sHHIQQQIHHHHHH" if wide else f"{endian}16sHHIIIIIHHHHHH"
        header_size = 64 if wide else 52

        (_, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, _,
         e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
         e_shstrndx) = struct.unpack(header_fmt, bytes(data[:header_size]))

        info: dict[str, Any] = {
            "elf_class": "ELF64" if wide else "ELF32",
            "endianness": "little" if endian == "<" else "big",
            "os_abi": osabi,
            "os_abi_label": ELF_OSABI.get(osabi, "unknown"),
            "ident_version": version,
            "version": e_version,
            "type": e_type,
            "type_label": ELF_TYPES.get(e_type, "unknown"),
            "machine": e_machine,
            "machine_label": ELF_MACHINES.get(e_machine, "unknown"),
            "entry": e_entry,
        }

        # SHN_XINDEX: a file with more sections than `e_shnum` can express
        # puts the real count in the first section header and sets the field
        # to zero. Without this a legal file reports no section table at all
        # and earns `no_section_headers`, which is a medium.
        if e_shoff and not e_shnum:
            e_shnum, e_shstrndx = self._extended_counts(
                data, endian, wide, e_shoff, e_shentsize, e_shstrndx, size)

        info["segments"] = attempt(
            "segments",
            lambda: self._segments(data, endian, wide, e_phoff, e_phentsize,
                                   e_phnum, size, config), [])
        info["sections"] = attempt(
            "sections",
            lambda: self._sections(data, endian, wide, e_shoff, e_shentsize,
                                   e_shnum, e_shstrndx, size, config), [])

        # A header that claims a table the extractor could not read is not the
        # same fact as a header that claims none, and `e_shentsize = 0` -- one
        # two-byte field -- used to produce the first while the report stated
        # the second. The file still runs: the kernel never reads section
        # headers. So `stripped` said "no symbol table" about a binary with a
        # full one, and the entropy and packer-name findings vanished without
        # a word.
        info["section_headers_present"] = bool(info["sections"])
        if e_shoff and e_shnum and not info["sections"]:
            problems.append(
                f"sections: the header claims {e_shnum} section header(s) of "
                f"{e_shentsize} bytes at offset {e_shoff}, which could not be read")
        if e_phoff and e_phnum and not info["segments"]:
            problems.append(
                f"segments: the header claims {e_phnum} program header(s) of "
                f"{e_phentsize} bytes at offset {e_phoff}, which could not be read")

        info["entry_segment"] = _segment_for_address(info["segments"], e_entry)
        info["interpreter"] = attempt(
            "interpreter", lambda: self._interpreter(data, info["segments"], config), None)
        info.update(attempt("dynamic",
                            lambda: self._dynamic(data, endian, wide, info, size, config),
                            {"needed": [], "soname": None, "rpath": None,
                             "runpath": None, "dynamic_entries": 0,
                             "needed_truncated": False,
                             "dynamic_truncated": False}))
        info["build_id"] = attempt(
            "notes", lambda: self._build_id(data, endian, info["sections"], config), None)
        # None, not False, when the table was never read. "There is no symbol
        # table" and "I could not look" are different facts, and only the
        # first is a statement about the binary.
        info["stripped"] = (None if not info["sections"]
                            else not any(s["type"] == SHT_SYMTAB
                                         for s in info["sections"]))
        info["statically_linked"] = (
            None if not info["segments"] else
            info["interpreter"] is None
            and not any(s["type"] == PT_DYNAMIC for s in info["segments"]))
        info["trailing"] = attempt(
            "trailing",
            lambda: self._trailing(data, info, e_shoff, e_shentsize, e_shnum,
                                   size, config), None)

        # Every cap this extractor applies says so. The project's own rule,
        # learned from the YARA extractor: `truncated` is the field whose
        # whole job is to say that nothing was left out, and a cap that goes
        # unrecorded is a report that looks complete because nobody counted.
        info["sections_truncated"] = getattr(self, "_sections_truncated", False)
        info["segments_truncated"] = getattr(self, "_segments_truncated", False)
        info["names_truncated"] = getattr(self, "_names_truncated", False)
        for label, flag, cap in (
                ("sections", info["sections_truncated"], "elf_max_sections"),
                ("segments", info["segments_truncated"], "elf_max_segments"),
                ("names", info["names_truncated"], "elf_max_string_table_bytes"),
                ("dynamic", info.get("dynamic_truncated"), "elf_max_dynamic_entries"),
                ("needed", info.get("needed_truncated"), "elf_max_listed_names")):
            if flag:
                problems.append(f"{label}: the table was longer than {cap}, so it "
                                "was read only as far as that")

        starved = [s["name"] for s in info["sections"]
                   if s.get("entropy_skipped") == "budget_exhausted"]
        if starved:
            problems.append(
                "sections: the entropy budget ran out, so "
                f"{len(starved)} section(s) were not scored: {', '.join(starved[:8])}")
        if problems:
            info["parse_errors"] = problems
        return info

    @staticmethod
    def _extended_counts(data, endian, wide, shoff, entry_size, shstrndx, size):
        """Read SHN_XINDEX's real section count and name index out of shdr[0]."""
        expected = 64 if wide else 40
        if entry_size < expected or shoff + expected > size:
            return 0, shstrndx
        fmt = f"{endian}IIQQQQIIQQ" if wide else f"{endian}IIIIIIIIII"
        fields = struct.unpack(fmt, bytes(data[shoff:shoff + expected]))
        count, link = fields[5], fields[6]
        return count, link if shstrndx == 0xFFFF else shstrndx

    def _segments(self, data, endian, wide, offset, entry_size, count, size, config):
        """The program header table: what the loader will actually map.

        Capped and clipped. `e_phnum` is a sixteen-bit field, so a header
        under a hundred bytes can ask for 65535 entries, and `p_offset` and
        `p_filesz` are full words that need not describe a region of the file
        that exists.
        """
        expected = 56 if wide else 32
        if not offset or not count or entry_size < expected:
            return []
        fmt = f"{endian}IIQQQQQQ" if wide else f"{endian}IIIIIIII"
        limit = min(count, config_int(config, "elf_max_segments", 256))
        out = []
        self._segments_truncated = count > limit
        for index in range(limit):
            start = offset + index * entry_size
            if start + expected > size:
                break
            fields = struct.unpack(fmt, bytes(data[start:start + expected]))
            if wide:
                p_type, flags, p_offset, vaddr, _, filesz, memsz, align = fields
            else:
                # The 32-bit layout puts p_flags after p_memsz rather than
                # after p_type. Reading it as a narrow copy of the 64-bit
                # record produces a file that parses and lies about which
                # segments are executable.
                p_type, p_offset, vaddr, _, filesz, memsz, flags, align = fields
            out.append({
                "type": p_type,
                "type_label": SEGMENT_TYPES.get(p_type, f"0x{p_type:x}"),
                "flags": flags,
                "readable": bool(flags & PF_R),
                "writable": bool(flags & PF_W),
                "executable": bool(flags & PF_X),
                "offset": p_offset,
                "vaddr": vaddr,
                "file_size": filesz,
                "memory_size": memsz,
                "align": align,
                "in_file": p_offset < size,
            })
        return out

    def _sections(self, data, endian, wide, offset, entry_size, count,
                  shstrndx, size, config):
        """The section header table, with per-section entropy.

        The entropy budget is shared across the table for the same reason it
        is in the PE extractor: `elf_region_entropy_bytes` bounds one section
        and `e_shnum` bounds nothing, so a header can ask for a ceiling's
        worth of work sixty-five thousand times over. Allocation is by size so
        that reordering the table cannot starve a section.
        """
        expected = 64 if wide else 40
        if not offset or not count or entry_size < expected:
            return []
        fmt = f"{endian}IIQQQQIIQQ" if wide else f"{endian}IIIIIIIIII"
        limit = min(count, config_int(config, "elf_max_sections", 512))
        self._sections_truncated = count > limit

        raw = []
        for index in range(limit):
            start = offset + index * entry_size
            if start + expected > size:
                break
            (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
             sh_link, _, _, _) = struct.unpack(fmt, bytes(data[start:start + expected]))
            raw.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link))

        names, self._names_truncated = self._section_names(
            data, endian, wide, offset, entry_size, shstrndx, len(raw), size, config)

        # SHT_NOBITS occupies address space and no file space, so its offset
        # and size do not describe a region of the file and must not be scored.
        lengths = [0 if kind == SHT_NOBITS or sh_offset >= size
                   else max(0, min(sh_size, size - sh_offset))
                   for _, kind, _, _, sh_offset, sh_size, _ in raw]
        cap = config_int(config, "elf_region_entropy_bytes", 16777216)
        grants = _share_budget([min(length, cap) for length in lengths],
                               config_int(config, "elf_entropy_budget_bytes", 67108864))
        floor = config_int(config, "entropy_min_window_bytes", 256)

        out = []
        for index, (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                    sh_link) in enumerate(raw):
            length, grant = lengths[index], grants[index]
            skipped = None
            if sh_type == SHT_NOBITS:
                skipped = "no_file_bytes"
            elif length < floor:
                skipped = "too_short" if length else "no_bytes"
            elif grant < floor:
                skipped = "budget_exhausted"
            if skipped:
                entropy, ratio, sampled, scored = None, None, False, 0
            else:
                entropy, ratio, sampled, scored = region_entropy(
                    data, sh_offset, length, grant)
                if not scored:
                    skipped = "unreadable"
            out.append({
                "name": _name_at(names, sh_name),
                "type": sh_type,
                "type_label": SECTION_TYPES.get(sh_type, f"0x{sh_type:x}"),
                "flags": sh_flags,
                "alloc": bool(sh_flags & SHF_ALLOC),
                "writable": bool(sh_flags & SHF_WRITE),
                "executable": bool(sh_flags & SHF_EXECINSTR),
                "addr": sh_addr,
                "offset": sh_offset,
                "size": sh_size,
                "link": sh_link,
                "scored_bytes": scored,
                "entropy": entropy,
                "entropy_ratio": ratio,
                "entropy_sampled": sampled,
                "entropy_skipped": skipped,
            })
        return out

    def _section_names(self, data, endian, wide, offset, entry_size, shstrndx,
                       count, size, config):
        """The section name string table, returned whole rather than indexed.

        Names are resolved by scanning from each `sh_name` to the next NUL,
        not by walking the table and keying the offsets that follow one. GNU
        ld tail-merges `.shstrtab`, so most names are interior offsets:
        `.rela.plt\\0` also serves `.plt` at +5 and `.plt.got\\0` serves `.got`
        at +4. Indexing only post-NUL offsets mis-resolved at least one name
        in 3181 of 3185 real binaries on this machine, which made
        `nonstandard_section_name` fire on almost every ELF in existence and
        let a crafted `sh_name` pointing into the middle of a string evade
        `packer_section_name` entirely.
        """
        expected = 64 if wide else 40
        if shstrndx == 0 or shstrndx >= count:
            return b"", False
        start = offset + shstrndx * entry_size
        if start + expected > size:
            return b"", False
        fmt = f"{endian}IIQQQQIIQQ" if wide else f"{endian}IIIIIIIIII"
        fields = struct.unpack(fmt, bytes(data[start:start + expected]))
        kind, table_offset, table_size = fields[1], fields[4], fields[5]
        # A NOBITS section describes no file bytes, so following its offset
        # decodes section names out of whatever happens to be there -- the ELF
        # header itself, in the case that found this.
        if kind == SHT_NOBITS or table_offset >= size:
            return b"", False
        cap = config_int(config, "elf_max_string_table_bytes", 262144)
        available = min(table_size, size - table_offset)
        return bytes(data[table_offset:table_offset + min(available, cap)]), available > cap

    def _interpreter(self, data, segments, config):
        for segment in segments:
            if segment["type"] != PT_INTERP or not segment["in_file"]:
                continue
            length = min(segment["file_size"],
                         config_int(config, "elf_max_string_bytes", 4096),
                         len(data) - segment["offset"])
            blob = bytes(data[segment["offset"]:segment["offset"] + length])
            return blob.split(b"\x00")[0].decode("ascii", "replace") or None
        return None

    def _dynamic(self, data, endian, wide, info, size, config):
        """The dynamic table: what this binary loads and where it looks.

        `runpath` and `rpath` matter for triage because they say where the
        loader will search before the system paths, which is a hijack the file
        itself asks for.
        """
        empty = {"needed": [], "soname": None, "rpath": None, "runpath": None,
                 "dynamic_entries": 0, "needed_truncated": False,
                 "dynamic_truncated": False}
        section = next((s for s in info["sections"] if s["type"] == SHT_DYNAMIC), None)
        segment = next((s for s in info["segments"]
                        if s["type"] == PT_DYNAMIC and s["in_file"]), None)
        if section is not None and section["offset"] < size:
            offset, length, link = section["offset"], section["size"], section["link"]
        elif segment is not None:
            offset, length, link = segment["offset"], segment["file_size"], None
        else:
            return empty

        strings = self._dynamic_strings(data, info, link, size, config)
        word = f"{endian}QQ" if wide else f"{endian}II"
        step = 16 if wide else 8
        length = min(length, size - offset)
        cap = config_int(config, "elf_max_dynamic_entries", 1024)
        available = length // step
        limit = min(available, cap)
        name_cap = config_int(config, "elf_max_listed_names", 128)

        # Whether the walk ended because the file said so. Stopping at DT_NULL
        # is the table ending; stopping at the cap is this extractor giving
        # up. Reporting the first as the second made a five-entry table
        # announce itself as truncated on every ordinary binary.
        terminated = False
        needed, soname, rpath, runpath, seen, dropped = [], None, None, None, 0, False
        for index in range(limit):
            tag, value = struct.unpack(
                word, bytes(data[offset + index * step:offset + (index + 1) * step]))
            seen += 1
            if tag == DT_NULL:
                terminated = True
                break
            if tag == DT_NEEDED:
                if len(needed) < name_cap:
                    needed.append(_read_string(strings, value, config))
                else:
                    dropped = True
            elif tag == DT_SONAME:
                soname = _read_string(strings, value, config)
            elif tag == DT_RPATH:
                rpath = _read_string(strings, value, config)
            elif tag == DT_RUNPATH:
                runpath = _read_string(strings, value, config)
        return {"needed": [n for n in needed if n], "soname": soname,
                "rpath": rpath, "runpath": runpath, "dynamic_entries": seen,
                "needed_truncated": dropped,
                "dynamic_truncated": not terminated and seen >= cap}

    def _dynamic_strings(self, data, info, link, size, config):
        """The `.dynstr` bytes, found through `sh_link` or by name."""
        target = None
        if link is not None and 0 < link < len(info["sections"]):
            target = info["sections"][link]
        if target is None:
            target = next((s for s in info["sections"] if s["name"] == ".dynstr"), None)
        if target is None or target["offset"] >= size:
            return b""
        length = min(target["size"], size - target["offset"],
                     config_int(config, "elf_max_string_table_bytes", 262144))
        return bytes(data[target["offset"]:target["offset"] + length])

    def _build_id(self, data, endian, sections, config):
        """The GNU build id, which is the closest ELF has to a PDB path."""
        section = next((s for s in sections
                        if s["type"] == SHT_NOTE and "build-id" in s["name"]), None)
        if section is None or not section["scored_bytes"] and not section["size"]:
            return None
        offset, length = section["offset"], min(section["size"], 4096)
        if offset + 12 > len(data):
            return None
        name_size, desc_size, kind = struct.unpack(
            f"{endian}III", bytes(data[offset:offset + 12]))
        if kind != NT_GNU_BUILD_ID or desc_size > 64:
            return None
        start = offset + 12 + ((name_size + 3) // 4) * 4
        if start + desc_size > offset + length or start + desc_size > len(data):
            return None
        return bytes(data[start:start + desc_size]).hex()

    def _trailing(self, data, info, shoff, shentsize, shnum, size, config):
        """Bytes past everything the file describes.

        The ELF counterpart of a PE overlay, and computed the same way: the
        end of the last thing any header accounts for, subtracted from the
        size of the file. Only regions that are actually inside the file
        count, or a forged offset would push the boundary past the end and
        report no trailing data at all.
        """
        end = 0
        for section in info["sections"]:
            if section["type"] == SHT_NOBITS or section["offset"] >= size:
                continue
            end = max(end, min(section["offset"] + section["size"], size))
        for segment in info["segments"]:
            if not segment["in_file"]:
                continue
            end = max(end, min(segment["offset"] + segment["file_size"], size))
        if shoff and shnum and shoff < size:
            end = max(end, min(shoff + shentsize * shnum, size))
        if end >= size:
            return None

        length = size - end
        cap = config_int(config, "elf_region_entropy_bytes", 16777216)
        floor = config_int(config, "entropy_min_window_bytes", 256)
        entropy, ratio, sampled, _ = (region_entropy(data, end, length, cap)
                                      if length >= floor else (None, None, False, 0))
        return {
            "offset": end,
            "size": length,
            "fraction_of_file": round(length / size, 4) if size else 0.0,
            "entropy": entropy,
            "entropy_ratio": ratio,
            "entropy_sampled": sampled,
        }

    # findings

    def findings(self, data: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        """The same tiering discipline the PE extractor is held to.

        Nothing here is `high`. `GATE_SEVERITY` is medium, so a finding earns
        medium only if a file deserves a human because of it alone. Being
        stripped and being statically linked are `info`, however unusual they
        may look, because release builds are stripped and Go binaries are
        static: a level that fires on most of a distribution is a level that
        tells an analyst nothing.
        """
        out: list[dict[str, Any]] = []
        out.extend(self._segment_findings(data, config))
        out.extend(self._section_findings(data, config))
        out.extend(self._linkage_findings(data, config))
        return out

    def _segment_findings(self, data, config):
        out = []
        segments = data.get("segments") or []
        # PT_LOAD only. PT_GNU_STACK is a flags-only marker rather than a
        # mapping, and `gcc -z execstack` sets it on request, so counting it
        # here called an ordinary build "a loadable segment mapped writable
        # and executable" -- both halves untrue, at medium, in somebody's CI.
        wx = [s for s in segments
              if s["type"] == PT_LOAD and s["writable"] and s["executable"]]
        if wx:
            out.append(mk_finding(self.name, "writable_executable_segment",
                f"{len(wx)} loadable segment(s) are mapped both writable and "
                "executable, which no mainstream toolchain emits and which "
                "self-modifying code needs", "medium"))

        if any(s["type"] == PT_GNU_STACK and s["executable"] for s in segments):
            out.append(mk_finding(self.name, "executable_stack",
                "the stack is marked executable, which a modern toolchain only "
                "does when asked", "low"))

        loadable = [s for s in segments if s["type"] == PT_LOAD]
        entry = data.get("entry")
        if loadable and entry:
            holder = next((s for s in loadable
                           if s["vaddr"] <= entry < s["vaddr"] + s["memory_size"]), None)
            if holder is None:
                out.append(mk_finding(self.name, "entry_point_outside_segments",
                    f"the entry point at {hex(entry)} is not inside any loadable "
                    "segment, so the file cannot start the way its header says",
                    "medium"))
            elif not holder["executable"]:
                out.append(mk_finding(self.name, "entry_point_not_executable",
                    f"the entry point at {hex(entry)} is in a segment that is not "
                    "mapped executable", "medium"))
        return out

    def _section_findings(self, data, config):
        out = []
        sections = data.get("sections") or []
        if not data.get("section_headers_present"):
            out.append(mk_finding(self.name, "no_section_headers",
                "the section header table is absent, which every mainstream "
                "toolchain emits and several packers remove", "medium"))
            return out

        threshold = config_ratio(config, "elf_section_entropy_ratio", 0.94)
        # Only sections the loader maps, and only those it maps writable or
        # executable. Measured against 7119 real binaries, scoring every
        # section fired this medium on 8.5% of them: 548 from `.debug_*`
        # alone, because DWARF is dense, and the rest from read-only tables --
        # a 256-byte byte-permutation table reaches a ratio above 1.0 while
        # being the most ordered data there is, since the reference is an
        # estimate of what a random *sample* reaches. Debug data is not mapped
        # and a payload has to be mapped to run, which is the line drawn here.
        hot = [s for s in sections
               if s.get("entropy_ratio") is not None and s["entropy_ratio"] >= threshold
               and s["alloc"] and (s["writable"] or s["executable"])]
        if hot:
            out.append(mk_finding(self.name, "section_entropy_high",
                "high-entropy section(s): " + ", ".join(
                    f"{s['name']} at {s['entropy_ratio']} of random" for s in hot) +
                ", consistent with a packed, compressed or encrypted section",
                "medium",
                evidence=[{"name": f"{s['name']}.entropy_ratio",
                           "value": s["entropy_ratio"]} for s in hot],
                discriminator=", ".join(s["name"] for s in hot)))

        packers = {p.lower() for p in config_list(config, "elf_packer_sections", [])}
        standard = {p.lower() for p in config_list(config, "elf_standard_sections", [])}
        named = [s["name"] for s in sections if s["name"].lower() in packers]
        if named:
            out.append(mk_finding(self.name, "packer_section_name",
                f"section name(s) {', '.join(named)} match a known packer's "
                "conventional layout", "medium"))

        odd = [s["name"] for s in sections
               if s["name"] and s["name"].lower() not in standard
               and s["name"].lower() not in packers
               and not s["name"].startswith(SECTION_NAME_FAMILIES)]
        if odd:
            out.append(mk_finding(self.name, "nonstandard_section_name",
                f"section name(s) {', '.join(odd[:8])} are not names a mainstream "
                "toolchain emits", "low"))
        return out

    def _linkage_findings(self, data, config):
        out = []
        for key, tag in (("runpath", "DT_RUNPATH"), ("rpath", "DT_RPATH")):
            value = data.get(key)
            if value:
                out.append(mk_finding(self.name, f"{key}_set",
                    f"{tag} is '{value}', so the loader searches there before the "
                    "system paths and a writable entry in it is a hijack the "
                    "binary asks for", "low"))

        trailing = data.get("trailing")
        if trailing:
            large = config_int(config, "elf_large_trailing_bytes", 1048576)
            if trailing["size"] >= large:
                out.append(mk_finding(self.name, "large_trailing_data",
                    f"{trailing['size']} bytes past everything the headers "
                    f"account for ({trailing['fraction_of_file']} of the file), "
                    "which no loader maps", "low"))
            else:
                out.append(mk_finding(self.name, "trailing_data_present",
                    f"{trailing['size']} bytes past everything the headers "
                    "account for", "info"))

        if data.get("stripped"):
            out.append(mk_finding(self.name, "stripped_symbols",
                "no symbol table, which is ordinary for a release build and is "
                "recorded because it bounds what any later analysis can say",
                "info"))
        if data.get("statically_linked"):
            out.append(mk_finding(self.name, "statically_linked",
                "no interpreter and no dynamic section, so nothing is resolved "
                "at load time", "info"))
        if data.get("build_id"):
            out.append(mk_finding(self.name, "build_id_present",
                f"GNU build id {data['build_id']}", "info"))
        return out



def _name_at(table: bytes, offset: int) -> str:
    """One name out of a string table, read from `offset` to the next NUL."""
    if not 0 <= offset < len(table):
        return f"<name+{offset}>" if offset >= 0 else "<name+invalid>"
    end = table.find(b"\x00", offset)
    return safe_text(table[offset:end if end >= 0 else len(table)], 256)


def _read_string(blob: bytes, offset: int, config: dict[str, Any]) -> str | None:
    """One NUL-terminated string out of a table, bounded.

    The offset comes from a dynamic entry and the table from a section header,
    so neither is trustworthy and both are the file's own account of itself.
    """
    if offset < 0 or offset >= len(blob):
        return None
    cap = config_int(config, "elf_max_string_bytes", 4096)
    end = blob.find(b"\x00", offset, offset + cap)
    end = end if end >= 0 else min(offset + cap, len(blob))
    return safe_text(blob[offset:end]) or None


def _segment_for_address(segments: list[dict[str, Any]], address: int) -> str | None:
    for segment in segments:
        if segment["type"] != PT_LOAD:
            continue
        if segment["vaddr"] <= address < segment["vaddr"] + segment["memory_size"]:
            return segment["type_label"]
    return None
