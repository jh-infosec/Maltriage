"""
Synthetic fixtures for maltriage.

Every fixture in this project is generated in-process. No malicious sample is
required to develop or test the tool, and none should ever be committed. That
promise is why `build_pe` and `build_elf` exist: testing a parser needs a
valid subject, so one is constructed byte by byte out of the structures the
format defines.

What they produce is structurally valid and contains no code. Section bodies
are padding, entry points address bytes that do nothing, and no import thunk
or dynamic entry resolves to anything at runtime.
"""

import os
import struct
from pathlib import Path

# Synthetic PE construction
#
# v0.2 needs a valid PE to test a PE parser against, and this project does not
# use real samples. So one is built here, byte by byte, out of the structures
# the format defines.
#
# What is produced is structurally valid and contains no code. Section bodies
# are padding, the entry point addresses a byte that does nothing, and there
# is no import thunk that resolves to anything at runtime. It is a file shaped
# like an executable, which is all a static parser needs and all this project
# is willing to ship.
#
# `build_pe` is the single source of every PE fixture. Variants come from its
# arguments rather than from separate builders, so a fixture that drifts from
# the format drifts for every test at once and is caught immediately.

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
PE_HEADER_OFFSET = 0x80

MACHINE_I386 = 0x014C
MACHINE_AMD64 = 0x8664

# Section characteristics, as the format defines them.
SECTION_CODE = 0x60000020    # code, executable, readable
SECTION_RDATA = 0x40000040   # initialised data, readable
SECTION_DATA = 0xC0000040    # initialised data, readable, writable
SECTION_RWX = 0xE0000020     # code, executable, readable AND writable


def _align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def _import_blob(base_rva, imports):
    """Build a complete import directory destined for `base_rva`.

    Returns the blob and the size of its descriptor array, which is what the
    data directory entry records.

    Layout is the descriptor array, then an import name table and an import
    address table per DLL, then the DLL name strings, then the hint/name
    entries. Every internal pointer is an RVA, which is why the blob has to
    know where it will be placed before it can be built.
    """
    dlls = list(imports.items())
    descriptor_size = (len(dlls) + 1) * 20  # null-terminated array

    cursor = descriptor_size
    int_offset, iat_offset, name_offset = {}, {}, {}
    for dll, funcs in dlls:
        int_offset[dll] = cursor
        cursor += (len(funcs) + 1) * 4
    for dll, funcs in dlls:
        iat_offset[dll] = cursor
        cursor += (len(funcs) + 1) * 4
    for dll, _ in dlls:
        name_offset[dll] = cursor
        cursor += len(dll) + 1
        cursor += cursor % 2

    hint_offset = {}
    for dll, funcs in dlls:
        for func in funcs:
            hint_offset[(dll, func)] = cursor
            cursor += 2 + len(func) + 1
            cursor += cursor % 2

    blob = bytearray(cursor)

    for index, (dll, _) in enumerate(dlls):
        struct.pack_into(
            "<IIIII", blob, index * 20,
            base_rva + int_offset[dll],   # OriginalFirstThunk
            0,                            # TimeDateStamp
            0,                            # ForwarderChain
            base_rva + name_offset[dll],  # Name
            base_rva + iat_offset[dll],   # FirstThunk
        )

    for dll, funcs in dlls:
        for slot, func in enumerate(funcs):
            thunk = base_rva + hint_offset[(dll, func)]
            struct.pack_into("<I", blob, int_offset[dll] + slot * 4, thunk)
            struct.pack_into("<I", blob, iat_offset[dll] + slot * 4, thunk)

    for dll, _ in dlls:
        blob[name_offset[dll]:name_offset[dll] + len(dll)] = dll.encode()

    for (_, func), offset in hint_offset.items():
        blob[offset + 2:offset + 2 + len(func)] = func.encode()

    return bytes(blob), descriptor_size


IMAGE_BASE = 0x400000

DIRECTORY_IMPORT = 1
DIRECTORY_SECURITY = 4
DIRECTORY_DEBUG = 6
DIRECTORY_TLS = 9

TLS_DIRECTORY_SIZE = 24
DEBUG_DIRECTORY_SIZE = 28
DEBUG_TYPE_CODEVIEW = 2


def _tls_blob(base_rva, callbacks):
    """IMAGE_TLS_DIRECTORY32 followed by its callback array.

    The array is what the parser actually walks, and it is null-terminated
    rather than counted, which is why a walker needs a cap: the terminator is
    a value in the file and a hostile file can decline to supply one.
    """
    array = base_rva + TLS_DIRECTORY_SIZE
    blob = bytearray(TLS_DIRECTORY_SIZE + (len(callbacks) + 1) * 4)
    struct.pack_into("<IIIIII", blob, 0,
                     IMAGE_BASE + base_rva,     # StartAddressOfRawData
                     IMAGE_BASE + base_rva,     # EndAddressOfRawData
                     IMAGE_BASE + base_rva,     # AddressOfIndex
                     IMAGE_BASE + array,        # AddressOfCallBacks
                     0, 0)                      # SizeOfZeroFill, Characteristics
    for slot, callback in enumerate(callbacks):
        struct.pack_into("<I", blob, TLS_DIRECTORY_SIZE + slot * 4, callback)
    return bytes(blob)


def _debug_blob(base_rva, base_pointer, pdb_path):
    """IMAGE_DEBUG_DIRECTORY plus the CV_INFO_PDB70 record it points at.

    The record carries both an RVA and a file pointer to the same bytes, and
    a parser that trusts one without the other is a parser this fixture
    should be able to catch out.
    """
    record = (b"RSDS" + bytes(16) + struct.pack("<I", 1)
              + pdb_path.encode() + b"\x00")
    blob = bytearray(DEBUG_DIRECTORY_SIZE + len(record))
    struct.pack_into("<IIHHIIII", blob, 0,
                     0, 0, 0, 0,                          # flags, stamp, version
                     DEBUG_TYPE_CODEVIEW, len(record),
                     base_rva + DEBUG_DIRECTORY_SIZE,     # AddressOfRawData
                     base_pointer + DEBUG_DIRECTORY_SIZE)  # PointerToRawData
    blob[DEBUG_DIRECTORY_SIZE:] = record
    return bytes(blob)


CN_OID = bytes.fromhex("0603550403")  # OBJECT IDENTIFIER 2.5.4.3, commonName


def build_certificate(common_names=("Example Signing Ltd",), revision=0x0200,
                      cert_type=2):
    """A WIN_CERTIFICATE blob carrying DER commonName attributes.

    Deliberately not a real PKCS#7 structure and signed by nothing. What the
    extractor does with a certificate table is scan it for commonName strings
    and report that it did not validate anything, so the fixture supplies
    exactly the bytes that scan looks for. Shipping a genuine certificate to
    test a string search would buy nothing and cost a dependency.
    """
    body = bytearray()
    for name in common_names:
        raw = name.encode("ascii")
        body += CN_OID + bytes([0x13, len(raw)]) + raw
    blob = struct.pack("<IHH", 8 + len(body), revision, cert_type) + bytes(body)
    return blob + bytes(-len(blob) % 8)  # entries are 8-byte aligned


def build_pe(sections=None, imports=None, overlay=b"", machine=MACHINE_I386,
             timestamp=0x5D2C0000, subsystem=3, characteristics=0x0102,
             entry_section=".text", tls_callbacks=None, pdb_path=None,
             certificate=None, entry_point=None):
    """Build a structurally valid PE32 executable.

    `sections` is a list of (name, characteristics, body). `imports` is a
    mapping of DLL name to a list of function names, which adds an `.idata`
    section. `overlay` is appended after the last section, which is exactly
    what makes it an overlay.

    `entry_point` overrides the address of entry, and exists for one shape:
    a resource-only module has no entry point at all. Windows ships thousands
    of them - every `en-US\\*.mui` is one - so it is a fixture this suite
    needs rather than a curiosity.

    `tls_callbacks` is a list of virtual addresses and adds a `.tls` section;
    `pdb_path` adds a `.debug` section carrying a CodeView record; and
    `certificate` is a blob appended at the end of the file with the security
    directory pointed at it. Each exists so the extractor's handling of that
    directory is tested against bytes rather than against nothing: those three
    paths are the only pointer arithmetic in the PE extractor that pefile does
    not do on its behalf.

    The optional header is always PE32. `machine` sets the COFF machine field
    only, so passing MACHINE_AMD64 produces a deliberately inconsistent file,
    which is useful as a malformed fixture and useless as an x64 one.
    """
    sections = list(sections if sections is not None
                    else [(".text", SECTION_CODE, b"\x90" * 0x180)])
    extra = {}
    if imports:
        extra["idata"] = len(sections)
        sections.append((".idata", SECTION_RDATA, b""))
    if tls_callbacks:
        extra["tls"] = len(sections)
        sections.append((".tls", SECTION_RDATA,
                         bytes(TLS_DIRECTORY_SIZE + (len(tls_callbacks) + 1) * 4)))
    if pdb_path:
        extra["debug"] = len(sections)
        sections.append((".debug", SECTION_RDATA,
                         bytes(DEBUG_DIRECTORY_SIZE + 4 + 16 + 4 + len(pdb_path) + 1)))

    count = len(sections)
    headers_size = _align(
        PE_HEADER_OFFSET + 4 + 20 + 224 + count * 40, FILE_ALIGNMENT)

    # A section entry is (name, characteristics, body) or, when the section
    # should claim more memory than the file provides for it,
    # (name, characteristics, body, virtual_size). That fourth element is how
    # the unpacker shape - a large VirtualSize over a small SizeOfRawData -
    # is built, and it is the only way to build it: everywhere else the two
    # are derived from the body and therefore agree by construction.
    placed = [{"name": entry[0], "chars": entry[1], "body": entry[2],
               "virtual_size": entry[3] if len(entry) > 3 else None}
              for entry in sections]

    def lay_out():
        rva = _align(headers_size, SECTION_ALIGNMENT)
        raw_pointer = headers_size
        for entry in placed:
            entry["rva"] = rva
            entry["raw_pointer"] = raw_pointer
            raw = max(len(entry["body"]), 1)
            virtual = max(entry["virtual_size"] or 0, raw)
            rva = _align(rva + virtual, SECTION_ALIGNMENT)
            raw_pointer += _align(raw, FILE_ALIGNMENT)
        return rva, raw_pointer

    lay_out()
    import_directory = (0, 0)
    if imports:
        # The blob's internal pointers depend on where it lands, and its size
        # decides where everything after it lands. Build it against the
        # provisional address, then lay out again now that the size is known.
        entry_ = placed[extra["idata"]]
        blob, descriptor_size = _import_blob(entry_["rva"], imports)
        entry_["body"] = blob
        lay_out()
        blob, descriptor_size = _import_blob(entry_["rva"], imports)
        entry_["body"] = blob
        import_directory = (entry_["rva"], descriptor_size)

    image_end, total_raw = lay_out()
    image_size = _align(image_end, SECTION_ALIGNMENT)

    # These two have a fixed size, so unlike the import blob their placement
    # is already final and one pass fills them.
    tls_directory = (0, 0)
    if tls_callbacks:
        entry_ = placed[extra["tls"]]
        entry_["body"] = _tls_blob(entry_["rva"], tls_callbacks)
        tls_directory = (entry_["rva"], TLS_DIRECTORY_SIZE)

    debug_directory = (0, 0)
    if pdb_path:
        entry_ = placed[extra["debug"]]
        entry_["body"] = _debug_blob(entry_["rva"], entry_["raw_pointer"], pdb_path)
        debug_directory = (entry_["rva"], DEBUG_DIRECTORY_SIZE)

    # The security directory is the one entry that holds a file offset rather
    # than an RVA, and the blob sits past the last section, after any overlay.
    security_directory = (0, 0)
    if certificate:
        security_directory = (total_raw + len(overlay), len(certificate))

    entry = next((e for e in placed if e["name"] == entry_section), placed[0])
    out = bytearray(total_raw)

    # DOS header, with the only field that matters: e_lfanew.
    struct.pack_into("<2sHH", out, 0, b"MZ", 0x90, 3)
    struct.pack_into("<I", out, 0x3C, PE_HEADER_OFFSET)
    stub = b"This program cannot be run in DOS mode.\r\r\n$"
    out[0x40:0x40 + len(stub)] = stub

    offset = PE_HEADER_OFFSET
    struct.pack_into("<4s", out, offset, b"PE\x00\x00")
    offset += 4

    code_size = sum(len(e["body"]) for e in placed if e["chars"] & 0x20)
    data_size = sum(len(e["body"]) for e in placed if not e["chars"] & 0x20)

    struct.pack_into("<HHIIIHH", out, offset,
                     machine, count, timestamp, 0, 0, 224, characteristics)
    offset += 20

    struct.pack_into("<HBBIIIIII", out, offset,
                     0x10B, 14, 0, code_size, data_size, 0,
                     entry["rva"] if entry_point is None else entry_point,
                     placed[0]["rva"], placed[0]["rva"])
    struct.pack_into("<IIIHHHHHHIIIIHHIIIIII", out, offset + 28,
                     0x400000, SECTION_ALIGNMENT, FILE_ALIGNMENT,
                     6, 0, 0, 0, 6, 0, 0,
                     image_size, headers_size, 0, subsystem, 0x8140,
                     0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    offset += 96

    directories = [(0, 0)] * 16
    directories[DIRECTORY_IMPORT] = import_directory
    directories[DIRECTORY_SECURITY] = security_directory
    directories[DIRECTORY_DEBUG] = debug_directory
    directories[DIRECTORY_TLS] = tls_directory
    for index, (dir_rva, dir_size) in enumerate(directories):
        struct.pack_into("<II", out, offset + index * 8, dir_rva, dir_size)
    offset += 128

    for entry_ in placed:
        body = entry_["body"]
        struct.pack_into(
            "<8sIIIIIIHHI", out, offset,
            entry_["name"].encode()[:8],
            max(entry_["virtual_size"] or 0, len(body), 1), entry_["rva"],
            _align(max(len(body), 1), FILE_ALIGNMENT), entry_["raw_pointer"],
            0, 0, 0, 0, entry_["chars"])
        offset += 40
        out[entry_["raw_pointer"]:entry_["raw_pointer"] + len(body)] = body

    return bytes(out) + overlay + (certificate or b"")


# Synthetic ELF construction
#
# The counterpart to `build_pe`, and deliberately simpler, because the format
# is. An ELF header, a program header table and a section header table are
# fixed-layout structures; there is no equivalent of a PE import table whose
# thunks have to be built against an address that is not known until the file
# is laid out.
#
# What is produced is structurally valid and contains no code. Section bodies
# are padding, the entry point addresses a byte that does nothing, and there
# is no dynamic linkage that resolves to anything at runtime.

ELF_MAGIC = b"\x7fELF"

ELFCLASS32, ELFCLASS64 = 1, 2
ELFDATA_LSB, ELFDATA_MSB = 1, 2

ET_REL, ET_EXEC, ET_DYN, ET_CORE = 1, 2, 3, 4
EM_386, EM_X86_64, EM_AARCH64 = 3, 0x3E, 0xB7

SHT_NULL, SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB = 0, 1, 2, 3
SHT_DYNAMIC, SHT_NOTE, SHT_NOBITS, SHT_DYNSYM = 6, 7, 8, 11

SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 0x1, 0x2, 0x4

PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE = 1, 2, 3, 4
PF_X, PF_W, PF_R = 0x1, 0x2, 0x4

DT_NULL, DT_NEEDED, DT_STRTAB, DT_STRSZ = 0, 1, 5, 10
DT_SONAME, DT_RPATH, DT_RUNPATH = 14, 15, 29

# Section flag shorthands, mirroring the PE constants above.
SECTION_TEXT = SHF_ALLOC | SHF_EXECINSTR
SECTION_RODATA = SHF_ALLOC
SECTION_DATA_ELF = SHF_ALLOC | SHF_WRITE
SECTION_WX = SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR

ELF_BASE_ADDRESS = 0x400000
ELF_PAGE = 0x1000


def _elf_formats(bitness, endian):
    """Header layouts for one class and byte order.

    The 32-bit program header is not the 64-bit one with narrower fields: it
    puts `p_flags` after `p_memsz` rather than immediately after `p_type`.
    Getting that wrong produces a file that parses and lies about which
    segments are executable, which is the single most useful thing this
    extractor reports, so the two layouts are written out separately rather
    than derived from each other.
    """
    if bitness == 64:
        return (f"{endian}16sHHIQQQIHHHHHH", 64,
                f"{endian}IIQQQQQQ", 56,
                f"{endian}IIQQQQIIQQ", 64)
    return (f"{endian}16sHHIIIIIHHHHHH", 52,
            f"{endian}IIIIIIII", 32,
            f"{endian}IIIIIIIIII", 40)


def _pack_phdr(fmt, bitness, p_type, flags, offset, vaddr, filesz, memsz, align):
    if bitness == 64:
        return struct.pack(fmt, p_type, flags, offset, vaddr, vaddr,
                           filesz, memsz, align)
    return struct.pack(fmt, p_type, offset, vaddr, vaddr,
                       filesz, memsz, flags, align)


def _string_table(names):
    """A packed string table and the offset of each name within it."""
    blob = bytearray(b"\x00")
    offsets = {}
    for name in names:
        offsets[name] = len(blob)
        blob += name.encode() + b"\x00"
    return bytes(blob), offsets


def build_elf(sections=None, segments=None, bitness=64, endian="<",
              elf_type=ET_EXEC, machine=EM_X86_64, entry_section=".text",
              interpreter=None, needed=None, soname=None, runpath=None,
              trailing=b"", strip_sections=False, entry=None):
    """Build a structurally valid ELF.

    `sections` is a list of (name, sh_type, sh_flags, body). `segments` is a
    list of (p_type, p_flags, [section names]) and defaults to one PT_LOAD
    covering everything allocated.

    `interpreter` adds a `.interp` section and a PT_INTERP segment.
    `needed`, `soname` and `runpath` add `.dynstr` and `.dynamic`.
    `trailing` is appended after everything, which is what makes it trailing.
    `strip_sections` omits the section header table entirely, which no
    mainstream toolchain does and several packers do.

    `entry` overrides the entry point address, so a file whose entry lands
    outside every executable segment can be built deliberately.
    """
    ehdr_fmt, ehdr_size, phdr_fmt, phdr_size, shdr_fmt, shdr_size = _elf_formats(
        bitness, endian)

    sections = list(sections if sections is not None
                    else [(".text", SHT_PROGBITS, SECTION_TEXT, b"\x90" * 0x100)])

    dynstr_names = []
    if interpreter:
        sections.append((".interp", SHT_PROGBITS, SECTION_RODATA,
                         interpreter.encode() + b"\x00"))
    if needed or soname or runpath:
        dynstr_names = list(needed or []) + ([soname] if soname else []) \
            + ([runpath] if runpath else [])
        dynstr, dyn_offsets = _string_table(dynstr_names)
        sections.append((".dynstr", SHT_STRTAB, SECTION_RODATA, dynstr))

        word = f"{endian}QQ" if bitness == 64 else f"{endian}II"
        entries = [(DT_NEEDED, dyn_offsets[n]) for n in (needed or [])]
        if soname:
            entries.append((DT_SONAME, dyn_offsets[soname]))
        if runpath:
            entries.append((DT_RUNPATH, dyn_offsets[runpath]))
        entries.append((DT_STRSZ, len(dynstr)))
        entries.append((DT_NULL, 0))
        sections.append((".dynamic", SHT_DYNAMIC, SECTION_DATA_ELF,
                         b"".join(struct.pack(word, tag, value)
                                  for tag, value in entries)))

    # Section index 0 is the reserved null entry the format requires.
    placed = [{"name": "", "type": SHT_NULL, "flags": 0, "body": b"", "link": 0}]
    placed += [{"name": name, "type": kind, "flags": flags, "body": body, "link": 0}
               for name, kind, flags, body in sections]

    # `.dynamic` addresses its string table through `sh_link`, and a real
    # parser needs it: without it the dynamic tags carry offsets into a table
    # nobody can find, so DT_NEEDED reads as a number rather than a library
    # name. The fixture parsed happily and produced no names at all until this
    # was set, which is the whole reason the builder is verified against an
    # independent parser rather than against itself.
    index_of = {entry["name"]: i for i, entry in enumerate(placed)}
    if ".dynamic" in index_of and ".dynstr" in index_of:
        placed[index_of[".dynamic"]]["link"] = index_of[".dynstr"]

    shstrtab, name_offsets = _string_table([e["name"] for e in placed if e["name"]]
                                           + [".shstrtab"])
    placed.append({"name": ".shstrtab", "type": SHT_STRTAB, "flags": 0,
                   "body": shstrtab, "link": 0})
    name_offsets[""] = 0

    cursor = ehdr_size
    phdr_offset = cursor
    segment_count = len(segments) if segments is not None else 1
    if interpreter:
        segment_count += 1
    if any(e["type"] == SHT_DYNAMIC for e in placed):
        segment_count += 1
    cursor += phdr_size * segment_count

    address = ELF_BASE_ADDRESS + cursor
    for entry_ in placed[1:]:
        entry_["offset"] = cursor
        entry_["addr"] = address if entry_["flags"] & SHF_ALLOC else 0
        size = len(entry_["body"])
        # SHT_NOBITS occupies address space and no file space, which is the
        # one case where offset and size do not describe a region of the file.
        cursor += 0 if entry_["type"] == SHT_NOBITS else size
        address += size
    placed[0]["offset"], placed[0]["addr"] = 0, 0

    shdr_offset = 0 if strip_sections else cursor
    total = cursor + (0 if strip_sections else shdr_size * len(placed))

    by_name = {e["name"]: e for e in placed}
    start = by_name.get(entry_section, placed[1] if len(placed) > 1 else placed[0])
    entry_address = entry if entry is not None else start.get("addr", 0)

    out = bytearray(total)

    ident = (ELF_MAGIC
             + bytes([ELFCLASS64 if bitness == 64 else ELFCLASS32,
                      ELFDATA_LSB if endian == "<" else ELFDATA_MSB, 1, 0, 0])
             + b"\x00" * 7)
    # A non-zero e_phoff with e_phnum == 0 is what readelf calls a possibly
    # corrupt header, so an ELF with no segments declares no table at all.
    struct.pack_into(ehdr_fmt, out, 0, ident, elf_type, machine, 1,
                     entry_address, phdr_offset if segment_count else 0,
                     shdr_offset, 0,
                     ehdr_size, phdr_size, segment_count,
                     shdr_size, 0 if strip_sections else len(placed),
                     0 if strip_sections else len(placed) - 1)

    written = []
    def _span(members):
        """File size and memory size of a run of sections.

        The two are measured in different spaces and are not interchangeable.
        An SHT_NOBITS section occupies address space and no file space, so a
        segment containing one has a memory size larger than its file size -
        which is the whole point of `.bss`. Computing both from file offsets
        produced a segment whose `p_memsz` stopped short of its own contents,
        and an entry point that fell outside every loadable segment, so the
        builder handed the extractor a file its own docstring called
        structurally valid and the extractor correctly called broken.
        """
        first, last = members[0], members[-1]
        file_end = last["offset"] + (0 if last["type"] == SHT_NOBITS
                                     else len(last["body"]))
        file_size = max(0, file_end - first["offset"])
        memory_size = max(file_size,
                          last["addr"] + len(last["body"]) - first["addr"])
        return first["offset"], first["addr"], file_size, memory_size

    if segments is None:
        allocated = [e for e in placed[1:] if e["flags"] & SHF_ALLOC]
        if allocated:
            offset, addr, filesz, memsz = _span(allocated)
            written.append((PT_LOAD, PF_R | PF_X, offset, addr, filesz, memsz))
    else:
        for p_type, flags, names in segments:
            members = [by_name[n] for n in names if n in by_name]
            if not members:
                written.append((p_type, flags, 0, 0, 0, 0))
                continue
            offset, addr, filesz, memsz = _span(members)
            written.append((p_type, flags, offset, addr, filesz, memsz))

    if interpreter:
        interp = by_name[".interp"]
        written.append((PT_INTERP, PF_R, interp["offset"], interp["addr"],
                        len(interp["body"]), len(interp["body"])))
    dynamic = next((e for e in placed if e["type"] == SHT_DYNAMIC), None)
    if dynamic is not None:
        written.append((PT_DYNAMIC, PF_R | PF_W, dynamic["offset"],
                        dynamic["addr"], len(dynamic["body"]),
                        len(dynamic["body"])))

    for index, (p_type, flags, offset, vaddr, filesz, memsz) in enumerate(written):
        out[phdr_offset + index * phdr_size:
            phdr_offset + (index + 1) * phdr_size] = _pack_phdr(
                phdr_fmt, bitness, p_type, flags, offset, vaddr,
                filesz, memsz, ELF_PAGE)

    for entry_ in placed:
        body = entry_["body"]
        if body and entry_["type"] != SHT_NOBITS:
            out[entry_["offset"]:entry_["offset"] + len(body)] = body

    if not strip_sections:
        for index, entry_ in enumerate(placed):
            struct.pack_into(
                shdr_fmt, out, shdr_offset + index * shdr_size,
                name_offsets.get(entry_["name"], 0), entry_["type"],
                entry_["flags"], entry_["addr"], entry_["offset"],
                len(entry_["body"]), entry_["link"], 0, 1, 0)

    return bytes(out) + trailing


# Windows shortcuts

_MY_COMPUTER = bytes.fromhex("e04fd020ea3a6910a2d808002b30309d")


def _short_name(name: str) -> str:
    """An 8.3 name the way Windows would make one, for the cases that need it."""
    stem, dot, ext = name.rpartition(".")
    if not dot:
        stem, ext = name, ""
    if len(stem) <= 8 and len(ext) <= 3 and " " not in name:
        return name.upper()
    short = stem.replace(" ", "").upper()[:6] + "~1"
    return short + ("." + ext.upper()[:3] if ext else "")


def _file_entry(name: str, is_file: bool, short_names: bool, version: int) -> bytes:
    primary = (_short_name(name) if short_names else name).encode("cp1252") + b"\0"
    if len(primary) % 2:
        primary += b"\0"
    body = struct.pack("<IIH", 0, 0, 0x20 if is_file else 0x10) + primary
    extension = struct.pack("<HIII", version, 0xBEEF0004, 0, 0) + struct.pack("<H", 0x2E)
    if version >= 7:
        extension += struct.pack("<H", 0) + b"\0" * 16
    extension += struct.pack("<H", 0)
    if version >= 9:
        extension += b"\0" * 4
    if version >= 8:
        extension += b"\0" * 4
    extension += name.encode("utf-16-le") + b"\0\0"
    extension += struct.pack("<H", 14 + len(primary))
    extension = struct.pack("<H", len(extension) + 2) + extension
    # `extension` now starts at its own size field, which the struct.pack
    # above put first; the version follows it.
    kind = 0x32 if is_file else 0x31
    item = bytes([kind, 0]) + body + extension
    return struct.pack("<H", len(item) + 2) + item


def lnk_root_item(guid: str) -> bytes:
    """A root folder shell item for `guid`."""
    import uuid
    body = bytes([0x1F, 0x50]) + uuid.UUID(guid).bytes_le
    return struct.pack("<H", len(body) + 2) + body


def lnk_uri_item(uri: str, unicode: bool = True, data: bytes = b"") -> bytes:
    """A URI shell item (class 0x61): flags, a data block, then the URI."""
    text = uri.encode("utf-16-le") + b"\0\0" if unicode else uri.encode() + b"\0"
    body = bytes([0x61, 0x80 if unicode else 0]) + struct.pack("<I", len(data)) + data + text
    return struct.pack("<H", len(body) + 2) + body


def lnk_delegate_item(name: str, is_file: bool, version: int = 9) -> bytes:
    """The `CFSF` delegate item Explorer wraps a file entry in under the
    user's folder: the entry without its extension block, two GUIDs, and
    then the extension block with the long name."""
    entry = _file_entry(name, is_file, True, version)
    at = entry.index(struct.pack("<I", 0xBEEF0004)) - 4
    bare = entry[2:at]
    sub = struct.pack("<H", len(bare) + 2) + bare
    inner = b"CFSF" + sub
    head = bytes([0x74, 0]) + struct.pack("<H", len(inner)) + inner + b"\x11" * 32
    extension = bytearray(entry[at:])
    struct.pack_into("<H", extension, len(extension) - 2, 2 + len(head))
    body = head + bytes(extension)
    return struct.pack("<H", len(body) + 2) + body


def lnk_id_list(*items: bytes) -> bytes:
    """An item list from items built above, with its size and terminator."""
    data = b"".join(items) + b"\0\0"
    return struct.pack("<H", len(data)) + data


def _id_list(path: str, short_names: bool, version: int) -> bytes:
    drive, _, rest = path.partition("\\")
    items = struct.pack("<H", 20) + bytes([0x1F, 0x50]) + _MY_COMPUTER
    volume = bytes([0x2F]) + (drive + "\\").encode() + b"\0" * 19
    items += struct.pack("<H", len(volume) + 2) + volume
    parts = [part for part in rest.split("\\") if part]
    for index, part in enumerate(parts):
        items += _file_entry(part, index == len(parts) - 1, short_names, version)
    items += b"\0\0"
    return struct.pack("<H", len(items)) + items


def _link_info(path: str, unicode: bool = False) -> bytes:
    """LinkInfo with a local path; with `unicode`, the 0x24 header and a
    UTF-16 copy of the path, which Windows writes when the ANSI one would
    lose characters."""
    volume = struct.pack("<IIII", 0x11, 3, 0x12345678, 0x10) + b"\0"
    base = path.encode("cp1252", "replace") + b"\0"
    header = 0x24 if unicode else 0x1C
    suffix_at = header + len(volume) + len(base)
    body = volume + base + b"\0"
    tail = b""
    if unicode:
        body += b"\0"
        wide_at = header + len(body)
        tail = path.encode("utf-16-le") + b"\0\0"
        wide_suffix_at = wide_at + len(tail)
        tail += b"\0\0"
    size = header + len(body) + len(tail)
    fields = struct.pack("<IIIIIII", size, header, 1, header, header + len(volume), 0, suffix_at)
    if unicode:
        fields += struct.pack("<II", wide_at, wide_suffix_at)
    return fields + body + tail


def _counted(text: str, unicode: bool) -> bytes:
    raw = text.encode("utf-16-le" if unicode else "cp1252")
    return struct.pack("<H", len(text)) + raw


def build_lnk(target: str = "C:\\Windows\\System32\\notepad.exe", arguments: str | None = None,
              icon: str | None = None, working_dir: str | None = None,
              description: str | None = None, relative_path: str | None = None,
              show: int = 1, id_list: bool = True, link_info: bool = True,
              environment: str | None = None, icon_environment: str | None = None,
              machine_id: str | None = "test-pc", trailing: bytes = b"",
              unicode: bool = True, short_names: bool = False,
              item_version: int = 9, link_info_unicode: bool = False,
              id_items: bytes | None = None) -> bytes:
    """A Windows shortcut built to MS-SHLLINK, the way Explorer writes one.

    Every part is optional, because the attacks differ in which parts they
    keep: a shortcut made by a script often has no shell item list at all,
    only the environment block.
    """
    flags = 0x80 if unicode else 0
    parts = b""
    if id_items is not None:
        flags |= 0x1
        parts += id_items
    elif id_list:
        flags |= 0x1
        parts += _id_list(target, short_names, item_version)
    if link_info:
        flags |= 0x2
        parts += _link_info(target, link_info_unicode)
    for text, bit in ((description, 0x4), (relative_path, 0x8), (working_dir, 0x10),
                      (arguments, 0x20), (icon, 0x40)):
        if text is not None:
            flags |= bit
            parts += _counted(text, unicode)
    extra = b""
    for path, signature, bit in ((environment, 0xA0000001, 0x200),
                                 (icon_environment, 0xA0000007, 0x4000)):
        if path is not None:
            flags |= bit
            ansi = path.encode("cp1252")[:259].ljust(260, b"\0")
            wide = path.encode("utf-16-le")[:518].ljust(520, b"\0")
            extra += struct.pack("<II", 0x314, signature) + ansi + wide
    if machine_id is not None:
        extra += (struct.pack("<IIII", 0x60, 0xA0000003, 0x58, 0)
                  + machine_id.encode()[:15].ljust(16, b"\0") + b"\0" * 64)
    header = (struct.pack("<I", 0x4C) + bytes.fromhex("0114020000000000c000000000000046")
              + struct.pack("<II", flags, 0x20) + b"\0" * 24
              + struct.pack("<IiI", 0, 0, show) + b"\0" * 12)
    return header + parts + extra + b"\0\0\0\0" + trailing


# Disk images

def _both16(value: int) -> bytes:
    return struct.pack("<H", value) + struct.pack(">H", value)


def _both32(value: int) -> bytes:
    return struct.pack("<I", value) + struct.pack(">I", value)


def _iso_record(name: bytes, lba: int, size: int, flags: int) -> bytes:
    body = (_both32(lba) + _both32(size) + b"\0" * 7 + bytes([flags, 0, 0])
            + _both16(1) + bytes([len(name)]) + name)
    record = bytes([0]) + body
    if (len(record) + 1) % 2:
        record += b"\0"
    return bytes([len(record) + 1]) + record


def build_iso(files: list[tuple[str, bytes, bool]], joliet: bool = True) -> bytes:
    """An ISO 9660 image of `(path, data, hidden)` files, with a Joliet tree
    of the same files when asked. Directories come from the paths. Each
    directory must fit in one sector, which is plenty for a test.
    """
    dirs: dict[str, list] = {"": []}
    for path, _, _ in files:
        parts = path.split("/")
        for depth in range(1, len(parts)):
            parent, here = "/".join(parts[:depth - 1]), "/".join(parts[:depth])
            if here not in dirs:
                dirs[here] = []
                dirs[parent].append(("dir", parts[depth - 1], here))
    for index, (path, data, hidden) in enumerate(files):
        parent, _, leaf = path.rpartition("/")
        dirs[parent].append(("file", leaf, index))
    order = sorted(dirs, key=lambda d: (d.count("/"), d))
    trees = [False, True] if joliet else [False]

    def name_of(text: str, tree: bool, is_file: bool) -> bytes:
        if tree:
            return text.encode("utf-16-be") + (";1".encode("utf-16-be") if is_file else b"")
        if is_file and "." not in text:
            text += "."          # level 1 writes `README.;1` for a name with no extension
        return text.upper().encode("ascii", "replace") + (b";1" if is_file else b"")

    def records_of(tree: bool, d: str, lba: dict, file_lba: list) -> list[bytes]:
        here = lba.get((tree, d), 0)
        parent = d.rpartition("/")[0] if "/" in d else ""
        size_of = lambda key: sectors.get(key, 1) * 2048
        out = [_iso_record(b"\0", here, size_of((tree, d)), 2),
               _iso_record(b"\1", lba.get((tree, parent), 0), size_of((tree, parent)), 2)]
        for kind, leaf, ref in dirs[d]:
            if kind == "dir":
                out.append(_iso_record(name_of(leaf, tree, False), lba.get((tree, ref), 0),
                                       size_of((tree, ref)), 2))
            else:
                _, data, hidden = files[ref]
                out.append(_iso_record(name_of(leaf, tree, True), file_lba[ref] if file_lba else 0,
                                       len(data), 1 if hidden else 0))
        return out

    def packed(records: list[bytes]) -> bytes:
        """Records never cross a sector: one that would not fit starts the next."""
        out = bytearray()
        for record in records:
            room = 2048 - len(out) % 2048
            if len(record) > room:
                out += b"\0" * room
            out += record
        return bytes(out)

    sectors: dict = {}
    for tree in trees:
        for d in order:
            sectors[(tree, d)] = max(1, (len(packed(records_of(tree, d, {}, []))) + 2047) // 2048)
    next_lba = 19 if joliet else 18
    lba = {}
    for tree in trees:
        for d in order:
            lba[(tree, d)] = next_lba
            next_lba += sectors[(tree, d)]
    file_lba = []
    for _, data, _ in files:
        file_lba.append(next_lba)
        next_lba += max(1, (len(data) + 2047) // 2048)
    total = next_lba

    image = bytearray(total * 2048)
    for tree in trees:
        for d in order:
            here = lba[(tree, d)]
            body = packed(records_of(tree, d, lba, file_lba))
            image[here * 2048:here * 2048 + len(body)] = body
    for index, (_, data, _) in enumerate(files):
        image[file_lba[index] * 2048:file_lba[index] * 2048 + len(data)] = data

    def descriptor(kind: int, tree: bool) -> bytes:
        block = bytearray(2048)
        block[0:7] = bytes([kind]) + b"CD001" + b"\1"
        block[881] = 1
        block[80:88] = _both32(total)
        if tree:
            block[88:91] = b"%/E"
        block[120:124] = _both16(1)
        block[124:128] = _both16(1)
        block[128:132] = _both16(2048)
        block[156:190] = _iso_record(b"\0", lba[(tree, "")], sectors[(tree, "")] * 2048, 2)
        return bytes(block)

    image[16 * 2048:17 * 2048] = descriptor(1, False)
    at = 17
    if joliet:
        image[17 * 2048:18 * 2048] = descriptor(2, True)
        at = 18
    image[at * 2048:at * 2048 + 7] = b"\xffCD001\x01"
    return bytes(image)


def _fat_short(index: int, name: str) -> bytes:
    stem, _, ext = name.rpartition(".")
    if not stem:
        stem, ext = name, ""
    short = f"F{index:05d}~1"[:8].ljust(8) + ext.upper()[:3].ljust(3)
    return short.encode("ascii")


def _lfn_entries(name: str, short: bytes) -> bytes:
    checksum = 0
    for byte in short:
        checksum = (((checksum & 1) << 7) + (checksum >> 1) + byte) & 0xFF
    raw = name.encode("utf-16-le") + b"\0\0"
    while len(raw) % 26:
        raw += b"\xff\xff"
    pieces = [raw[i:i + 26] for i in range(0, len(raw), 26)]
    out = b""
    for ordinal in range(len(pieces), 0, -1):
        piece = pieces[ordinal - 1]
        seq = ordinal | (0x40 if ordinal == len(pieces) else 0)
        out += (bytes([seq]) + piece[0:10] + bytes([0x0F, 0, checksum]) + piece[10:22]
                + b"\0\0" + piece[22:26])
    return out


def build_fat(files: list[tuple[str, bytes, bool]]) -> bytes:
    """A 1.44 MB FAT12 floppy image of `(path, data, hidden)` files, with long
    names and subdirectories, laid out the way mkfs.fat and Windows do."""
    bps, total, fat_sectors, root_entries = 512, 2880, 9, 224
    data_start = (1 + 2 * fat_sectors + root_entries * 32 // bps) * bps
    image = bytearray(total * bps)
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"MALTRIAG"
    struct.pack_into("<HBHBHHBHHHII", boot, 11, bps, 1, 1, 2, root_entries, total, 0xF0,
                     fat_sectors, 18, 2, 0, 0)
    boot[38] = 0x29
    boot[43:54] = b"NO NAME    "
    boot[54:62] = b"FAT12   "
    boot[510:512] = b"\x55\xaa"
    image[0:512] = boot
    fat = {0: 0xFF0, 1: 0xFFF}
    next_cluster = [2]

    def allocate(length: int) -> int:
        count = max(1, (length + bps - 1) // bps)
        first = next_cluster[0]
        for i in range(count):
            fat[first + i] = first + i + 1 if i < count - 1 else 0xFFF
        next_cluster[0] += count
        return first

    def entry(name: str, index: int, cluster: int, size: int, attributes: int) -> bytes:
        short = _fat_short(index, name)
        body = short + bytes([attributes]) + b"\0" * 8 + struct.pack("<HHHHI", 0, 0, 0,
                                                                   cluster, size)
        return _lfn_entries(name, short) + body

    dirs: dict[str, list] = {"": []}
    for path, _, _ in files:
        parts = path.split("/")
        for depth in range(1, len(parts)):
            parent, here = "/".join(parts[:depth - 1]), "/".join(parts[:depth])
            if here not in dirs:
                dirs[here] = []
                dirs[parent].append(("dir", parts[depth - 1], here))
    for index, (path, _, _) in enumerate(files):
        parent, _, leaf = path.rpartition("/")
        dirs[parent].append(("file", leaf, index))
    cluster_of = {"": 0}
    for d in sorted(dirs, key=lambda d: (d.count("/"), d)):
        if d:
            cluster_of[d] = allocate(bps)
    counter = [0]
    for d in sorted(dirs, key=lambda d: (d.count("/"), d)):
        records = b""
        if d:
            records += (b".          " + bytes([0x10]) + b"\0" * 14 + struct.pack("<HI", cluster_of[d], 0)
                        + b"..         " + bytes([0x10]) + b"\0" * 14
                        + struct.pack("<HI", cluster_of[d.rpartition("/")[0] if "/" in d else ""], 0))
        for kind, leaf, ref in dirs[d]:
            counter[0] += 1
            if kind == "dir":
                records += entry(leaf, counter[0], cluster_of[ref], 0, 0x10)
            else:
                _, data, hidden = files[ref]
                cluster = allocate(len(data)) if data else 0
                start = data_start + (cluster - 2) * bps
                if data:
                    image[start:start + len(data)] = data
                records += entry(leaf, counter[0], cluster, len(data), 0x22 if hidden else 0x20)
        where = (bps * (1 + 2 * fat_sectors) if not d
                 else data_start + (cluster_of[d] - 2) * bps)
        image[where:where + len(records)] = records
    table = bytearray(fat_sectors * bps)
    for cluster, value in fat.items():
        at = cluster + cluster // 2
        pair = struct.unpack_from("<H", table, at)[0]
        pair = (pair & 0x000F) | (value << 4) if cluster & 1 else (pair & 0xF000) | value
        struct.pack_into("<H", table, at, pair)
    for copy in range(2):
        start = bps * (1 + copy * fat_sectors)
        image[start:start + len(table)] = table
    return bytes(image)


# Sample files
#
# Every fixture is synthetic. The whole test suite runs without a single
# malicious sample, and none should ever be committed to this repository.

SAMPLE_FILES = {
    # plain text, nothing to report
    "notes.txt": lambda: b"hello world " * 3000,

    # PE content wearing a document extension
    "invoice.pdf": lambda: b"MZ\x90\x00" + b"\x00" * 2048,

    # low overall entropy with a random blob inside: the packed-stub shape
    "packed.bin": lambda: b"A" * 150_000 + os.urandom(50_000) + b"A" * 150_000,

    # the same shape at dropper scale. v0.1.0 scored this "info" because no
    # window fitted inside it, which is the defect fixed in v0.1.1.
    "small_dropper.bin": lambda: b"\x00" * 1200 + os.urandom(1800),

    # uniformly random: high whole-file entropy, no hotspot
    "encrypted.bin": lambda: os.urandom(200_000),

    # a real ELF, replacing the eight plausible bytes this used to be. It
    # carries a writable executable segment, a high-entropy section, a RUNPATH
    # the loader searches before the system paths, and appended data.
    "helper.elf": lambda: build_elf(
        sections=[(".text", SHT_PROGBITS, SECTION_TEXT, b"\x90" * 0x400),
                  (".packed", SHT_PROGBITS, SECTION_WX, os.urandom(0x800))],
        segments=[(PT_LOAD, PF_R | PF_W | PF_X, [".text", ".packed"])],
        interpreter="/lib64/ld-linux-x86-64.so.2",
        needed=["libc.so.6"], runpath="/tmp/.hidden/lib",
        trailing=os.urandom(0x2000)),

    # a document carrying a Windows executable in its body: the shape the
    # bundled YARA rules exist for, and one no extractor sees, because the
    # file really is a PDF and the payload is just bytes inside it.
    "carrier.pdf": lambda: (
        b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript "
        b"/JS (app.alert\\(1\\)) >> >>\nendobj\n"
        + b"%" + b"filler " * 64 + b"\n"
        + build_pe(imports={"KERNEL32.dll": ["VirtualAlloc", "LoadLibraryA"]})
        + b"\n%%EOF\n"),

    # a structurally valid PE wearing every shape v0.2 looks for: a packed
    # section that is writable and executable, a section reserving far more
    # memory than the file fills, a thin import table and an appended payload.
    # Contains no code: the section bodies are padding and random bytes.
    "dropper.exe": lambda: build_pe(
        sections=[(".text", SECTION_CODE, b"\x90" * 0x400, 0x20000),
                  (".packed", SECTION_RWX, os.urandom(0x2000))],
        imports={"KERNEL32.dll": ["VirtualAlloc", "LoadLibraryA"]},
        overlay=os.urandom(0x8000),
        timestamp=0),
}


def write_samples(directory):
    """Write every sample file into `directory` and return the paths."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for name, builder in SAMPLE_FILES.items():
        path = directory / name
        path.write_bytes(builder())
        written.append(path)
    return written
