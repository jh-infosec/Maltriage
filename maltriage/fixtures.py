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
             certificate=None):
    """Build a structurally valid PE32 executable.

    `sections` is a list of (name, characteristics, body). `imports` is a
    mapping of DLL name to a list of function names, which adds an `.idata`
    section. `overlay` is appended after the last section, which is exactly
    what makes it an overlay.

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
    # the unpacker shape -- a large VirtualSize over a small SizeOfRawData --
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
                     entry["rva"], placed[0]["rva"], placed[0]["rva"])
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
        segment containing one has a memory size larger than its file size --
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
