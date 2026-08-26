"""
Sample fixtures, default config and config access for maltriage.

The accessors in this module are the only supported way to read a config
value. They validate, fall back to a stated default and never raise, so a
bad config produces a reported problem instead of a wrong answer.

v0.1.0 read config with a bare `config.get(key, default)`. That let
`hash_chunk_bytes: 0` through, which made every hash read zero bytes and
report the digest of an empty file with no error raised anywhere.
"""

import os
import struct
from pathlib import Path

from models import SEVERITIES

# Default configuration
#
# Every threshold the extraction engine uses lives here rather than being
# hard-coded, so behaviour is tunable without editing extractors.py.
#
# Signature magic is stored as hex so the config stays JSON-serialisable and
# can later be loaded from a file or an API.

DEFAULT_CONFIG = {
    "signatures": [
        [0, "4d5a", "PE/DOS executable", "pe"],
        [0, "7f454c46", "ELF executable", "elf"],
        [0, "cafebabe", "Mach-O fat binary", "macho"],
        [0, "cffaedfe", "Mach-O 64-bit", "macho"],
        [0, "504b0304", "ZIP archive (or OOXML/JAR/APK)", "zip"],
        [0, "25504446", "PDF document", "pdf"],
        [0, "d0cf11e0", "OLE2 compound document", "ole"],
        [0, "526172211a07", "RAR archive", "rar"],
        [0, "1f8b", "GZIP stream", "gzip"],
        [0, "377abcaf271c", "7-Zip archive", "7z"],
        [0, "2321", "script with shebang", "script"],
        [0, "edabeedb", "RPM package", "rpm"],
    ],
    "executable_families": ["pe", "elf", "macho"],
    "document_extensions": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt",
                            ".jpg", ".png", ".rtf"],
    # Read sizing. The pipeline opens the file once and drives every
    # extractor from that handle, so these bound peak memory for the whole
    # run regardless of how large the sample is.
    "header_bytes": 4096,
    "read_chunk_bytes": 1048576,

    # Ceiling for the random-access phase. A parser handed a hostile file is
    # the one place in this tool where work is not bounded by the read sizes
    # above, so a sample larger than this is declined and the refusal is
    # recorded. 512 MiB is far above any plausible triage subject.
    "max_parse_bytes": 536870912,

    # Entropy is scored as a ratio of what uniformly random data of the same
    # length actually reaches, not as an absolute bits-per-byte figure. See
    # `expected_random_entropy` in extractors.py for why.
    #
    # 0.90 and 0.94 reproduce the v0.1.0 absolute thresholds of 7.2 and 7.5
    # at the default 8192-byte window, and unlike them they stay meaningful
    # when the window has to shrink for a small file.
    "entropy_window_bytes": 8192,
    "entropy_min_window_bytes": 256,
    "entropy_target_windows": 8,
    "entropy_file_ratio": 0.90,
    "entropy_window_ratio": 0.94,

    # PE parsing.
    #
    # The first two are hostile-input ceilings rather than tuning knobs.
    # pefile's own defaults (8192 exports, 120 repeats) are generous enough
    # that a crafted export table keeps it busy on a file that is not large,
    # and a parser that hangs is the gap `max_parse_bytes` does not close.
    "pe_max_symbol_exports": 4096,
    "pe_max_repeated_symbol": 64,
    "pe_max_tls_callbacks": 64,
    "pe_max_debug_entries": 32,
    "pe_max_certificate_bytes": 1048576,

    # A CodeView record's PdbFileName is whatever is left after a fixed-size
    # prefix, and its length comes from a field in the file. Uncapped, a
    # one-DWORD edit turns a build path into a copy of the whole sample.
    "pe_max_pdb_bytes": 1024,

    # Entropy over a section or an overlay is computed from the mapping in
    # bounded pieces, but a 400 MB overlay would still cost a full read to
    # score. Above this, the first slice is scored and the figure is marked
    # `entropy_sampled`, so a partial answer never passes as a whole one.
    "pe_region_entropy_bytes": 16777216,

    # And a budget shared across the whole section table, because the cap
    # above is per region while the number of regions is a field in the file.
    # A section table under 100 KB can otherwise ask for a cap's worth of
    # work a thousand times over.
    "pe_entropy_budget_bytes": 67108864,

    # Longest symbol list any single directory contributes to the report.
    # imphash is computed over everything pefile parsed, not over this slice.
    "pe_max_listed_symbols": 256,

    # Section entropy is scored against random data of the same length, the
    # same way file entropy is, so one threshold works for a 512-byte section
    # and a 4 MB one.
    "pe_section_entropy_ratio": 0.94,

    # Virtual size as a percentage of raw size, above which a section is
    # reserving more memory than the file fills: the room an unpacker needs.
    "pe_virtual_size_percent": 200,

    "pe_few_imports": 6,
    "pe_large_overlay_bytes": 1048576,

    # 1993-01-01. Earlier than any genuine PE compile timestamp, so anything
    # below it was stripped or forged rather than merely old.
    "pe_min_timestamp": 725846400,

    # YARA. Rules are text and the bundled set ships with the project, so
    # `yara_rule_paths` adds to it rather than replacing it.
    "yara_rule_paths": [],

    # yara takes a timeout and raises on it, which makes this the one
    # extractor that closes the hang gap for itself. Ten seconds is far above
    # any sane rule set against a triage-sized sample.
    "yara_timeout_seconds": 10,

    "yara_max_matches": 64,
    "yara_max_rules_reported": 64,

    # Fast matching records the first occurrence of each string rather than
    # every one. The difference is not cosmetic: a four-byte string against a
    # crafted sample produces libyara's cap of a million match objects, which
    # cost 220 MB on a 4 MB file, and that is bounded memory lost to a rule
    # somebody wrote carelessly. Under fast matching `count` is 1 rather than
    # a total, and `fast_matching` in the report says which figure it is.
    "yara_fast_matching": True,

    # A ceiling on what is handed to yara at all, lower than `max_parse_bytes`
    # and there for a different reason: fast matching bounds the common case,
    # but libyara ignores it for any string whose condition reads that
    # string's count, offset or length, and a rule using the console module
    # can allocate until the deadline fires. Neither cost is bounded by
    # anything the extractor controls, so it bounds the input instead.
    "yara_max_scan_bytes": 67108864,

    # An `include` is resolved relative to the rule file and is confined to
    # nothing, so `include "/etc/passwd"` is opened, parsed, and quoted back
    # in the syntax error. Turn this on only for a rule set you wrote.
    "yara_allow_includes": False,

    # What a rule scores when it declares no severity of its own. Deliberately
    # the quietest level: a rule that forgot to say how much it matters should
    # not be able to fail somebody's build by forgetting.
    "yara_default_severity": "info",

    # ELF parsing. No optional dependency: the format is fixed-layout and
    # `struct` reads it, so every bound below is this module's own.
    "elf_max_segments": 256,
    "elf_max_sections": 512,
    "elf_max_dynamic_entries": 1024,
    "elf_max_listed_names": 128,
    "elf_max_string_bytes": 4096,
    "elf_max_string_table_bytes": 262144,
    "elf_region_entropy_bytes": 16777216,
    "elf_entropy_budget_bytes": 67108864,
    "elf_section_entropy_ratio": 0.94,
    "elf_large_trailing_bytes": 1048576,

    "elf_packer_sections": [
        "upx0", "upx1", "upx2", "upx!", ".upx0", ".upx1", ".upx2",
        "packed", ".packed", ".midgetpack", ".gnu_debugdata_upx",
    ],

    # Names a mainstream toolchain emits. Prefixed families -- `.debug*`,
    # `.rela*`, `.rel*`, `.note*`, `.gnu*` -- are handled by prefix in the
    # extractor rather than enumerated here, because they are open sets.
    "elf_standard_sections": [
        "", ".text", ".data", ".rodata", ".bss", ".init", ".fini",
        ".init_array", ".fini_array", ".preinit_array", ".ctors", ".dtors",
        ".plt", ".plt.got", ".plt.sec", ".got", ".got.plt", ".dynamic",
        ".dynsym", ".dynstr", ".symtab", ".strtab", ".shstrtab", ".hash",
        ".interp", ".comment", ".eh_frame", ".eh_frame_hdr", ".tbss",
        ".tdata", ".jcr", ".data.rel.ro", ".sdata", ".sbss", ".tm_clone_table",
        ".stab", ".stabstr", ".ARM.exidx", ".ARM.attributes", ".riscv.attributes",
        ".gcc_except_table", ".stapsdt.base", ".probes", ".qtversion",
        ".PyRuntime", "SYSTEMD_STATIC_DESTRUCT",
        # Go emits its own runtime sections and they are not a signal.
        ".gopclntab", ".gosymtab", ".noptrdata", ".noptrbss", ".typelink",
        ".itablink", ".gcdata", ".gcbss", ".zdebug_info",
    ],

    "pe_packer_sections": [
        "upx0", "upx1", "upx2", "upx!", ".upx0", ".upx1", ".aspack", ".adata",
        ".asdata", "aspack", ".boom", ".ccg", ".charmve", "bitarts", "dxpack",
        ".ecode", ".edata", ".enigma1", ".enigma2", "fsg!", ".gentee", "kkrunchy",
        ".mackt", ".mpress1", ".mpress2", ".neolit", ".neolite", ".nsp0", ".nsp1",
        ".nsp2", "nsp0", "nsp1", "nsp2", "packedbyskpe", "pebundle", "pec",
        "pec1", "pec2", "pec3", "pec4", "pec5", "pec6", "pelocknt", ".perplex",
        "petite", ".petite", ".pinclie", "prochyde", ".rmnet", "rcryptor",
        ".seau", ".sforce3", ".shrink1", ".shrink2", ".shrink3", ".spack",
        ".svkp", ".taz", ".tsuarch", ".tsustub", ".packed", "themida",
        ".themida", ".vmp0", ".vmp1", ".vmp2", ".winapi", "wwpack", ".wwp32",
        ".y0da", ".yp", "_winzip_",
    ],

    # Names mainstream toolchains emit. Anything outside this and the packer
    # list above is merely unusual, which is a `low`, not an accusation.
    "pe_standard_sections": [
        ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc",
        ".reloc", ".tls", ".debug", ".pdata", ".xdata", ".didat", ".sdata",
        ".srdata", ".crt", ".ctors", ".dtors", ".gfids", ".00cfg", ".textbss",
        ".voltbl", ".init", ".fini", ".rodata", ".comment", ".detourc",
        ".detourd", ".sxdata", ".imrsiv", ".cormeta", ".drectve", ".symtab",
        "code", "data", "text", "init", "page", "pagedata", ".bindat",
    ],
}


# Config access
#
# Each accessor validates, falls back to the caller's default and never
# raises. `validate_config` reports every problem at once so the pipeline can
# record them on the report rather than failing silently one value at a time.

def config_int(config, key, default, minimum=1):
    value = config.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        return default
    return value


# A ratio can slightly exceed 1.0, because the reference is a statistical
# estimate rather than a hard ceiling. The accepted range therefore runs to
# RATIO_MAX, and any threshold above about 1.01 effectively disables its
# check, which is how v0.1.0's out-of-range absolute thresholds behaved.
RATIO_MAX = 2.0


def config_ratio(config, key, default):
    value = config.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    if not 0.0 <= value <= RATIO_MAX:
        return default
    return float(value)


def config_bool(config, key, default):
    """A boolean, or the default. `1` and `"true"` are not booleans here.

    Deliberately strict, in the same way `config_int` rejects `True`: a switch
    that quietly accepts a truthy value is a switch that behaves differently
    from what the config file appears to say.
    """
    value = config.get(key, default)
    return value if isinstance(value, bool) else default


def config_list(config, key, default):
    value = config.get(key, default)
    return value if isinstance(value, list) else default


def validate_config(config):
    """Return a list of human-readable problems.

    Empty means the config is usable. Every problem reported here is
    survivable: the offending value is ignored and its default used instead.
    Reporting is the point, since the alternative is a confident wrong answer.
    """
    problems = []

    def check_int(key, minimum=1):
        if key not in config:
            return
        value = config[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            problems.append(f"{key}={value!r} is not an integer >= {minimum}, default used")

    def check_bool(key):
        """A switch is the value most likely to be written as a string.

        `"yara_fast_matching": "false"` and `: 0` are both what somebody
        reaches for in a JSON or YAML config, and both used to leave the
        switch on while the report stated the setting they thought they had
        turned off.
        """
        if key in config and not isinstance(config[key], bool):
            problems.append(f"{key}={config[key]!r} is not true or false, default used")

    def check_ratio(key):
        if key not in config:
            return
        value = config[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) \
                or not 0.0 <= value <= RATIO_MAX:
            problems.append(
                f"{key}={value!r} is not a ratio between 0 and {RATIO_MAX}, default used")

    check_int("header_bytes")
    check_int("read_chunk_bytes")
    check_int("max_parse_bytes")
    check_int("entropy_window_bytes")
    check_int("entropy_min_window_bytes")
    check_int("entropy_target_windows")
    check_ratio("entropy_file_ratio")
    check_ratio("entropy_window_ratio")

    check_int("pe_max_symbol_exports")
    check_int("pe_max_repeated_symbol")
    check_int("pe_max_tls_callbacks")
    check_int("pe_max_debug_entries")
    check_int("pe_max_pdb_bytes")
    check_int("pe_entropy_budget_bytes")
    check_int("pe_max_certificate_bytes")
    check_int("pe_region_entropy_bytes")
    check_int("pe_max_listed_symbols")
    check_int("pe_virtual_size_percent", minimum=100)
    check_int("pe_few_imports")
    check_int("pe_large_overlay_bytes")
    check_int("pe_min_timestamp")
    check_ratio("pe_section_entropy_ratio")

    check_int("yara_timeout_seconds")
    check_int("yara_max_matches")
    check_int("yara_max_rules_reported")
    check_int("yara_max_scan_bytes")

    check_int("elf_max_segments")
    check_int("elf_max_sections")
    check_int("elf_max_dynamic_entries")
    check_int("elf_max_listed_names")
    check_int("elf_max_string_bytes")
    check_int("elf_max_string_table_bytes")
    check_int("elf_region_entropy_bytes")
    check_int("elf_entropy_budget_bytes")
    check_int("elf_large_trailing_bytes")
    check_ratio("elf_section_entropy_ratio")
    check_bool("yara_fast_matching")
    check_bool("yara_allow_includes")
    if "yara_default_severity" in config and config["yara_default_severity"] not in SEVERITIES:
        problems.append(
            f"yara_default_severity={config['yara_default_severity']!r} is not one of "
            f"{SEVERITIES}, default used")

    for key in ("executable_families", "document_extensions", "signatures",
                "pe_packer_sections", "pe_standard_sections", "yara_rule_paths",
                "elf_packer_sections", "elf_standard_sections"):
        if key in config and not isinstance(config[key], list):
            problems.append(f"{key} is not a list, default used")

    for index, signature in enumerate(config_list(config, "signatures", [])):
        if not isinstance(signature, (list, tuple)) or len(signature) != 4:
            problems.append(
                f"signatures[{index}] is not [offset, hex, label, family], skipped")
            continue
        offset, magic_hex = signature[0], signature[1]
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            problems.append(
                f"signatures[{index}] offset {offset!r} is not a byte offset, skipped")
        try:
            bytes.fromhex(str(magic_hex))
        except ValueError:
            problems.append(
                f"signatures[{index}] magic {magic_hex!r} is not valid hex, skipped")

    return problems


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
