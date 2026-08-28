"""
Default configuration and validated config access for maltriage.

The accessors here are the only supported way to read a config value. They
validate, fall back to a stated default and never raise, so a bad config
produces a reported problem instead of a wrong answer.

v0.1.0 read config with a bare `config.get(key, default)`. That let
`hash_chunk_bytes: 0` through, which made every hash read zero bytes and
report the digest of an empty file with no error raised anywhere.

Split out of `sample_data` in v0.4. Every extractor needs these accessors and
none of them needs a PE builder, so a module named for its fixtures was the
wrong home -- and the shared secret engine, which is not a fixture consumer at
all, would have had to import one to read a threshold.
"""

from .models import SEVERITIES

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

    # Strings.
    #
    # Six is the conventional floor and it matters: at five, printable runs
    # occur often enough in random data to bury the report in noise.
    "strings_min_length": 6,

    # One string, and the number kept across both ASCII and UTF-16 together.
    # The product is the worst case this extractor can hold -- 2 MiB -- which
    # is the same order as one read chunk rather than a multiple of it. The
    # counts keep rising after the retained list is full, so the report still
    # says how many there were, and `parse_errors` says the indicator lists
    # were derived from a subset.
    "strings_max_length": 1024,
    "strings_max_retained": 2048,

    "strings_max_iocs": 128,

    # Whether the report carries the strings themselves as well as the
    # indicators drawn from them. Off: it is a dump rather than a finding,
    # and a report is stored, piped and shared.
    "strings_include_text": False,

    # Registry locations that survive a reboot, matched case-insensitively as
    # substrings. In config rather than in code so the list can grow without
    # a release.
    "strings_run_keys": [
        "currentversion\\run", "currentversion\\runonce",
        "currentversion\\policies\\explorer\\run", "winlogon",
        "\\services\\", "image file execution options",
        "currentversion\\explorer\\shell folders",
    ],

    # API name matching. The vocabulary itself is in `apis.py` rather than
    # here: it is several hundred names with their capability grouping and
    # their severities, and a config file is a place for the two numbers below
    # rather than for a taxonomy.
    #
    # How many distinct names a capability needs before it is worth a finding.
    # Two, because one is not a pattern: every name in the registry is called
    # by legitimate software, and a lone `GetTickCount` is a timer. Below the
    # threshold nothing is lost -- the names are in `report.data` either way,
    # which is the difference between an observation and a finding.
    "api_min_names_per_capability": 2,

    # How long a string may be before it is matched whole rather than taken
    # apart into tokens. A symbol reference is short: bare, stdcall-decorated
    # or inside a mangled C++ signature. A run longer than this that mentions
    # an API name is prose, and reporting the manual as an injector teaches
    # nobody anything. Also the cost bound -- this is the expensive path on a
    # sample with millions of strings.
    "api_max_token_scan_bytes": 128,

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

    check_int("strings_min_length")
    check_int("strings_max_length")
    check_int("strings_max_retained")
    check_int("strings_max_iocs")
    check_bool("strings_include_text")

    check_int("api_min_names_per_capability")
    check_int("api_max_token_scan_bytes")

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
                "strings_run_keys",
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


