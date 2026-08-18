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
from pathlib import Path

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
    check_int("entropy_window_bytes")
    check_int("entropy_min_window_bytes")
    check_int("entropy_target_windows")
    check_ratio("entropy_file_ratio")
    check_ratio("entropy_window_ratio")

    for key in ("executable_families", "document_extensions", "signatures"):
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

    # a legitimate-looking ELF header
    "helper.elf": lambda: b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 4096,
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
