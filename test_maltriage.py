"""
Test suite for maltriage.

Runs the extraction engine against synthetic fixtures and verifies the
pipeline behaves correctly after changes.

Every fixture is generated in-process. No malicious samples are required to
test the analysis logic, and none should ever be committed.

The `regression` section holds one test per defect found in v0.1.0. Those
tests exist to fail if the defect ever returns, so each one should be read
alongside the CHANGELOG entry that describes it.

    pytest
"""

import json
import math
import os
import re
import statistics
import struct
import time
import tracemalloc
from pathlib import Path

import pytest

import cli
import extractors as extractors_module
from extractors import (
    EntropyExtractor,
    Extractor,
    FileTypeExtractor,
    FuzzyHashExtractor,
    HashExtractor,
    PEExtractor,
    RandomAccessExtractor,
    StreamExtractor,
    byte_counts,
    certificate_common_names,
    entropy_from_counts,
    expected_random_entropy,
    shannon,
)
from models import SEVERITIES, mk_finding
from extractors import default_extractors
from pipeline import analyse, analyse_directory
from sample_data import (
    DEFAULT_CONFIG,
    PE_HEADER_OFFSET,
    SECTION_CODE,
    SECTION_DATA,
    SECTION_RDATA,
    SECTION_RWX,
    build_certificate,
    build_pe,
    config_int,
    config_ratio,
    validate_config,
    write_samples,
)

try:  # only the fixture-verification tests need it
    import pefile
except ImportError:
    pefile = None

needs_pefile = pytest.mark.skipif(
    pefile is None, reason="verifying the PE fixture requires pefile")


def _run_one(extractor, path, ctx=None, config=None):
    """Drive a single extractor through the same contract the pipeline uses,
    so these tests break if that contract changes."""
    report = analyse(path, config=config, extractors=[extractor])
    if ctx is not None and "hashes" in report.data:
        ctx["sha256"] = report.data["hashes"]["sha256"]
    assert not report.errors, report.errors
    return report.data[extractor.name]


@pytest.fixture
def write(tmp_path):
    def _write(name, content):
        path = tmp_path / name
        path.write_bytes(content)
        return path
    return _write


# entropy

def test_shannon_uniform_bytes_is_zero():
    assert shannon(b"\x00" * 4096) == 0.0


def test_shannon_random_bytes_approaches_eight():
    assert shannon(os.urandom(65536)) > 7.9


def test_shannon_empty_is_zero():
    assert shannon(b"") == 0.0


def test_entropy_hotspot_detected(write):
    """Low-entropy file with a random blob inside: the packed-stub shape."""
    content = b"A" * 200_000 + os.urandom(40_000) + b"A" * 200_000
    report = analyse(write("hotspot.bin", content))
    assert "entropy_hotspot" in {f["key"] for f in report.findings}
    assert report.severity == "medium"


def test_uniformly_random_file_reports_file_entropy_not_hotspot(write):
    report = analyse(write("encrypted.bin", os.urandom(200_000)))
    keys = {f["key"] for f in report.findings}
    assert "high_file_entropy" in keys
    assert "entropy_hotspot" not in keys


def test_flat_file_has_no_entropy_findings(write):
    report = analyse(write("flat.bin", b"hello world " * 5000))
    assert not [f for f in report.findings if f["extractor"] == "entropy"]


# entropy reference

@pytest.mark.parametrize("n", [128, 256, 512, 1024, 4096, 8192])
def test_expected_random_entropy_predicts_measured_randomness(n):
    """The reference must track what random data of that length really scores,
    or ratio thresholds mean nothing at small window sizes."""
    measured = statistics.mean(shannon(os.urandom(n)) for _ in range(40))
    predicted = expected_random_entropy(n)
    assert abs(predicted - measured) / measured < 0.03


def test_expected_random_entropy_is_capped_by_sample_length():
    """8 bytes cannot express more than 3 bits of entropy per byte."""
    assert expected_random_entropy(8) <= math.log2(8)


def test_expected_random_entropy_handles_degenerate_lengths():
    assert expected_random_entropy(0) == 0.0
    assert expected_random_entropy(1) == 0.0


# hashes

def test_hashes_match_hashlib(write):
    import hashlib
    content = b"the quick brown fox"
    report = analyse(write("h.bin", content))
    assert report.data["hashes"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert report.data["hashes"]["md5"] == hashlib.md5(content).hexdigest()


def test_hash_extractor_publishes_sha256_to_context(write):
    """The context is how v0.4 enrichment will find its lookup key."""
    import hashlib
    seen = {}

    class ContextSpy(StreamExtractor):
        name = "spy"

        def feed(self, chunk):
            pass

        def finish(self, path, ctx, config):
            seen.update(ctx)
            return {}

    analyse(write("h.bin", b"x"), extractors=[HashExtractor(), ContextSpy()])
    assert seen["sha256"] == hashlib.sha256(b"x").hexdigest()


# file type

@pytest.mark.parametrize("header,family", [
    (b"MZ\x90\x00", "pe"),
    (b"\x7fELF\x02\x01", "elf"),
    (b"%PDF-1.7", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"\x00\x00\x00\x00", "unknown"),
])
def test_family_detection(write, header, family):
    path = write("t.bin", header + b"\x00" * 64)
    data = FileTypeExtractor().read_header(header + b"\x00" * 64, path, {}, DEFAULT_CONFIG)
    assert data["family"] == family


def test_extension_mismatch_is_high_severity(write):
    """PE content wearing a .pdf extension."""
    report = analyse(write("invoice.pdf", b"MZ" + b"\x00" * 1024))
    mismatch = [f for f in report.findings if f["key"] == "extension_mismatch"]
    assert mismatch and mismatch[0]["severity"] == "high"
    assert report.severity == "high"


# config

def test_a_high_threshold_suppresses_the_finding(write):
    path = write("encrypted.bin", os.urandom(100_000))
    report = analyse(path, config={**DEFAULT_CONFIG, "entropy_file_ratio": 1.5})
    assert "high_file_entropy" not in {f["key"] for f in report.findings}


def test_a_low_threshold_makes_the_check_more_sensitive(write):
    """Plain text is nowhere near random, so only a deliberately loose
    threshold should flag it. This is the tuning knob working in the
    direction a triage tool actually cares about."""
    path = write("notes.txt", b"hello world " * 5000)
    assert "high_file_entropy" not in {
        f["key"] for f in analyse(path).findings}
    loose = analyse(path, config={**DEFAULT_CONFIG, "entropy_file_ratio": 0.2})
    assert "high_file_entropy" in {f["key"] for f in loose.findings}


def test_signature_table_is_json_serialisable():
    """Config must survive a round trip so it can be loaded from a file."""
    assert json.loads(json.dumps(DEFAULT_CONFIG)) == DEFAULT_CONFIG


def test_default_config_is_valid():
    assert validate_config(DEFAULT_CONFIG) == []


@pytest.mark.parametrize("value", [0, -1, "1024", 1.5, True, None])
def test_config_int_rejects_bad_values(value):
    assert config_int({"k": value}, "k", 4096) == 4096


@pytest.mark.parametrize("value", [-0.1, 2.5, "0.9", True, None])
def test_config_ratio_rejects_bad_values(value):
    assert config_ratio({"k": value}, "k", 0.94) == 0.94


def test_validate_config_reports_bad_signature_rows():
    problems = validate_config({"signatures": [[0, "zz", "bad hex", "x"], ["nope"]]})
    assert len(problems) == 2
    assert any("valid hex" in p for p in problems)


def test_malformed_signature_does_not_stop_later_signatures(write):
    """One bad row must not cost every signature after it."""
    config = {**DEFAULT_CONFIG, "signatures": [["broken"], [0, "4d5a", "PE", "pe"]]}
    report = analyse(write("a.bin", b"MZ\x00\x00"), config=config)
    assert report.data["filetype"]["family"] == "pe"


# models

def test_mk_finding_rejects_unknown_severity():
    with pytest.raises(ValueError):
        mk_finding("x", "y", "z", "hihg")


@pytest.mark.parametrize("severity", SEVERITIES)
def test_mk_finding_accepts_every_declared_severity(severity):
    assert mk_finding("x", "y", "z", severity)["severity"] == severity


# pipeline

def test_failing_header_extractor_does_not_lose_other_results(write):
    class Exploding(FileTypeExtractor):
        name = "exploding"

        def read_header(self, header, path, ctx, config):
            raise ValueError("corrupt header")

    report = analyse(
        write("a.bin", b"MZ" + b"\x00" * 100),
        extractors=[Exploding(), HashExtractor()],
    )
    assert "ValueError" in report.errors["exploding"]
    assert report.data["hashes"]["sha256"]


def test_report_serialises_to_json(write):
    report = analyse(write("invoice.pdf", b"MZ" + b"\x00" * 100))
    parsed = json.loads(report.to_json())
    assert parsed["schema_version"] == "1.4"
    assert parsed["severity"] == "high"


def test_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        analyse(tmp_path / "nope.bin")


# sample data

def test_bundled_samples_produce_expected_severities(tmp_path):
    write_samples(tmp_path)
    reports = {r.filename: r for r in analyse_directory(tmp_path)}
    assert reports["invoice.pdf"].severity == "high"
    assert reports["packed.bin"].severity == "medium"
    assert reports["small_dropper.bin"].severity == "medium"
    assert reports["notes.txt"].severity == "info"
    assert reports["helper.elf"].data["filetype"]["family"] == "elf"


@needs_pefile
def test_the_bundled_dropper_exercises_the_pe_extractor(tmp_path):
    """The demo directory should contain something the newest phase actually
    has an opinion about, or a first run of the tool shows none of v0.2."""
    write_samples(tmp_path)
    report = analyse(tmp_path / "dropper.exe")
    assert "pe" not in report.errors, report.errors
    keys = {f["key"] for f in report.findings if f["extractor"] == "pe"}
    assert {"section_entropy_high", "writable_executable_section",
            "virtual_size_mismatch"} <= keys
    assert report.severity == "medium"


# regression
#
# One test per defect found in v0.1.0. Each should be read alongside its
# CHANGELOG entry.

def test_small_packed_file_is_flagged(write):
    """v0.1.0 blind spot: at a fixed 8192-byte window a 3 KB file produced no
    windows at all, so a dropper-sized packed payload scored `info`."""
    content = b"\x00" * 1200 + os.urandom(1800)
    report = analyse(write("dropper.bin", content))
    entropy = report.data["entropy"]
    assert entropy["window_count"] > 0
    assert entropy["window_size"] < 8192
    assert "entropy_hotspot" in {f["key"] for f in report.findings}
    assert report.severity == "medium"


def test_tiny_file_reports_no_windows_rather_than_guessing(write):
    """Below roughly 128 bytes there are too few samples for entropy to mean
    anything. Reporting nothing is correct; inventing a score is not."""
    report = analyse(write("tiny.bin", os.urandom(40)))
    assert report.data["entropy"]["window_count"] == 0
    assert report.data["entropy"]["window_max"] is None
    assert "entropy_hotspot" not in {f["key"] for f in report.findings}


def test_zero_chunk_size_does_not_truncate_the_read(write):
    """v0.1.0 returned the digest of an empty file, silently, with no error.
    The chunk size now lives on the pipeline, so this is the same defect at
    its new address: a zero read size would stop the stream after the header."""
    import hashlib
    content = b"hello world" * 2000
    path = write("h.bin", content)
    report = analyse(path, config={**DEFAULT_CONFIG, "read_chunk_bytes": 0})
    assert report.data["hashes"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert "read_chunk_bytes" in report.errors["config"]


def test_empty_file_is_described_not_crashed(write):
    report = analyse(write("empty.bin", b""))
    assert report.size_bytes == 0
    assert report.data["entropy"]["overall"] == 0.0
    details = " ".join(f["detail"] for f in report.findings)
    assert "empty" in details


def test_json_output_is_always_a_list(tmp_path):
    """v0.1.0 wrote an object for one file and an array for several, so a
    consumer had to branch on the shape of its own input."""
    one, many = tmp_path / "one", tmp_path / "many"
    one.mkdir(), many.mkdir()
    (one / "a.txt").write_bytes(b"hello")
    (many / "a.txt").write_bytes(b"hello")
    (many / "b.txt").write_bytes(b"hello")

    for directory in (one, many):
        out = tmp_path / f"{directory.name}.json"
        cli.main(["scan", str(directory), "--json", str(out), "-q"])
        assert isinstance(json.loads(out.read_text()), list)


def test_missing_target_exits_cleanly(tmp_path, capsys):
    """v0.1.0 raised an uncaught FileNotFoundError and printed a traceback."""
    code = cli.main(["scan", str(tmp_path / "nope.bin")])
    assert code == cli.EXIT_USAGE
    assert "no such file" in capsys.readouterr().err


def test_empty_directory_exits_clean(tmp_path, capsys):
    (tmp_path / "empty").mkdir()
    code = cli.main(["scan", str(tmp_path / "empty")])
    assert code == cli.EXIT_CLEAN
    assert "no files found" in capsys.readouterr().err


def test_exit_code_signals_findings(tmp_path):
    (tmp_path / "invoice.pdf").write_bytes(b"MZ" + b"\x00" * 1024)
    assert cli.main(["scan", str(tmp_path), "-q"]) == cli.EXIT_FINDINGS

    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "notes.txt").write_bytes(b"hello world " * 3000)
    assert cli.main(["scan", str(clean), "-q"]) == cli.EXIT_CLEAN


# streaming
#
# These exist because the streaming refactor in v0.1.2 changed how bytes reach
# an extractor. The guarantees below are the ones that make it safe.

@pytest.mark.parametrize("chunk_bytes", [64, 512, 4096, 100_003, 1 << 20])
def test_results_are_independent_of_chunk_size(write, chunk_bytes):
    """Chunk boundaries and entropy window boundaries are unrelated, so the
    accumulator has to split chunks across windows. If it gets that wrong the
    numbers move when the read size changes."""
    content = b"A" * 40_000 + os.urandom(30_000) + b"B" * 40_000
    path = write("split.bin", content)

    reference = analyse(path, config={**DEFAULT_CONFIG, "read_chunk_bytes": 1 << 20})
    actual = analyse(path, config={**DEFAULT_CONFIG, "read_chunk_bytes": chunk_bytes})

    assert actual.data["entropy"] == reference.data["entropy"]
    assert actual.data["hashes"] == reference.data["hashes"]
    assert actual.severity == reference.severity


@pytest.mark.parametrize("header_bytes", [1, 64, 4096, 1_000_000])
def test_results_are_independent_of_header_size(write, header_bytes):
    """The header is the first slice of the same read, and is also fed to the
    stream phase. Change its size and nothing downstream should move."""
    content = b"MZ" + b"\x00" * 20_000 + os.urandom(20_000)
    path = write("h.bin", content)

    reference = analyse(path)
    actual = analyse(path, config={**DEFAULT_CONFIG, "header_bytes": header_bytes})

    assert actual.data["hashes"] == reference.data["hashes"]
    assert actual.data["entropy"] == reference.data["entropy"]


def test_streaming_entropy_matches_a_whole_buffer_calculation(write):
    """The streamed result must equal what the naive whole-file calculation
    would give. This is the property the refactor traded implementation for,
    and it is the one worth pinning down."""
    for content in (
        b"",
        b"\x00" * 10,
        b"hello world " * 900,
        os.urandom(50_000),
        b"A" * 30_000 + os.urandom(9_000),
    ):
        path = write("e.bin", content)
        streamed = analyse(path).data["entropy"]["overall"]
        assert streamed == pytest.approx(round(shannon(content), 4), abs=1e-4)


def test_the_file_is_opened_once_and_read_once(write, monkeypatch):
    """v0.1.1 opened the sample three times and read it in full twice."""
    path = write("counted.bin", os.urandom(300_000))

    opens = []
    original = Path.open

    def counting_open(self, *args, **kwargs):
        if self == path:
            opens.append(self)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", counting_open)
    monkeypatch.setattr(
        Path, "read_bytes",
        lambda self: pytest.fail("read_bytes loads the whole sample into memory"))

    analyse(path)
    assert len(opens) == 1


def test_peak_memory_does_not_track_sample_size(write):
    """The point of the refactor. Peak memory should be governed by the chunk
    size, not by how large the sample is."""
    tracemalloc.start()
    try:
        small = write("small.bin", os.urandom(200_000))
        tracemalloc.reset_peak()
        analyse(small, config={**DEFAULT_CONFIG, "read_chunk_bytes": 65_536})
        _, small_peak = tracemalloc.get_traced_memory()

        large = write("large.bin", os.urandom(20_000_000))
        tracemalloc.reset_peak()
        analyse(large, config={**DEFAULT_CONFIG, "read_chunk_bytes": 65_536})
        _, large_peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    # 100x the sample for well under 2x the peak. v0.1.1 was linear.
    assert large_peak < small_peak * 2
    assert large_peak < 4_000_000


def test_a_failure_mid_stream_drops_only_that_extractor(write):
    """The v0.1.0 isolation guarantee, restated for a streaming run: an
    extractor that dies on the third chunk must not cost the others their
    remaining chunks."""
    class DiesOnThirdChunk(StreamExtractor):
        name = "flaky"

        def begin(self, path, ctx, config):
            self.seen = 0

        def feed(self, chunk):
            self.seen += 1
            if self.seen == 3:
                raise ValueError("bad chunk")

        def finish(self, path, ctx, config):
            return {"chunks": self.seen}

    import hashlib
    content = os.urandom(100_000)
    path = write("flaky.bin", content)
    report = analyse(
        path,
        config={**DEFAULT_CONFIG, "read_chunk_bytes": 8192},
        extractors=[DiesOnThirdChunk(), HashExtractor(), EntropyExtractor()],
    )

    assert "ValueError" in report.errors["flaky"]
    assert "flaky" not in report.data
    # The survivors saw every byte, not just the first three chunks.
    assert report.data["hashes"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert report.data["entropy"]["overall"] > 7.0


def test_a_failure_in_begin_drops_only_that_extractor(write):
    class DiesEarly(StreamExtractor):
        name = "early"

        def begin(self, path, ctx, config):
            raise RuntimeError("no")

        def feed(self, chunk):
            pytest.fail("feed must not be called after begin failed")

        def finish(self, path, ctx, config):
            pytest.fail("finish must not be called after begin failed")

    report = analyse(write("a.bin", b"hello" * 100),
                     extractors=[DiesEarly(), HashExtractor()])
    assert "RuntimeError" in report.errors["early"]
    assert report.data["hashes"]["sha256"]


def test_a_broken_heuristic_does_not_lose_the_data(write):
    """findings() runs after extraction. If it raises, the extracted data is
    still worth keeping."""
    class BadFindings(HashExtractor):
        name = "hashes"

        def findings(self, data, config):
            raise ZeroDivisionError("oops")

    report = analyse(write("a.bin", b"hello" * 100), extractors=[BadFindings()])
    assert report.data["hashes"]["sha256"]
    assert "ZeroDivisionError" in report.errors["hashes.findings"]


def test_stream_extractors_can_gate_on_the_header_phase(write):
    """The ordered-context guarantee: the header phase finishes before any
    stream extractor is consulted, so applies_to can see what it published.
    This is how v0.2 PE parsing will avoid running on every file."""
    ran = []

    class OnlyForPE(StreamExtractor):
        name = "pe_only"

        def applies_to(self, path, ctx, config):
            return ctx.get("family") == "pe"

        def feed(self, chunk):
            pass

        def finish(self, path, ctx, config):
            ran.append(path.name)
            return {"ok": True}

    extractors = [FileTypeExtractor(), OnlyForPE()]
    analyse(write("a.txt", b"just text"), extractors=extractors)
    assert ran == []

    analyse(write("b.exe", b"MZ" + b"\x00" * 100), extractors=extractors)
    assert ran == ["b.exe"]


def test_extractor_instances_are_reusable_across_files(write):
    """begin() must reset per-run state. Reusing an instance is the normal
    case for a directory scan."""
    import hashlib
    shared = [FileTypeExtractor(), HashExtractor(), EntropyExtractor()]

    first = analyse(write("one.bin", b"aaaa" * 100), extractors=shared)
    second = analyse(write("two.bin", b"bbbb" * 100), extractors=shared)

    assert first.data["hashes"]["sha256"] == hashlib.sha256(b"aaaa" * 100).hexdigest()
    assert second.data["hashes"]["sha256"] == hashlib.sha256(b"bbbb" * 100).hexdigest()


def test_byte_counts_agrees_with_the_stdlib(write):
    """numpy is an optional accelerator. Whichever path is taken, the counts
    must be the same, or entropy silently changes with the environment."""
    from collections import Counter
    data = os.urandom(20_000) + b"\x00" * 500
    counts = byte_counts(data)
    reference = Counter(data)
    assert len(counts) == 256
    assert all(counts[i] == reference.get(i, 0) for i in range(256))
    assert sum(counts) == len(data)


def test_entropy_from_counts_handles_degenerate_input():
    assert entropy_from_counts([0] * 256, 0) == 0.0
    assert entropy_from_counts([10] + [0] * 255, 10) == 0.0


# the synthetic PE fixture
#
# v0.2 parses executables, and this project does not use real samples, so the
# executable is built. These tests verify the builder against pefile, which is
# the thing v0.2 will parse with: a fixture that does not contain what it was
# built to contain makes every test above it a test of the fixture.

DEMO_IMPORTS = {
    "KERNEL32.dll": ["CreateFileA", "WriteFile", "VirtualAlloc"],
    "USER32.dll": ["MessageBoxA"],
}


def _expected_imphash(imports):
    """imphash independently of pefile: lowercased `lib.func` pairs, comma
    joined, md5. Computing it here rather than asking pefile means the test
    can disagree with pefile instead of agreeing with it by construction."""
    import hashlib
    parts = []
    for dll, funcs in imports.items():
        lib = dll.lower()
        for extension in (".dll", ".ocx", ".sys"):
            if lib.endswith(extension):
                lib = lib[: -len(extension)]
        parts.extend(f"{lib}.{func.lower()}" for func in funcs)
    return hashlib.md5(",".join(parts).encode()).hexdigest()


def test_the_fixture_is_identified_as_a_pe(write):
    """The cheapest possible check, and the one everything else assumes."""
    report = analyse(write("a.exe", build_pe()))
    assert report.data["filetype"]["family"] == "pe"


@needs_pefile
def test_pefile_parses_the_fixture_without_structural_warnings(write):
    pe = pefile.PE(name=str(write("a.exe", build_pe(imports=DEMO_IMPORTS))))
    structural = [w for w in pe.get_warnings() if "makes up" not in w]
    assert structural == [], structural


@needs_pefile
def test_fixture_sections_are_where_the_section_table_says(write):
    sections = [
        (".text", SECTION_CODE, b"\x90" * 0x180),
        (".evil", SECTION_RWX, os.urandom(0x400)),
    ]
    pe = pefile.PE(name=str(write("a.exe", build_pe(sections=sections))))
    names = [s.Name.rstrip(b"\x00").decode() for s in pe.sections]
    assert names == [".text", ".evil"]
    for section, (_, characteristics, body) in zip(pe.sections, sections):
        assert section.Characteristics == characteristics
        assert section.get_data()[: len(body)] == body


@needs_pefile
def test_fixture_imports_resolve_and_the_imphash_is_right(write):
    """The import table is the reason the random-access phase exists: its
    thunks are RVAs that only resolve once the section table has been read.
    If the fixture's are wrong, nothing built on it means anything."""
    pe = pefile.PE(name=str(write("a.exe", build_pe(imports=DEMO_IMPORTS))))
    parsed = {
        entry.dll.decode(): [imp.name.decode() for imp in entry.imports]
        for entry in pe.DIRECTORY_ENTRY_IMPORT
    }
    assert parsed == DEMO_IMPORTS
    assert pe.get_imphash() == _expected_imphash(DEMO_IMPORTS)


@needs_pefile
def test_fixture_overlay_starts_exactly_after_the_last_section(write):
    """Overlay detection in v0.2 is this subtraction, so the fixture has to
    put the boundary exactly where it claims."""
    body = build_pe(imports=DEMO_IMPORTS)
    overlay = b"appended" * 64
    pe = pefile.PE(name=str(write("a.exe", body + overlay)))
    last = max(pe.sections, key=lambda s: s.PointerToRawData + s.SizeOfRawData)
    assert last.PointerToRawData + last.SizeOfRawData == len(body)
    assert pe.get_overlay() == overlay


@needs_pefile
def test_fixture_without_imports_has_no_import_directory(write):
    """A stripped import table is a packer tell, so it has to be buildable."""
    pe = pefile.PE(name=str(write("a.exe", build_pe())))
    assert not hasattr(pe, "DIRECTORY_ENTRY_IMPORT")


def test_fixture_section_entropy_is_measurable(write):
    """Per-section entropy is a v0.2 finding, so the builder has to be able to
    produce a section that would trip it and one that would not."""
    packed = os.urandom(0x400)
    sections = [(".text", SECTION_CODE, b"\x90" * 0x400),
                (".packed", SECTION_RWX, packed)]
    build_pe(sections=sections)  # the builder must accept the shape
    assert shannon(packed) > 7.5
    assert shannon(b"\x90" * 0x400) < 1.0


# the random-access phase
#
# v0.2 adds a third extractor kind, for structure that cannot be reached in
# one forward pass. These tests pin its contract before anything uses it.

class _Probe(RandomAccessExtractor):
    """A random-access extractor that records what it was given."""

    name = "probe"

    def __init__(self, gate=None):
        self.seen = []
        self._gate = gate

    def applies_to(self, path, ctx, config):
        return self._gate(ctx) if self._gate else True

    def parse(self, path, ctx, config):
        self.seen.append(dict(ctx))
        with path.open("rb") as fh:
            fh.seek(-4, os.SEEK_END)
            tail = fh.read(4)
        return {"tail": tail.hex(), "size": ctx["size"]}


def test_random_access_extractor_runs_and_files_its_data(write):
    probe = _Probe()
    report = analyse(write("a.bin", b"hello world!"), extractors=[probe])
    assert report.data["probe"]["tail"] == b"rld!".hex()
    assert not report.errors


def test_random_access_phase_sees_what_both_earlier_phases_published(write):
    """The whole point of running last: `family` comes from the header phase
    and `sha256` from the stream phase, and a parser needs both."""
    import hashlib
    content = b"MZ" + b"\x00" * 200
    probe = _Probe()
    analyse(write("a.exe", content),
            extractors=[FileTypeExtractor(), HashExtractor(), probe])
    ctx = probe.seen[0]
    assert ctx["family"] == "pe"
    assert ctx["sha256"] == hashlib.sha256(content).hexdigest()


def test_random_access_extractor_gates_on_family(write):
    """How the v0.2 PE parser avoids opening every file it is handed."""
    probe = _Probe(gate=lambda ctx: ctx.get("family") == "pe")
    extractors = [FileTypeExtractor(), probe]

    analyse(write("a.txt", b"just text"), extractors=extractors)
    assert probe.seen == []

    analyse(write("b.exe", build_pe()), extractors=extractors)
    assert len(probe.seen) == 1


def test_a_failing_parse_does_not_lose_the_other_phases(write):
    """The isolation guarantee, restated for the third phase."""
    import hashlib

    class Exploding(RandomAccessExtractor):
        name = "exploding"

        def parse(self, path, ctx, config):
            raise ValueError("malformed section table")

    content = b"MZ" + b"\x00" * 500
    report = analyse(write("a.exe", content),
                     extractors=[Exploding(), HashExtractor(), EntropyExtractor()])
    assert "ValueError" in report.errors["exploding"]
    assert "exploding" not in report.data
    assert report.data["hashes"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert report.data["entropy"]["overall"] >= 0.0


def test_a_broken_parse_heuristic_does_not_lose_the_parsed_data(write):
    class BadFindings(_Probe):
        def findings(self, data, config):
            raise ZeroDivisionError("oops")

    report = analyse(write("a.bin", b"hello world!"), extractors=[BadFindings()])
    assert report.data["probe"]["tail"] == b"rld!".hex()
    assert "ZeroDivisionError" in report.errors["probe.findings"]


def test_an_oversized_sample_is_declined_out_loud(write):
    """A parser's cost is not bounded by the read sizes, so the ceiling is
    enforced by the pipeline. The refusal must be recorded: a report that
    silently skipped the analysis looks identical to one that found nothing."""
    probe = _Probe()
    report = analyse(write("big.bin", b"x" * 5000),
                     config={**DEFAULT_CONFIG, "max_parse_bytes": 1000},
                     extractors=[probe])
    assert probe.seen == []
    assert "probe" not in report.data
    assert "max_parse_bytes" in report.errors["probe"]


def test_the_ceiling_does_not_stop_the_earlier_phases(write):
    """Declining to parse is not declining to triage."""
    report = analyse(write("a.exe", build_pe()),
                     config={**DEFAULT_CONFIG, "max_parse_bytes": 10},
                     extractors=[FileTypeExtractor(), HashExtractor(), _Probe()])
    assert report.data["filetype"]["family"] == "pe"
    assert report.data["hashes"]["sha256"]
    assert "probe" in report.errors


def test_the_pipeline_still_reads_the_sample_once_itself(write, monkeypatch):
    """The v0.1.2 guarantee, restated now that a later phase may open the file
    again. The pipeline's own sequential pass is still exactly one read, and
    nothing anywhere calls read_bytes."""
    path = write("counted.bin", os.urandom(300_000))

    opens = []
    original = Path.open

    def counting_open(self, *args, **kwargs):
        if self == path:
            opens.append(self)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", counting_open)
    monkeypatch.setattr(
        Path, "read_bytes",
        lambda self: pytest.fail("read_bytes loads the whole sample into memory"))

    analyse(path, extractors=[HashExtractor(), EntropyExtractor()])
    assert len(opens) == 1

    # The probe opens the file for itself, which is exactly what the third
    # kind is permitted to do. One pipeline read, one deliberate parse open.
    opens.clear()
    analyse(path, extractors=[HashExtractor(), _Probe()])
    assert len(opens) == 2


def test_an_extractor_of_no_known_kind_is_reported_not_crashed(write):
    """v0.1.2 called `extract()` on anything that was not a header or stream
    extractor, and no class has ever defined it. The resulting AttributeError
    read as though the extractor had failed at its job rather than as though
    it had no contract."""
    class Neither(Extractor):
        name = "neither"

    report = analyse(write("a.bin", b"hello"),
                     extractors=[Neither(), HashExtractor()])
    assert "TypeError" in report.errors["neither"]
    assert "RandomAccessExtractor" in report.errors["neither"]
    assert report.data["hashes"]["sha256"]


# the PE extractor
#
# v0.2's payload. The fixture tests above establish that the synthetic PE
# contains what it was built to contain; these establish that the extractor
# reports what the fixture contains. Everything here needs pefile except the
# two tests about not having it.

DROPPER_IMPORTS = {"KERNEL32.dll": ["VirtualAlloc", "LoadLibraryA", "GetProcAddress"]}


def _pe_data(path, config=None):
    report = analyse(path, config=config)
    assert "pe" not in report.errors, report.errors["pe"]
    return report.data["pe"]


def test_the_pe_extractor_declines_anything_that_is_not_a_pe(write):
    """Gating is the contract that lets a parser exist at all: it must decide
    from `ctx` rather than by opening the file and finding out."""
    report = analyse(write("a.elf", b"\x7fELF" + b"\x00" * 4096))
    assert "pe" not in report.data
    assert "pe" not in report.errors


def test_a_pe_without_pefile_is_reported_rather_than_silently_skipped(write, monkeypatch):
    """numpy's absence is allowed to be silent because it costs only speed.
    pefile's absence costs findings, so a report that omits them has to say
    so: a clean-looking report on an unparsed executable is the failure mode
    this whole rule exists to prevent."""
    monkeypatch.setattr(extractors_module, "HAVE_PEFILE", False)
    report = analyse(write("a.exe", build_pe()))
    assert "pe" not in report.data
    assert "pefile" in report.errors["pe"]
    assert "ParserUnavailable" in report.errors["pe"]
    # and the rest of the run is untouched
    assert report.data["hashes"]["sha256"]
    assert report.data["filetype"]["family"] == "pe"


@needs_pefile
def test_pe_headers_reach_the_report(write):
    data = _pe_data(write("a.exe", build_pe(timestamp=1563164672)))
    assert data["pe_type"] == "PE32"
    assert data["machine_label"] == "I386"
    assert data["subsystem_label"] == "WINDOWS_CUI"
    assert data["timestamp"] == 1563164672
    assert data["timestamp_iso"].startswith("2019-07-15")
    assert data["is_dll"] is False
    assert data["entry_point_section"] == ".text"


@needs_pefile
def test_the_section_table_survives_the_round_trip(write):
    sections = [(".text", SECTION_CODE, b"\x90" * 0x400),
                (".rdata", SECTION_RDATA, b"const" * 100),
                (".evil", SECTION_RWX, os.urandom(0x400))]
    data = _pe_data(write("a.exe", build_pe(sections=sections)))
    by_name = {s["name"]: s for s in data["sections"]}
    assert list(by_name) == [".text", ".rdata", ".evil"]
    assert by_name[".text"]["executable"] and not by_name[".text"]["writable"]
    assert by_name[".rdata"]["readable"] and not by_name[".rdata"]["executable"]
    assert by_name[".evil"]["writable"] and by_name[".evil"]["executable"]


@needs_pefile
def test_per_section_entropy_separates_a_packed_section_from_a_padded_one(write):
    """The reason per-section entropy belongs to this extractor rather than to
    the entropy extractor: section boundaries do not exist until the file is
    parsed, and by then the stream phase's accumulator is gone."""
    sections = [(".text", SECTION_CODE, b"\x90" * 0x800),
                (".packed", SECTION_RWX, os.urandom(0x800))]
    data = _pe_data(write("a.exe", build_pe(sections=sections)))
    by_name = {s["name"]: s for s in data["sections"]}
    assert by_name[".packed"]["entropy_ratio"] > 0.98
    assert by_name[".text"]["entropy_ratio"] < 0.10
    assert by_name[".text"]["entropy"] == 0.0  # not -0.0, which JSON keeps


@needs_pefile
def test_a_section_too_short_to_score_reports_no_entropy_rather_than_a_guess(write):
    """The same rule the file-level extractor already follows: below roughly a
    window's worth of bytes the estimator is biased low enough to be
    misleading, so it declines instead of answering. File alignment means a
    real section is never smaller than 512 bytes, so the floor is what is
    raised here rather than the section lowered."""
    path = write("a.exe", build_pe(sections=[(".text", SECTION_CODE, b"\x90" * 8)]))
    data = _pe_data(path, config={**DEFAULT_CONFIG, "entropy_min_window_bytes": 4096})
    assert data["sections"][0]["entropy"] is None
    assert data["sections"][0]["entropy_ratio"] is None
    assert _pe_data(path)["sections"][0]["entropy"] is not None


@needs_pefile
def test_a_section_claiming_more_bytes_than_the_file_holds_is_scored_on_what_is_there(write):
    """A truncated sample keeps a section table that describes the file it
    used to be. Scoring the claim rather than the content would read past the
    mapping, so the extractor clips and records how much it actually scored."""
    body = build_pe(sections=[(".text", SECTION_CODE, os.urandom(0x1000))])
    data = _pe_data(write("a.exe", body[: len(body) - 0x800]))
    section = data["sections"][0]
    assert section["raw_size"] > section["scored_bytes"]
    assert section["entropy"] is not None


@needs_pefile
def test_imports_and_imphash_reach_the_report(write):
    data = _pe_data(write("a.exe", build_pe(imports=DROPPER_IMPORTS)))
    assert data["imports"] == DROPPER_IMPORTS
    assert data["import_count"] == 3
    assert data["imphash"] == _expected_imphash(DROPPER_IMPORTS)


@needs_pefile
def test_a_long_import_list_is_capped_for_display_but_not_for_imphash(write):
    """imphash is a correlation key, so it has to be computed over the whole
    table. The list in the report is for a human, so it has a ceiling, and the
    report says when it hit one."""
    names = [f"Function{n:03d}" for n in range(40)]
    path = write("a.exe", build_pe(imports={"KERNEL32.dll": names}))
    capped = _pe_data(path, config={**DEFAULT_CONFIG, "pe_max_listed_symbols": 10})
    full = _pe_data(path)
    assert len(capped["imports"]["KERNEL32.dll"]) == 10
    assert capped["imports_truncated"] is True
    assert capped["import_count"] == 40
    assert capped["imphash"] == full["imphash"]


@needs_pefile
def test_tls_callbacks_are_walked(write):
    """pefile parses the TLS directory but not the callback array it points
    at, so this walk is the extractor's own pointer arithmetic and needs its
    own fixture."""
    data = _pe_data(write("a.exe", build_pe(tls_callbacks=[0x401234, 0x401300])))
    assert data["tls_callbacks"] == [0x401234, 0x401300]


@needs_pefile
def test_the_tls_walk_is_capped_because_the_terminator_lives_in_the_file(write):
    """The array ends at a null the file supplies. A file that supplies none
    would otherwise be walked until something else stopped it."""
    path = write("a.exe", build_pe(tls_callbacks=[0x401000 + n for n in range(40)]))
    data = _pe_data(path, config={**DEFAULT_CONFIG, "pe_max_tls_callbacks": 5})
    assert len(data["tls_callbacks"]) == 5


@needs_pefile
def test_the_debug_directory_yields_the_pdb_path(write):
    """A build path is one of the few genuinely attributable strings in a
    stripped binary, which is why it is lifted to the top level."""
    data = _pe_data(write("a.exe", build_pe(pdb_path=r"C:\build\dropper.pdb")))
    assert data["pdb_path"] == r"C:\build\dropper.pdb"
    assert data["debug"][0]["type_label"] == "CODEVIEW"


@needs_pefile
def test_a_certificate_is_reported_as_present_and_never_as_valid(write):
    """v0.2 answers "whose name is in here" and refuses "is this trustworthy".
    The refusal is in the data, so a consumer cannot mistake one for the
    other."""
    blob = build_certificate(("Contoso Signing", "Contoso Root CA"))
    data = _pe_data(write("a.exe", build_pe(certificate=blob)))
    assert data["certificate"]["present"] is True
    assert data["certificate"]["validated"] is False
    assert data["certificate"]["common_names"] == ["Contoso Signing", "Contoso Root CA"]


@needs_pefile
def test_an_unsigned_pe_reports_an_absent_certificate_rather_than_nothing(write):
    data = _pe_data(write("a.exe", build_pe()))
    assert data["certificate"] == {"present": False, "common_names": [], "validated": False}


def test_the_common_name_scan_survives_a_blob_that_lies(write):
    """The scan reads lengths out of hostile bytes, so every truncated,
    over-long and undecodable case has to end the walk rather than raise."""
    oid = bytes.fromhex("0603550403")
    assert certificate_common_names(b"") == []
    assert certificate_common_names(oid) == []                      # ends abruptly
    assert certificate_common_names(oid + b"\x13\xff") == []        # length past the end
    assert certificate_common_names(oid + b"\x13\x40" + b"A" * 8) == []  # claims 64, has 8
    assert certificate_common_names(oid + b"\x13\x02\xff\xfe") == []     # not decodable
    assert certificate_common_names(oid + b"\x13\x03abc") == ["abc"]


@needs_pefile
def test_the_certificate_table_is_not_counted_as_an_overlay(write):
    """The format puts the signature past the last section, so a naive
    subtraction reports every signed binary as carrying an appended payload."""
    signed = _pe_data(write("signed.exe", build_pe(certificate=build_certificate())))
    assert signed["overlay"] is None

    both = _pe_data(write("both.exe", build_pe(overlay=b"P" * 5000,
                                               certificate=build_certificate())))
    assert both["overlay"]["size"] == 5000
    assert both["overlay"]["excludes_certificate"] is True


@needs_pefile
def test_the_overlay_is_measured_from_the_end_of_the_last_section(write):
    payload = os.urandom(20_000)
    data = _pe_data(write("a.exe", build_pe(imports=DROPPER_IMPORTS, overlay=payload)))
    assert data["overlay"]["size"] == len(payload)
    assert data["overlay"]["entropy_ratio"] > 0.98
    assert data["overlay"]["excludes_certificate"] is False


@needs_pefile
def test_a_region_larger_than_the_ceiling_is_marked_as_sampled(write):
    """A partial answer is fine. A partial answer that reads as a whole one is
    not, so the report carries the distinction."""
    path = write("a.exe", build_pe(sections=[(".text", SECTION_CODE, os.urandom(0x4000))]))
    data = _pe_data(path, config={**DEFAULT_CONFIG, "pe_region_entropy_bytes": 4096})
    assert data["sections"][0]["entropy_sampled"] is True
    assert _pe_data(path)["sections"][0]["entropy_sampled"] is False


@needs_pefile
def test_a_malformed_pe_is_reported_not_crashed(write):
    """Malformed headers are an anti-analysis technique, not an accident."""
    report = analyse(write("a.exe", b"MZ" + b"\x00" * 200))
    assert "pe" in report.errors
    assert "pe" not in report.data
    assert report.data["hashes"]["sha256"]  # the rest of the run survives


@needs_pefile
def test_one_broken_directory_does_not_cost_the_others(write, monkeypatch):
    """The pipeline isolates extractors from each other. Inside a parser the
    same argument applies one level down: an import table crafted to throw
    should not also cost the section table, the overlay and the hashes."""
    monkeypatch.setattr(PEExtractor, "_imports",
                        lambda *a, **k: (_ for _ in ()).throw(ValueError("crafted")))
    report = analyse(write("a.exe", build_pe(imports=DROPPER_IMPORTS, overlay=b"x" * 4096)))
    data = report.data["pe"]
    assert "pe" not in report.errors
    assert any("crafted" in p for p in data["parse_errors"])
    assert data["import_count"] == 0          # the default stood in
    assert [s["name"] for s in data["sections"]] == [".text", ".idata"]
    assert data["overlay"]["size"] == 4096


@needs_pefile
def test_parsing_a_pe_does_not_copy_it_into_memory(write):
    """tracemalloc cannot see mapped pages, so this does not prove the mapping
    is cheap. What it does catch is the mistake actually available here:
    calling `get_data()` on a section and scoring a whole copy of it, which is
    an ordinary Python allocation.

    Measured as a ratio rather than an absolute, for the same reason the
    streaming test is: an optional numpy adds a fixed cost on first use that
    dwarfs a bounded chunk and says nothing about whether the chunk is
    bounded. Eight times the section for well under twice the peak.
    """
    def peak_for(name, size):
        path = write(name, build_pe(sections=[(".big", SECTION_DATA, os.urandom(size))]))
        tracemalloc.reset_peak()
        analyse(path, extractors=[FileTypeExtractor(), PEExtractor()])
        return tracemalloc.get_traced_memory()[1]

    tracemalloc.start()
    try:
        peak_for("warm.exe", 1_000_000)  # pay any one-off cost before measuring
        small = peak_for("small.exe", 1_000_000)
        large = peak_for("large.exe", 8_000_000)
    finally:
        tracemalloc.stop()
    assert large < small * 2, (small, large)


@needs_pefile
def test_the_parse_phase_opens_the_sample_once_per_parser(write, monkeypatch):
    """The second open is the price the design accepted. It should not become
    a third."""
    path = write("a.exe", build_pe(imports=DROPPER_IMPORTS))
    monkeypatch.setattr(
        Path, "read_bytes",
        lambda self: pytest.fail("read_bytes loads the whole sample into memory"))
    opens = []
    original = Path.open
    monkeypatch.setattr(Path, "open", lambda self, *a, **k: (
        opens.append(self) if self == path else None, original(self, *a, **k))[1])
    analyse(path, extractors=[FileTypeExtractor(), PEExtractor()])
    assert len(opens) == 1  # pefile opens by name, not through Path.open


# PE findings
#
# The severity tiering is load-bearing rather than cosmetic: GATE_SEVERITY is
# medium, so every medium here is a new reason for this tool to exit non-zero
# in somebody's CI.

def _keys(report, severity=None):
    return {f["key"] for f in report.findings
            if severity is None or f["severity"] == severity}


@needs_pefile
def test_a_writable_executable_section_is_medium(write):
    report = analyse(write("a.exe", build_pe(
        sections=[(".text", SECTION_CODE, b"\x90" * 0x400),
                  (".evil", SECTION_RWX, b"\x90" * 0x400)])))
    assert "writable_executable_section" in _keys(report, "medium")


@needs_pefile
def test_an_entry_point_in_a_writable_section_is_medium(write):
    report = analyse(write("a.exe", build_pe(
        sections=[(".evil", SECTION_RWX, b"\x90" * 0x400)], entry_section=".evil")))
    assert "entry_point_in_writable_section" in _keys(report, "medium")


@needs_pefile
def test_a_known_packer_section_name_is_medium(write):
    report = analyse(write("a.exe", build_pe(
        sections=[("UPX0", SECTION_CODE, b"\x90" * 0x400),
                  ("UPX1", SECTION_CODE, b"\x90" * 0x400)])))
    assert "known_packer_section" in _keys(report, "medium")
    # a recognised packer name is not also merely "unusual"
    assert "nonstandard_section_name" not in _keys(report)


@needs_pefile
def test_a_section_reserving_far_more_memory_than_it_fills_is_medium(write):
    report = analyse(write("a.exe", build_pe(
        sections=[(".text", SECTION_CODE, b"\x90" * 0x100, 0x20000)])))
    assert "virtual_size_mismatch" in _keys(report, "medium")


@needs_pefile
def test_no_imports_at_all_is_medium_and_a_thin_table_is_low(write):
    stripped = analyse(write("a.exe", build_pe()))
    assert "no_imports" in _keys(stripped, "medium")

    thin = analyse(write("b.exe", build_pe(imports={"KERNEL32.dll": ["ExitProcess"]})))
    assert "few_imports" in _keys(thin, "low")
    assert "no_imports" not in _keys(thin)


@needs_pefile
def test_a_stripped_or_forged_timestamp_is_low(write):
    assert "implausible_timestamp" in _keys(
        analyse(write("zero.exe", build_pe(timestamp=0))), "low")
    assert "implausible_timestamp" in _keys(
        analyse(write("future.exe", build_pe(timestamp=4_000_000_000))), "low")
    assert "implausible_timestamp" not in _keys(
        analyse(write("normal.exe", build_pe(timestamp=1563164672))))


@needs_pefile
def test_a_large_overlay_is_low_and_a_small_one_is_only_information(write):
    big = analyse(write("big.exe", build_pe(overlay=os.urandom(2_000_000))))
    assert "large_overlay" in _keys(big, "low")

    small = analyse(write("small.exe", build_pe(overlay=b"note" * 64)))
    assert "overlay_present" in _keys(small, "info")
    assert "large_overlay" not in _keys(small)


@needs_pefile
def test_tls_callbacks_are_low_because_they_run_before_the_entry_point(write):
    report = analyse(write("a.exe", build_pe(tls_callbacks=[0x401234])))
    assert "tls_callbacks_present" in _keys(report, "low")


@needs_pefile
def test_a_present_signature_is_information_and_says_it_was_not_checked(write):
    report = analyse(write("a.exe", build_pe(certificate=build_certificate())))
    finding = next(f for f in report.findings if f["key"] == "signature_present")
    assert finding["severity"] == "info"
    assert "validates" in finding["detail"]


@needs_pefile
def test_nothing_the_pe_extractor_raises_is_high(write):
    """Stated in the design and worth pinning, because the temptation to
    promote a packer detection to high is permanent. Packing is not deception:
    it is the normal state of most commercial installers, and `high` is
    reserved for content that lies about what it is."""
    worst = build_pe(
        sections=[("UPX0", SECTION_RWX, os.urandom(0x800), 0x40000),
                  ("UPX1", SECTION_RWX, os.urandom(0x800))],
        timestamp=0, overlay=os.urandom(2_000_000), tls_callbacks=[0x401234],
        entry_section="UPX0", certificate=build_certificate())
    report = analyse(write("worst.exe", worst))
    pe_findings = [f for f in report.findings if f["extractor"] == "pe"]
    assert pe_findings
    assert not [f for f in pe_findings if f["severity"] == "high"]
    assert report.severity == "medium"


@needs_pefile
def test_a_benign_looking_pe_raises_nothing_alarming(write):
    """The other half of the tiering: an ordinary binary should not arrive
    covered in mediums, or the gate is useless."""
    benign = build_pe(
        sections=[(".text", SECTION_CODE, b"\x90" * 0x800),
                  (".rdata", SECTION_RDATA, b"string data " * 200),
                  (".data", SECTION_DATA, b"\x00" * 0x400)],
        imports={"KERNEL32.dll": ["CreateFileA", "WriteFile", "CloseHandle",
                                  "GetLastError", "ExitProcess"],
                 "USER32.dll": ["MessageBoxA", "LoadStringA"]},
        timestamp=1563164672)
    report = analyse(write("benign.exe", benign))
    assert _keys(report, "medium") == set()
    assert _keys(report, "high") == set()


# fuzzy hashing moved to the random-access phase

def test_the_stream_phase_no_longer_touches_the_disk(write):
    """ssdeep was the one component reading the sample a second time from
    inside the phase whose promise was that nothing did."""
    report = analyse(write("a.bin", b"hello world" * 500),
                     extractors=[HashExtractor()])
    assert "ssdeep" not in report.data["hashes"]
    assert set(report.data["hashes"]) == {"md5", "sha1", "sha256"}


def test_a_missing_fuzzy_hash_is_data_rather_than_an_error(write):
    """The asymmetry with pefile is deliberate. A missing parser removes
    findings and must be reported as a failure; a missing fuzzy hash removes a
    correlation key nothing in this release consumes, and reporting it as a
    failure would teach an analyst to skim past `report.errors`."""
    report = analyse(write("a.bin", b"hello world" * 500),
                     extractors=[FuzzyHashExtractor()])
    assert not report.errors
    data = report.data["fuzzy"]
    assert data["available"] is extractors_module.HAVE_SSDEEP
    if not extractors_module.HAVE_SSDEEP:
        assert data["ssdeep"] is None


@needs_pefile
def test_the_default_extractors_carry_both_random_access_kinds(write):
    report = analyse(write("a.exe", build_pe(imports=DROPPER_IMPORTS)))
    assert "pe" in report.data
    assert "fuzzy" in report.data


# hostile input
#
# One test per defect found by adversarially fuzzing the PE extractor after it
# was written. Every one of these files parses cleanly and reports something
# false or expensive; each is a single forged field in an otherwise valid PE,
# which is what "the input is hostile by assumption" means in practice.

def _patch(body, offset, value, fmt="<I"):
    """Overwrite one field in a built PE, leaving everything else valid."""
    out = bytearray(body)
    struct.pack_into(fmt, out, offset, value)
    return bytes(out)


def _directory_offset(index):
    """File offset of one data directory entry, for a fixture from build_pe."""
    return PE_HEADER_OFFSET + 4 + 20 + 96 + index * 8


def _debug_entry_offset(body):
    """File offset of the fixture's single IMAGE_DEBUG_DIRECTORY entry."""
    rva, _ = struct.unpack("<II", body[_directory_offset(6):_directory_offset(6) + 8])
    return next(s[2] for s in _fixture_sections(body) if s[1] == rva)


def _fixture_sections(body):
    """(name, rva, raw_pointer) for each section in a fixture."""
    count = struct.unpack("<H", body[PE_HEADER_OFFSET + 6:PE_HEADER_OFFSET + 8])[0]
    base = PE_HEADER_OFFSET + 4 + 20 + 224
    out = []
    for index in range(count):
        entry = body[base + index * 40: base + (index + 1) * 40]
        name = entry[:8].rstrip(b"\x00").decode()
        out.append((name, struct.unpack("<I", entry[12:16])[0],
                    struct.unpack("<I", entry[20:24])[0]))
    return out


@needs_pefile
def test_a_forged_pdb_length_cannot_pull_the_whole_sample_into_the_report(write):
    """A CodeView record's path is whatever follows a fixed prefix, and its
    length is a field in the file. pefile sizes its read from that field, so
    one DWORD turned a build path into a copy of the sample: a 40 MB file
    produced a 40 MB string and an 84 MB report with no error raised. The
    directory is walked here instead, and every read is given a length.

    `SizeOfData` is set to exactly the bytes remaining after the CodeView
    record, not to the file length. A larger value makes pefile's own unpack
    fail for an unrelated reason, so the test would pass against the unfixed
    code and pin nothing.
    """
    body = build_pe(pdb_path=r"C:\build\dropper.pdb", overlay=os.urandom(4_000_000))
    entry = _debug_entry_offset(body)
    record = entry + 28  # the CodeView record follows the directory entry
    hostile = _patch(body, entry + 16, len(body) - record)  # SizeOfData
    data = _pe_data(write("a.exe", hostile))
    assert data["pdb_path"] == r"C:\build\dropper.pdb"
    assert len(json.dumps(data)) < 100_000


@needs_pefile
def test_a_debug_record_reachable_only_by_file_pointer_is_still_read(write):
    """The entry carries both an RVA and a file pointer to the same bytes. A
    debug record is not required to be mapped, and reading only the RVA hands
    a one-DWORD eraser for the build path, which is one of the few
    attributable strings a stripped binary has."""
    body = build_pe(pdb_path=r"C:\build\dropper.pdb")
    hostile = _patch(body, _debug_entry_offset(body) + 20, 0)  # AddressOfRawData
    assert _pe_data(write("a.exe", hostile))["pdb_path"] == r"C:\build\dropper.pdb"


@needs_pefile
def test_a_tls_pointer_inside_the_image_but_in_no_section_invents_nothing(write):
    """Checking the RVA against `SizeOfImage` is not enough, because
    `SizeOfImage` is also a field in the file. An RVA inside the declared
    image but covered by no section falls through `pefile.get_data` to being
    treated as a raw file offset, which on a file with an overlay returned
    sixty-four callbacks read straight out of the appended payload."""
    body = build_pe(tls_callbacks=[0x401234], overlay=bytes(range(256)) * 512)
    tls_rva = struct.unpack("<I", body[_directory_offset(9):_directory_offset(9) + 4])[0]
    pointer = next(s[2] for s in _fixture_sections(body) if s[1] == tls_rva)
    hostile = _patch(_patch(body, PE_HEADER_OFFSET + 24 + 56, 0x10000000),  # SizeOfImage
                     pointer + 12, 0x400000 + 67584)                       # callbacks
    report = analyse(write("a.exe", hostile))
    assert report.data["pe"]["tls_callbacks"] == []
    assert "tls_callbacks_present" not in _keys(report)


@needs_pefile
def test_a_zeroed_size_of_headers_does_not_reopen_the_tls_walk(write):
    """The first guard was written against `SizeOfHeaders`, which is a field
    in the file, so zeroing it restored the original defect exactly."""
    body = build_pe(tls_callbacks=[0x401234])
    tls_rva = struct.unpack("<I", body[_directory_offset(9):_directory_offset(9) + 4])[0]
    pointer = next(s[2] for s in _fixture_sections(body) if s[1] == tls_rva)
    hostile = _patch(_patch(body, PE_HEADER_OFFSET + 24 + 60, 0),  # SizeOfHeaders
                     pointer + 12, 0x400000)                       # callbacks at rva 0
    assert _pe_data(write("a.exe", hostile))["tls_callbacks"] == []


@needs_pefile
def test_the_entropy_budget_cannot_be_evaded_by_reordering_the_section_table(write):
    """Spending the budget in table order lets a file starve a section by
    putting it last. Section order has no effect on loading, so that is a free
    evasion: move the packed section to the end and it is never scored."""
    packed = (".packed", SECTION_RWX, os.urandom(0x4000))
    filler = [(f".f{n}", SECTION_CODE, b"\x90" * 0x4000) for n in range(6)]
    config = {**DEFAULT_CONFIG, "pe_entropy_budget_bytes": 0x6000}

    first = _pe_data(write("a.exe", build_pe(sections=[packed] + filler)), config)
    last = _pe_data(write("b.exe", build_pe(sections=filler + [packed])), config)

    def packed_section(data):
        return next(s for s in data["sections"] if s["name"] == ".packed")

    assert packed_section(first)["entropy_ratio"] is not None
    # byte for byte, not merely "both got scored". A one-byte difference in
    # the grant moves the entropy figure in its fourth decimal place, which
    # makes the table order observable in the report.
    assert packed_section(first)["scored_bytes"] == packed_section(last)["scored_bytes"]
    assert packed_section(first)["entropy_ratio"] == packed_section(last)["entropy_ratio"]


@needs_pefile
def test_a_starved_section_declines_rather_than_scoring_a_handful_of_bytes(write):
    """Scoring 64 bytes of a 16 MB section produces a ratio above 1.0, because
    the reference model is out of range below about 128 bytes. That was a
    `medium` finding, and a non-zero exit, bought with a forged size field."""
    sections = [(f".s{n}", SECTION_CODE, os.urandom(0x2000)) for n in range(4)]
    path = write("a.exe", build_pe(sections=sections))
    data = _pe_data(path, config={**DEFAULT_CONFIG, "pe_entropy_budget_bytes": 600})
    starved = [s for s in data["sections"] if s["entropy_skipped"] == "budget_exhausted"]
    assert starved
    assert all(s["entropy"] is None and s["scored_bytes"] == 0 for s in starved)
    assert all((s["entropy_ratio"] or 0) <= 1.05 for s in data["sections"])


@needs_pefile
def test_an_exhausted_entropy_budget_is_reported_rather_than_read_as_absence(write):
    """A starved section used to be byte-identical in the report to a section
    that was empty or pointed past the end of the file. That is the same
    failure `entropy_sampled` and `scan_truncated` exist to prevent."""
    sections = [(f".s{n}", SECTION_CODE, os.urandom(0x2000)) for n in range(4)]
    report = analyse(write("a.exe", build_pe(sections=sections)),
                     config={**DEFAULT_CONFIG, "pe_entropy_budget_bytes": 600})
    assert any("budget" in note for note in report.data["pe"]["parse_errors"])
    assert "budget" in cli.render_human(report)


def test_the_entropy_budget_is_shared_by_size_not_by_position():
    share = extractors_module._share_budget
    assert share([100, 100, 100], 300) == [100, 100, 100]
    assert share([100, 100, 100], 30) == [10, 10, 10]
    # a small claim leaves its remainder to the others
    assert share([10, 1000, 1000], 210) == [10, 100, 100]
    # and the result does not depend on the order the claims arrive in
    assert share([1000, 10, 1000], 210) == [100, 10, 100]
    assert share([], 100) == []

    # equal claims get byte-identical grants even when the budget does not
    # divide evenly, because a remainder handed to whoever came last makes
    # the order observable
    assert share([16384] * 7, 0x6000) == [3510] * 7
    for wants in ([5, 5, 5, 5], [100, 7, 100, 7, 100], [1] * 9, [3, 3, 999]):
        for budget in (0, 1, 13, 97, 1000):
            grants = share(wants, budget)
            assert sum(grants) <= budget
            assert all(g <= w for g, w in zip(grants, wants))
            by_want = {}
            for want, grant in zip(wants, grants):
                by_want.setdefault(want, set()).add(grant)
            assert all(len(v) == 1 for v in by_want.values()), (wants, budget, grants)


def test_every_pefile_warning_reaches_the_human_output(write):
    """A fixed key printed the first warning and dropped the rest, and a
    malformed PE routinely produces five or more distinct ones."""
    report = analyse(write("a.bin", b"hello"), extractors=[HashExtractor()])
    report.data["pe"] = {"warnings": ["first", "second", "third"]}
    rendered = cli.render_human(report)
    assert all(w in rendered for w in ("first", "second", "third"))


@needs_pefile
def test_the_section_table_cannot_multiply_the_entropy_ceiling(write):
    """`pe_region_entropy_bytes` bounds one region; the number of regions is a
    field in the file. Two thousand sections each claiming the whole file took
    75 seconds against 0.3 for a normal sample of the same size, so the budget
    is spent across the table rather than granted to each section."""
    import time as _time
    sections = [(f".s{n:04d}", SECTION_CODE, os.urandom(0x200)) for n in range(64)]
    path = write("many.exe", build_pe(sections=sections))
    started = _time.monotonic()
    data = _pe_data(path, config={**DEFAULT_CONFIG, "pe_entropy_budget_bytes": 8192,
                                  "entropy_min_window_bytes": 256})
    assert _time.monotonic() - started < 10
    scored = sum(s["scored_bytes"] for s in data["sections"])
    assert scored <= 8192, scored
    # and the sections past the budget decline rather than guess
    assert any(s["entropy"] is None for s in data["sections"])


@needs_pefile
def test_a_tls_pointer_below_the_image_base_invents_no_callbacks(write):
    """`AddressOfCallBacks` minus `ImageBase` can be negative, and
    `pefile.get_data` resolves a negative RVA by slicing backwards from the
    end of the header buffer. That returned DOS-stub and section-table bytes
    dressed as callback addresses, and each one earned a finding."""
    body = build_pe(tls_callbacks=[0x401234])
    tls_rva = struct.unpack("<I", body[_directory_offset(9):_directory_offset(9) + 4])[0]
    pointer = next(s[2] for s in _fixture_sections(body) if s[1] == tls_rva)
    for address in (0x400000, 0x400000 - 96, 0x400000 - 132, 0x3FFFFF, 0xFFFFFFFF):
        hostile = _patch(body, pointer + 12, address)  # AddressOfCallBacks
        report = analyse(write("a.exe", hostile))
        data = report.data["pe"]
        assert data["tls_callbacks"] == [], (address, data["tls_callbacks"])
        assert "tls_callbacks_present" not in _keys(report)


@needs_pefile
def test_a_forged_security_directory_cannot_erase_the_overlay(write):
    """The certificate is subtracted from the overlay because the format puts
    it past the last section. A security directory claiming to start at the
    headers and run to the end of the file therefore deleted the overlay from
    the report: a dropper's payload hidden for the price of two DWORDs."""
    body = build_pe(overlay=os.urandom(3_000_000))
    hostile = _patch(_patch(body, _directory_offset(4), 0x40),
                     _directory_offset(4) + 4, len(body) - 0x40)
    report = analyse(write("a.exe", hostile))
    assert report.data["pe"]["overlay"]["size"] == 3_000_000
    assert "large_overlay" in _keys(report, "low")


@needs_pefile
def test_an_unreadable_import_table_is_not_reported_as_having_no_imports(write):
    """"No imports" and "an import table I could not follow" are different
    facts, and only the first is evidence of a self-loading binary. pefile
    signals the second with a warning and no parsed directory, which looked
    identical to the first: a forged import RVA bought a medium finding, and
    the gate exits non-zero on a medium."""
    body = build_pe(imports=DROPPER_IMPORTS)
    hostile = _patch(body, _directory_offset(1), 0xFFFFFFFF)
    report = analyse(write("a.exe", hostile))
    assert "no_imports" not in _keys(report)
    assert report.data["pe"]["imports_parsed"] is False
    # and the failure to look is on the report rather than swallowed
    assert report.data["pe"]["warnings"]


@needs_pefile
def test_a_truly_stripped_import_table_is_still_reported(write):
    """The other side of the gate above: a file that genuinely imports nothing
    must still earn the finding, or the fix has removed the check."""
    report = analyse(write("a.exe", build_pe()))
    assert report.data["pe"]["imports_parsed"] is True
    assert "no_imports" in _keys(report, "medium")


@needs_pefile
def test_a_certificate_scan_that_stopped_early_says_so(write):
    """`region_entropy` marks a sampled figure; the certificate scan had no
    equivalent, so a name past the ceiling was indistinguishable from no name."""
    blob = build_certificate(("Front Name",)) + b"\x00" * 50_000 + \
        build_certificate(("Hidden Name",))
    path = write("a.exe", build_pe(certificate=blob))
    data = _pe_data(path, config={**DEFAULT_CONFIG, "pe_max_certificate_bytes": 4096})
    assert data["certificate"]["common_names"] == ["Front Name"]
    assert data["certificate"]["scan_truncated"] is True
    assert data["certificate"]["scanned_bytes"] == 4096
    assert _pe_data(path)["certificate"]["scan_truncated"] is False


@needs_pefile
def test_scored_bytes_reports_what_was_read_not_what_was_claimed(write):
    """It was computed before the ceiling was applied, so a capped region
    recorded a byte count nobody had read."""
    path = write("a.exe", build_pe(sections=[(".text", SECTION_CODE, os.urandom(0x4000))]))
    data = _pe_data(path, config={**DEFAULT_CONFIG, "pe_region_entropy_bytes": 4096})
    section = data["sections"][0]
    assert section["scored_bytes"] == 4096
    assert section["entropy_sampled"] is True


def test_region_entropy_declines_a_region_it_could_not_read(write):
    """Zero is the entropy of a flat region. A region that was never read is
    not a flat region, and returning 0.0 for one made an unreadable section
    indistinguishable from a padded one."""
    data = b"hello world" * 100
    assert extractors_module.region_entropy(data, 0, 0, 4096) == (None, None, False, 0)
    assert extractors_module.region_entropy(data, 0, -5, 4096) == (None, None, False, 0)
    assert extractors_module.region_entropy(data, -1, 10, 4096) == (None, None, False, 0)
    assert extractors_module.region_entropy(data, 10_000, 500, 4096) == (None, None, False, 0)
    assert extractors_module.region_entropy(data, 0, 10, 0) == (None, None, False, 0)
    # a region that runs off the end scores the part that exists, and says so
    entropy, ratio, sampled, scored = extractors_module.region_entropy(data, 1000, 500, 4096)
    assert entropy is not None and sampled is True and scored == len(data) - 1000


@needs_pefile
def test_incomplete_analysis_reaches_the_human_output(write):
    """`parse_errors` and pefile's warnings were written into the report and
    rendered nowhere, so a file that defeated a directory printed as a clean
    scan with no findings."""
    body = build_pe(imports=DROPPER_IMPORTS)
    report = analyse(write("a.exe", _patch(body, _directory_offset(1), 0xFFFFFFFF)))
    rendered = cli.render_human(report)
    assert "incomplete:" in rendered
    assert "pe.warning" in rendered


# YARA
#
# v0.3 adds pattern matching. The bundled rules describe structure rather than
# naming families, so every one of them is demonstrable against a fixture
# `sample_data.py` can build, which is the standard the authoring notes set.

try:  # only the rule tests need it
    import yara
except ImportError:
    yara = None

needs_yara = pytest.mark.skipif(yara is None, reason="the rule tests require yara-python")

RULE_DIR = Path(extractors_module.__file__).resolve().parent / "rules"


def _carrier(payload=b"", prefix=b"%PDF-1.7\n"):
    """A PDF-looking file with something buried in it."""
    return prefix + b"%" + b"filler " * 64 + b"\n" + payload + b"\n%%EOF\n"


def _yara_data(path, config=None):
    report = analyse(path, config=config)
    assert "yara" not in report.errors, report.errors["yara"]
    return report.data["yara"]


def _rules_of(data):
    return {m["rule"] for m in data["matches"]}


def test_the_bundled_rules_are_text_and_carry_a_severity_each():
    """Rules ship as source in the repository, which is only safe because they
    describe structure rather than embedding sample bytes. And a rule that
    declares no severity scores `info`, so the bundled set declares one
    everywhere rather than relying on that."""
    files = sorted(RULE_DIR.glob("*.yar"))
    assert files, "the bundled rule set is missing"
    declared = 0
    for path in files:
        # Split on declarations at column zero, so prose in the file header
        # that happens to contain the word "rule" is not counted as one.
        blocks = re.split(r"^rule\s+", path.read_text(), flags=re.MULTILINE)[1:]
        assert blocks, f"{path.name} declares no rules"
        for block in blocks:
            name = block.split()[0]
            severity = re.search(r'severity\s*=\s*"([^"]+)"', block)
            assert severity, f"{name} declares no severity"
            assert severity.group(1) in SEVERITIES, (name, severity.group(1))
            declared += 1
    assert declared >= 5


@needs_yara
def test_every_bundled_rule_compiles():
    for path in sorted(RULE_DIR.glob("*.yar")):
        yara.compile(filepath=str(path))


@needs_yara
def test_no_bundled_rule_reaches_high():
    """The same discipline the PE extractor is held to. `high` means content
    that lies about what it is, and a byte pattern is not in a position to
    establish deception."""
    for path in sorted(RULE_DIR.glob("*.yar")):
        assert '"high"' not in path.read_text()


@needs_yara
def test_an_embedded_executable_is_found_in_a_document(write):
    """The rule the bundled set exists for: no extractor sees this, because
    the file really is a PDF and the payload is just bytes inside it."""
    data = _yara_data(write("carrier.pdf", _carrier(build_pe())))
    assert "embedded_pe_header" in _rules_of(data)
    match = next(m for m in data["matches"] if m["rule"] == "embedded_pe_header")
    assert match["severity"] == "medium"
    assert "structural" in match["tags"]


@needs_yara
def test_a_clean_executable_does_not_trip_the_embedded_rule(write):
    """A PE is not a PE carrying a PE. The rule anchors on `uint16(0)` for
    exactly this."""
    assert "embedded_pe_header" not in _rules_of(_yara_data(write("a.exe", build_pe())))


@needs_yara
def test_a_base64_encoded_executable_is_found(write):
    """An executable encoded as text is one somebody wanted to move through
    something that only carries text."""
    import base64
    body = b"var payload = '" + base64.b64encode(build_pe()) + b"';"
    assert "base64_encoded_pe_header" in _rules_of(_yara_data(write("a.js", body)))


@needs_yara
def test_random_data_does_not_trip_the_bundled_rules(write):
    """This tool is pointed at packed and encrypted files by definition, so a
    rule set that fires on entropy is a rule set that fires constantly. The
    DOS stub requirement in `embedded_pe_header` is what buys this."""
    for name in ("a.bin", "b.bin", "c.bin"):
        assert _rules_of(_yara_data(write(name, os.urandom(400_000)))) == set()


@needs_yara
def test_a_findings_key_is_stable_while_rule_names_are_not(write):
    """Every match files under one key, with the rule name in the detail and
    the data. Rules are user-extensible, and a key set that grows with
    somebody's rules directory is not one a dashboard can count on."""
    report = analyse(write("carrier.pdf", _carrier(build_pe())))
    matched = [f for f in report.findings if f["extractor"] == "yara"]
    assert matched
    assert {f["key"] for f in matched} == {"yara_match"}
    assert any("embedded_pe_header" in f["detail"] for f in matched)


@needs_yara
def test_a_finding_carries_offsets_and_never_the_matched_bytes(write):
    """The portfolio rule: a report is stored, piped and shared, and a rule
    that matched a credential would otherwise put the credential in it. There
    is no switch for this, so there is nothing to leave switched on."""
    marker = b"SECRETVALUE_DO_NOT_LEAK"
    source = ('rule leaky { meta: severity = "low" strings: $s = "%s" condition: $s }'
              % marker.decode())
    rules = write("leaky.yar", source.encode())
    path = write("a.bin", b"x" * 100 + marker + b"y" * 100)
    report = analyse(path, config={**DEFAULT_CONFIG, "yara_rule_paths": [str(rules)]})

    blob = json.dumps(report.to_dict())
    assert "leaky" in blob                      # the rule fired
    assert marker.decode() not in blob          # and the bytes are not in the report
    match = next(m for m in report.data["yara"]["matches"] if m["rule"] == "leaky")
    assert match["strings"][0]["offsets"] == [100]
    assert match["strings"][0]["lengths"] == [len(marker)]


@needs_yara
def test_a_rule_declares_its_own_severity_and_a_silent_rule_is_only_information(write):
    """A rule that forgot to say how much it matters must not be able to fail
    somebody's build by forgetting. `GATE_SEVERITY` is medium."""
    rules = write("mixed.yar", b'''
rule loud { meta: severity = "medium" strings: $a = "alpha" condition: $a }
rule quiet { strings: $b = "bravo" condition: $b }
rule nonsense_severity { meta: severity = "catastrophic" strings: $c = "charlie" condition: $c }
''')
    config = {**DEFAULT_CONFIG, "yara_rule_paths": [str(rules)]}
    report = analyse(write("a.bin", b"alpha bravo charlie"), config=config)
    by_rule = {m["rule"]: m["severity"] for m in report.data["yara"]["matches"]}
    assert by_rule == {"loud": "medium", "quiet": "info", "nonsense_severity": "info"}


@needs_yara
def test_one_broken_rule_file_does_not_disable_the_others(write):
    """Compiling every file in one call loses the whole set to a syntax error
    anywhere in it. This is the pipeline's isolation applied to rule files: a
    rule somebody is halfway through writing disables that file and nothing
    else."""
    broken = write("broken.yar", b"rule wrong { condition: nonsense }")
    report = analyse(write("carrier.pdf", _carrier(build_pe())),
                     config={**DEFAULT_CONFIG, "yara_rule_paths": [str(broken)]})
    data = report.data["yara"]
    assert "embedded_pe_header" in _rules_of(data)      # the bundled set survived
    assert any("broken.yar" in p for p in data["parse_errors"])
    assert "yara" not in report.errors
    rendered = cli.render_human(report)
    assert "incomplete:" in rendered and "broken.yar" in rendered   # and not silent


def test_no_rules_configured_is_silence_and_no_parser_is_an_error(write, monkeypatch):
    """Two different facts. Nothing to scan with is not a failure; a rule set
    that exists and cannot be run is."""
    monkeypatch.setattr(extractors_module, "BUNDLED_RULES", Path("/nonexistent"))
    report = analyse(write("a.bin", b"hello"))
    assert "yara" not in report.data and "yara" not in report.errors

    monkeypatch.undo()
    monkeypatch.setattr(extractors_module, "HAVE_YARA", False)
    report = analyse(write("b.bin", b"hello"))
    assert "yara-python" in report.errors["yara"]
    assert report.data["hashes"]["sha256"]  # the rest of the run is untouched


@needs_yara
def test_a_rule_set_that_does_not_finish_is_reported_not_read_as_no_matches(write,
                                                                           monkeypatch):
    """maltriage's one standing gap is a parser that hangs rather than raises.
    yara takes a timeout and raises on it, so this is the first extractor that
    closes it for itself — and a timeout has to reach the report, because "did
    not finish" and "found nothing" are different answers."""
    class TimesOut:
        def match(self, *args, **kwargs):
            raise yara.TimeoutError("scanning timed out")

    monkeypatch.setattr(extractors_module, "compile_rules",
                        lambda paths, allow=False: ([("structural", TimesOut())], []))
    report = analyse(write("carrier.pdf", _carrier(build_pe())))
    data = report.data["yara"]
    assert data["match_count"] == 0
    assert any("timed out" in p.lower() for p in data["parse_errors"])
    assert "incomplete" in cli.render_human(report)


@needs_yara
def test_a_rule_that_matches_everywhere_is_capped(write):
    """A one-byte string matches roughly every 256 bytes, and the offsets list
    is in the report."""
    rules = write("noisy.yar", b'rule noisy { strings: $a = "A" condition: $a }')
    config = {**DEFAULT_CONFIG, "yara_rule_paths": [str(rules)], "yara_max_matches": 10,
              "yara_fast_matching": False}
    data = _yara_data(write("a.bin", b"A" * 5000), config)
    string = data["matches"][0]["strings"][0]
    assert len(string["offsets"]) == 10
    assert string["count"] == 5000
    assert string["truncated"] is True
    assert data["fast_matching"] is False


@needs_yara
def test_the_bundled_carrier_sample_is_caught_by_a_rule(tmp_path):
    """The demo directory should contain something the newest release has an
    opinion about, or a first run of the tool shows none of v0.3."""
    write_samples(tmp_path)
    report = analyse(tmp_path / "carrier.pdf")
    assert "yara" not in report.errors, report.errors
    assert "embedded_pe_header" in _rules_of(report.data["yara"])
    assert report.severity == "medium"


@needs_yara
def test_rules_are_compiled_once_for_a_directory_rather_than_once_per_file(tmp_path,
                                                                          monkeypatch):
    """Compiling is the expensive part of a yara run and matching is the cheap
    part. Until v0.3 `analyse_directory` built a fresh extractor set per file,
    so the reuse the StreamExtractor contract has always described was pinned
    by a test and never exercised in the production path."""
    write_samples(tmp_path)
    compiles = []
    original = extractors_module.compile_rules
    monkeypatch.setattr(
        extractors_module, "compile_rules",
        lambda paths, allow=False: (compiles.append(paths), original(paths, allow))[1])
    reports = analyse_directory(tmp_path)
    assert len(reports) > 3
    assert len(compiles) == 1, f"compiled {len(compiles)} times for {len(reports)} files"


# YARA under hostile rules and hostile samples
#
# One test per defect found by fuzzing the extractor after it was written.
# Half of these are about the rules rather than the sample, which is the new
# thing in v0.3: a rules directory is an extension point, and an extension
# point is an input.

@needs_yara
def test_a_match_bomb_does_not_cost_memory_in_proportion_to_the_sample(write):
    """libyara caps a string at a million matches and yara-python builds an
    object for each, so a four-byte string against a crafted sample cost
    220 MB on a 4 MB file. Fast matching records the first occurrence of each
    string instead, which is the difference between bounded and merely
    finite."""
    bomb = write("bomb.bin", b"X" + b"\x7fELF\x02\x01\x01" * 500_000)
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        data = _yara_data(bomb)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert data["fast_matching"] is True
    assert peak < 8_000_000, peak
    for match in data["matches"]:
        for string in match["strings"]:
            assert string["count"] == 1


@needs_yara
def test_a_rule_cannot_write_the_sample_to_stdout(write, capfd):
    """YARA's `console` module writes to the process's own stdout when nothing
    captures it. A rule could therefore dump the sample to the terminal, under
    `--quiet`, without a byte of it appearing in the report — the one channel
    that defeated "the extractor never reads matched_data"."""
    marker = b"SECRETBYTES-do-not-print"
    rules = write("console.yar", b'''
import "console"
rule dump { meta: severity = "info" condition: for all i in (0..23) : ( console.hex(uint8(i)) ) }
''')
    path = write("a.bin", marker + b"x" * 100)
    capfd.readouterr()
    report = analyse(path, config={**DEFAULT_CONFIG, "yara_rule_paths": [str(rules)]})
    captured = capfd.readouterr()
    assert "0x" not in captured.out and "0x" not in captured.err
    assert marker.decode() not in json.dumps(report.to_dict())


@needs_yara
def test_a_rule_file_cannot_include_its_way_out_of_the_rules_directory(write):
    """An include is resolved relative to the rule file and confined to
    nothing, so `include "/etc/passwd"` was opened and parsed — and YARA
    quotes offending tokens back in its syntax errors, which puts arbitrary
    file content in reach of the report."""
    rules = write("escape.yar", b'include "/etc/passwd"\nrule r { condition: true }')
    config = {**DEFAULT_CONFIG, "yara_rule_paths": [str(rules)]}
    report = analyse(write("a.bin", b"hello"), config=config)
    problems = " ".join(report.data["yara"]["parse_errors"])
    assert "includes are disabled" in problems
    assert "root:" not in json.dumps(report.to_dict())

    # and it is a decision somebody can take deliberately
    allowed = analyse(write("b.bin", b"hello"),
                      config={**config, "yara_allow_includes": True})
    assert "includes are disabled" not in " ".join(
        allowed.data["yara"].get("parse_errors") or [])


@needs_yara
def test_an_unusable_rule_path_is_reported_rather_than_skipped(write, tmp_path):
    """Every one of these produced a report claiming a full YARA run while the
    configured rules never executed, with nothing but a log line on stderr —
    which is not in the artefact that gets stored and piped."""
    unreadable = tmp_path / "locked"
    unreadable.mkdir()
    for bad in (str(tmp_path / "nowhere.yar"), "", 42, None, str(tmp_path)):
        report = analyse(write("a.bin", b"hello"),
                         config={**DEFAULT_CONFIG, "yara_rule_paths": [bad]})
        problems = report.data["yara"].get("parse_errors") or []
        if bad == str(tmp_path):
            continue  # a real directory with no rule files in it is not an error
        assert problems, f"{bad!r} was skipped silently"
        assert "incomplete:" in cli.render_human(report)


@needs_yara
def test_naming_the_bundled_directory_does_not_double_every_finding(write):
    """Configured paths add to the bundled set rather than replacing it, so
    naming it is a natural thing to write — and it emitted every match twice,
    including the medium the CI gate reads."""
    config = {**DEFAULT_CONFIG, "yara_rule_paths": [str(RULE_DIR)]}
    report = analyse(write("carrier.pdf", _carrier(build_pe())), config=config)
    data = report.data["yara"]
    assert data["namespaces"] == ["structural"]
    assert len(data["matches"]) == len({m["rule"] for m in data["matches"]})
    keys = [f["detail"] for f in report.findings if f["extractor"] == "yara"]
    assert len(keys) == len(set(keys))


@needs_yara
def test_a_changed_rule_set_is_recompiled_rather_than_answered_from_cache(write):
    """`analyse_directory` hands one extractor instance to every file, so the
    compile cache needs a key. Without one it answered with whichever rule set
    it saw first, while reporting the files it was asked for — a stale result
    presented as a current one, which is worse than recompiling."""
    first = write("first.yar", b'rule alpha { meta: severity = "low" strings: $a = "alpha" condition: $a }')
    second = write("second.yar", b'rule bravo { meta: severity = "low" strings: $b = "bravo" condition: $b }')
    sample = write("a.bin", b"alpha and bravo")
    shared = default_extractors()

    a = analyse(sample, {**DEFAULT_CONFIG, "yara_rule_paths": [str(first)]}, shared)
    b = analyse(sample, {**DEFAULT_CONFIG, "yara_rule_paths": [str(second)]}, shared)
    assert _rules_of(a.data["yara"]) & {"alpha"} == {"alpha"}
    assert _rules_of(b.data["yara"]) & {"bravo"} == {"bravo"}
    assert "alpha" not in _rules_of(b.data["yara"])
    assert "second.yar" in b.data["yara"]["rule_files"]

    # an edit to the same path is picked up too
    first.write_bytes(b'rule gamma { meta: severity = "low" strings: $c = "alpha" condition: $c }')
    c = analyse(sample, {**DEFAULT_CONFIG, "yara_rule_paths": [str(first)]}, shared)
    assert "gamma" in _rules_of(c.data["yara"])


@needs_yara
def test_an_unhashable_default_severity_falls_back_instead_of_crashing(write):
    """`config.get` followed by `x in SEVERITY_RANK` raises on an unhashable
    value, and the pipeline then loses the whole extractor: every match
    discarded because one config value was a list."""
    rules = write("silent.yar", b'rule quiet { strings: $a = "alpha" condition: $a }')
    for bad in ([], {}, set(), ["info"], 3):
        report = analyse(write("a.bin", b"alpha"),
                         config={**DEFAULT_CONFIG, "yara_rule_paths": [str(rules)],
                                 "yara_default_severity": bad})
        assert "yara" not in report.errors, (bad, report.errors)
        assert report.data["yara"]["matches"][0]["severity"] == "info"


@needs_yara
def test_the_scan_budget_is_spent_across_the_rule_set_not_per_file(write, monkeypatch):
    """The timeout bounded each rule file, and the number of rule files is a
    directory listing rather than a bound: a hundred of them at ten seconds
    each is a thousand seconds per sample, multiplied again by every file in
    a directory scan.

    Driven by fake rule sets rather than by genuinely slow rules, because a
    version of this test built from real ones passed against the unfixed code:
    four files at a second each never approach any plausible wall-clock
    assertion, and the pre-fix `TimeoutError` text satisfies a loose check on
    the message.
    """
    class Slow:
        def match(self, *args, **kwargs):
            time.sleep(0.3)
            return []

    monkeypatch.setattr(extractors_module, "compile_rules",
                        lambda paths, allow=False: ([(f"slow{n}", Slow()) for n in range(12)], []))
    started = time.monotonic()
    report = analyse(write("a.bin", b"hello"),
                     config={**DEFAULT_CONFIG, "yara_timeout_seconds": 1})
    elapsed = time.monotonic() - started

    problems = report.data["yara"].get("parse_errors") or []
    assert elapsed < 2.5, elapsed                       # not 12 x 0.3
    assert sum("budget was already spent" in p for p in problems) >= 6


@needs_yara
def test_two_broken_rule_files_with_the_same_name_both_reach_the_output(write, tmp_path):
    """The renderer keyed its lines on the extractor and the note's first
    token, so two files called bad.yar collapsed to one line — understating
    how thin the report is, which is what the block exists to prevent."""
    for name, token in (("one", "alpha_missing"), ("two", "bravo_missing")):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "bad.yar").write_bytes(b"rule broken { condition: %s }" % token.encode())
    config = {**DEFAULT_CONFIG,
              "yara_rule_paths": [str(tmp_path / "one"), str(tmp_path / "two")]}
    report = analyse(write("a.bin", b"hello"), config=config)
    rendered = cli.render_human(report)
    assert "alpha_missing" in rendered and "bravo_missing" in rendered


@needs_yara
@pytest.mark.parametrize("ident", [
    b"\x00\x01\x01",   # EI_CLASS 0, which no ELF has
    b"\x03\x01\x01",   # EI_CLASS 3
    b"\x02\x00\x01",   # EI_DATA 0
    b"\x02\x03\x01",   # EI_DATA 3
    b"\x02\x01\x00",   # EI_VERSION 0
    b"\x02\x01\x02",   # EI_VERSION 2
])
def test_the_elf_rule_ignores_magic_bytes_with_an_impossible_identifier(write, ident):
    """The four magic bytes alone occur once every 4 GB of random data, which
    made an existing test fail about once in 3600 runs and dirtied real
    reports on packed samples.

    Asserted against specific impossible identifiers rather than against a
    pile of random data. A random-data version of this test has about a 0.1%
    chance of catching the unconstrained rule, so it reproduces the flake it
    documents instead of pinning the fix.
    """
    body = _carrier(b"\x7fELF" + ident + b"\x00" * 64)
    assert "embedded_elf_header" not in _rules_of(_yara_data(write("a.pdf", body)))


@needs_yara
@pytest.mark.parametrize("trial", range(4))
def test_the_bundled_rules_stay_quiet_on_random_data(write, trial):
    """Weak on its own, kept because it is the shape the tool actually meets:
    this thing is pointed at packed and encrypted files by definition."""
    assert _rules_of(_yara_data(write(f"r{trial}.bin", os.urandom(400_000)))) == set()


@needs_yara
def test_the_elf_rule_still_fires_on_a_real_embedded_header(write):
    """The other half: constraining it must not stop it working."""
    body = _carrier(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
    assert "embedded_elf_header" in _rules_of(_yara_data(write("a.pdf", body)))


@needs_yara
def test_a_rule_that_reads_its_own_match_count_is_bounded_by_the_scan_ceiling(write):
    """Fast matching is not a bound on its own. libyara ignores it for any
    string whose condition reads that string's count, offset or length, and
    `#a > 5` is one of the most common idioms in public rule sets. What the
    extractor can bound is how much file it hands over, which is the same
    refusal `max_parse_bytes` already makes one level up."""
    rules = write("counts.yar", b'''
rule counts_its_matches {
    meta: severity = "low"
    strings: $a = "AAAAAAAAAAAAAAAA"
    condition: #a > 5
}
''')
    config = {**DEFAULT_CONFIG, "yara_rule_paths": [str(rules)],
              "yara_max_scan_bytes": 65536}
    report = analyse(write("big.bin", b"A" * 4_000_000), config=config)
    data = report.data["yara"]
    assert data["match_count"] == 0
    assert any("yara_max_scan_bytes" in p for p in data["parse_errors"])
    assert "incomplete:" in cli.render_human(report)
    # and the rest of the run is unaffected
    assert report.data["hashes"]["sha256"]


@needs_yara
def test_a_count_reported_under_fast_matching_does_not_claim_to_be_a_total(write):
    """`truncated` is the field whose whole job is to say nothing was left
    out, and under fast matching it said that about an enumeration cut off
    after the first hit."""
    bomb = write("bomb.bin", b"X" + b"\x7fELF\x02\x01\x01" * 100_000)
    fast = _yara_data(bomb)
    string = fast["matches"][0]["strings"][0]
    assert string["count"] == 1
    assert string["complete"] is False        # the count is not a total

    full = _yara_data(bomb, config={**DEFAULT_CONFIG, "yara_fast_matching": False,
                                    "yara_max_scan_bytes": 10_000_000})
    string = full["matches"][0]["strings"][0]
    assert string["count"] == 100_000
    assert string["complete"] is False        # truncated by yara_max_matches instead


@needs_yara
def test_turning_includes_off_takes_effect_on_a_reused_extractor(write):
    """The compile cache keyed on the rule files and not on the other input to
    the compile, so an include-bearing set compiled permissively kept running
    after the caller had explicitly asked for includes to be off."""
    included = write("payload.yarinc",
                     b'rule from_include { meta: severity = "low" strings: $a = "alpha" condition: $a }')
    host = write("host.yar", b'include "%s"' % str(included).encode())
    sample = write("a.bin", b"alpha")
    shared = default_extractors()
    config = {**DEFAULT_CONFIG, "yara_rule_paths": [str(host)]}

    permissive = analyse(sample, {**config, "yara_allow_includes": True}, shared)
    assert "from_include" in _rules_of(permissive.data["yara"])

    refused = analyse(sample, {**config, "yara_allow_includes": False}, shared)
    assert "from_include" not in _rules_of(refused.data["yara"])
    assert any("includes are disabled" in p
               for p in refused.data["yara"]["parse_errors"])


@needs_yara
def test_a_broken_entry_inside_a_rules_directory_is_reported_not_dropped(write, tmp_path):
    """A rules directory holding a dangling symlink, a symlink loop or a
    directory named `sub.yar` used to lose those entries without a word, which
    silently shortens the rule set. A moved rules repository or an
    unchecked-out submodule is ordinary breakage."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "kept.yar").write_bytes(
        b'rule kept { meta: severity = "low" strings: $a = "alpha" condition: $a }')
    (rules / "dangling.yar").symlink_to(tmp_path / "gone.yar")
    (rules / "sub.yar").mkdir()

    report = analyse(write("a.bin", b"alpha"),
                     config={**DEFAULT_CONFIG, "yara_rule_paths": [str(rules)]})
    data = report.data["yara"]
    assert "kept" in _rules_of(data)                    # the good file survived
    problems = " ".join(data["parse_errors"])
    assert "dangling.yar" in problems and "sub.yar" in problems
    assert "incomplete:" in cli.render_human(report)


def test_a_switch_written_as_a_string_is_reported_rather_than_absorbed():
    """`"yara_fast_matching": "false"` and `: 0` are what somebody reaches for
    in a JSON config, and both left the switch on while the report stated the
    setting they thought they had turned off."""
    for bad in ("false", "true", 0, 1, "no", [], None):
        problems = validate_config({"yara_fast_matching": bad})
        assert problems, bad
        assert "true or false" in problems[0]
    assert validate_config({"yara_fast_matching": False}) == []
    assert extractors_module.config_bool({"k": "false"}, "k", True) is True
    assert extractors_module.config_bool({"k": False}, "k", True) is False
