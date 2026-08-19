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
import statistics
import tracemalloc
from pathlib import Path

import pytest

import cli
from extractors import (
    EntropyExtractor,
    Extractor,
    FileTypeExtractor,
    HashExtractor,
    RandomAccessExtractor,
    StreamExtractor,
    byte_counts,
    entropy_from_counts,
    expected_random_entropy,
    shannon,
)
from models import SEVERITIES, mk_finding
from pipeline import analyse, analyse_directory
from sample_data import (
    DEFAULT_CONFIG,
    SECTION_CODE,
    SECTION_RWX,
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
    """The context is how v0.5 enrichment will find its lookup key."""
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
    assert parsed["schema_version"] == "1.2"
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
