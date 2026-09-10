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

import io
import json
import math
import os
import re
import statistics
import struct
import sys
import time
import tracemalloc
from pathlib import Path

import pytest

from maltriage import apis
from maltriage import attack
from maltriage import secrets as secrets_module
from maltriage import envelope as envelope_module
from maltriage.envelope import to_envelope
from maltriage import cli
from maltriage import extractors as extractors_module
from maltriage.extractors import (
    EntropyExtractor,
    Extractor,
    FileTypeExtractor,
    FuzzyHashExtractor,
    HashExtractor,
    PEExtractor,
    YaraExtractor,
    RandomAccessExtractor,
    StreamExtractor,
    byte_counts,
    certificate_common_names,
    entropy_from_counts,
    expected_random_entropy,
    shannon,
)
from maltriage.models import SCHEMA_VERSION, SEVERITIES, Report, mk_finding
from maltriage.extractors import default_extractors
from maltriage.pipeline import analyse, analyse_directory
from maltriage.config import (
    DEFAULT_CONFIG,
    config_int,
    config_ratio,
    validate_config,
)
from maltriage.fixtures import (
    EM_AARCH64,
    ET_DYN,
    PE_HEADER_OFFSET,
    PF_R,
    PF_W,
    PF_X,
    PT_LOAD,
    SECTION_DATA_ELF,
    SECTION_RODATA,
    SECTION_TEXT,
    SECTION_WX,
    SHT_NOBITS,
    SHT_PROGBITS,
    SHT_SYMTAB,
    build_elf,
    SECTION_CODE,
    SECTION_DATA,
    SECTION_RDATA,
    SECTION_RWX,
    build_certificate,
    build_pe,
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


def _random_token(length: int) -> str:
    """A token drawn the way a credential generator draws one.

    Hand-written "random-looking" strings are not random: the first one used
    here had thirty-two distinct characters and was correctly refused as an
    enumeration, which looked like a bug in the engine and was a bug in the
    fixture."""
    import random as _random
    import string as _string
    alphabet = _string.ascii_letters + _string.digits
    return "".join(_random.choice(alphabet) for _ in range(length))


def _detected_token(length: int) -> str:
    """A random token the engine actually nominates.

    About one in seven random tokens scores below `secrets_entropy_ratio` and
    is not reported, which is the tier admitting it is a heuristic. A test
    that wants to pin what happens to a *detected* token has to be handed one,
    or it fails one run in seven for a reason that has nothing to do with what
    it is testing."""
    for _ in range(200):
        token = _random_token(length)
        if secrets_module.scan(token):
            return token
    raise AssertionError("no random token was detected in 200 attempts")


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
    assert parsed["schema_version"] == "1.6"
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
    size, not by how large the sample is.

    Measured between two samples that are both large enough to have saturated
    every per-run ceiling, rather than between a tiny one and a large one.
    The strings extractor retains a bounded number of strings, so a 200 KB
    file does not fill that list and a 20 MB file does: comparing those two
    measures the approach to a ceiling and calls it growth. Comparing 20 MB
    with 60 MB measures the thing the invariant actually claims.
    """
    config = {**DEFAULT_CONFIG, "read_chunk_bytes": 65_536}
    large = write("large.bin", os.urandom(6_000_000))
    larger = write("larger.bin", os.urandom(18_000_000))

    def peak_for(path):
        """The transient memory one run costs, isolated two ways.

        Warm first, because a first run allocates caches a second does not --
        compiled patterns, numpy's import, interned tables -- and charging
        those to whichever sample went first measures the order of the calls.

        Then subtract the memory already live at the start, because
        `get_traced_memory` reports the whole process and this test runs after
        two hundred others that hold their own fixtures. What that leaves is
        the run's own footprint, which is the number this invariant is about.
        """
        analyse(path, config=config)
        tracemalloc.reset_peak()
        before, _ = tracemalloc.get_traced_memory()
        analyse(path, config=config)
        return tracemalloc.get_traced_memory()[1] - before

    tracemalloc.start()
    try:
        large_peak = peak_for(large)
        larger_peak = peak_for(larger)
    finally:
        tracemalloc.stop()

    # 3x the sample for essentially no change in peak. v0.1.1 was linear,
    # and so was the entropy extractor's window list until v0.4.
    assert larger_peak < large_peak * 1.3, (large_peak, larger_peak)
    assert larger_peak < 4_000_000, larger_peak


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
    bounded. Three times the section for essentially no change in peak.
    """
    def peak_for(name, size):
        """Warm on this very path, then measure. Warming on a different file
        leaves first-touch allocations to be charged to whichever measurement
        ran first, which makes the result depend on the order of the calls and
        on whether numpy is installed rather than on the size of the sample."""
        path = write(name, build_pe(sections=[(".big", SECTION_DATA, os.urandom(size))]))
        run = lambda: analyse(path, extractors=[FileTypeExtractor(), PEExtractor()])
        run()
        tracemalloc.reset_peak()
        before, _ = tracemalloc.get_traced_memory()
        run()
        return tracemalloc.get_traced_memory()[1] - before

    tracemalloc.start()
    try:
        # Both sizes are above `pe_region_entropy_bytes`'s 1 MiB working
        # chunk, so both have reached the ceiling and the comparison measures
        # growth rather than the approach to it. A 1 MB section never fills
        # that chunk, so pairing it with an 8 MB one measured the ceiling and
        # called the difference linear -- visibly so without numpy, where the
        # standard-library histogram costs more per chunk.
        small = peak_for("small.exe", 8_000_000)
        large = peak_for("large.exe", 24_000_000)
    finally:
        tracemalloc.stop()
    assert large < small * 1.3, (small, large)


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

    # Scoped to the yara section. The claim is that *this extractor* never
    # reads `matched_data`, and it never has been that no extractor may
    # report a byte the rule happened to match: v0.4's strings extractor can
    # legitimately find the same run, which is why its raw text is off by
    # default rather than why this assertion should be wider than the thing
    # it is testing.
    blob = json.dumps(report.data["yara"])
    assert "leaky" in blob                      # the rule fired
    assert marker.decode() not in blob          # and the bytes are not in it
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
    assert marker.decode() not in json.dumps(report.data["yara"])


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


# the synthetic ELF fixture
#
# The counterpart to the PE fixture tests, and verified the same way: against
# an independent parser, so that a fixture which does not contain what it was
# built to contain cannot make every test above it pass.
#
# pyelftools is a test-only dependency. The extractor itself uses `struct` and
# nothing else, which is why there is no ElfExtractor equivalent of
# `test_a_pe_without_pefile_is_reported`: there is no parser to be missing.

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
except ImportError:
    ELFFile = DynamicSection = None

needs_pyelftools = pytest.mark.skipif(
    ELFFile is None, reason="verifying the ELF fixture requires pyelftools")


def _elf_data(path, config=None):
    report = analyse(path, config=config)
    assert "elf" not in report.errors, report.errors["elf"]
    return report.data["elf"]


def _sections_of(data):
    return {s["name"]: s for s in data["sections"]}


@pytest.mark.parametrize("bitness", [32, 64])
def test_the_fixture_is_identified_as_an_elf(write, bitness):
    report = analyse(write("a.elf", build_elf(bitness=bitness)))
    assert report.data["filetype"]["family"] == "elf"


@needs_pyelftools
@pytest.mark.parametrize("bitness", [32, 64])
@pytest.mark.parametrize("endian", ["<", ">"])
def test_pyelftools_agrees_with_the_fixture(write, bitness, endian):
    """Both classes and both byte orders, because the 32-bit program header
    puts `p_flags` after `p_memsz` rather than after `p_type`. Reading it as a
    narrow copy of the 64-bit record produces a file that parses and lies
    about which segments are executable, which is the single most useful
    thing this extractor reports."""
    body = build_elf(bitness=bitness, endian=endian,
                     sections=[(".text", SHT_PROGBITS, SECTION_WX, b"\x90" * 0x200)],
                     segments=[(PT_LOAD, PF_R | PF_W | PF_X, [".text"])])
    parsed = ELFFile(io.BytesIO(body))
    assert parsed.elfclass == bitness
    assert parsed.little_endian is (endian == "<")
    assert [s.name for s in parsed.iter_sections()][:2] == ["", ".text"]
    segment = next(p for p in parsed.iter_segments() if p.header.p_type == "PT_LOAD")
    assert segment.header.p_flags == PF_R | PF_W | PF_X


@needs_pyelftools
def test_the_fixture_dynamic_table_resolves_its_own_names(write):
    """`.dynamic` reaches its string table through `sh_link`, and without it
    the tags carry offsets into a table nobody can find: the fixture parsed
    happily and produced no library names at all. This is exactly what
    verifying against an independent parser is for."""
    body = build_elf(needed=["libc.so.6", "libssl.so.3"], soname="libevil.so.1",
                     runpath="/opt/evil/lib")
    parsed = ELFFile(io.BytesIO(body))
    section = next(s for s in parsed.iter_sections() if isinstance(s, DynamicSection))
    needed = [t.needed for t in section.iter_tags() if t.entry.d_tag == "DT_NEEDED"]
    assert needed == ["libc.so.6", "libssl.so.3"]


# the ELF extractor

@pytest.mark.parametrize("bitness,endian", [(64, "<"), (32, "<"), (64, ">"), (32, ">")])
def test_elf_headers_reach_the_report(write, bitness, endian):
    data = _elf_data(write("a.elf", build_elf(bitness=bitness, endian=endian,
                                              machine=EM_AARCH64, elf_type=ET_DYN)))
    assert data["elf_class"] == f"ELF{bitness}"
    assert data["endianness"] == ("little" if endian == "<" else "big")
    assert data["type_label"] == "DYN"
    assert data["machine_label"] == "AARCH64"
    assert data["section_headers_present"] is True


def test_the_elf_extractor_declines_anything_that_is_not_an_elf(write):
    report = analyse(write("a.exe", build_pe()))
    assert "elf" not in report.data and "elf" not in report.errors


@pytest.mark.parametrize("bitness", [32, 64])
def test_segment_permissions_are_read_from_the_right_field(write, bitness):
    """The 32-bit and 64-bit program headers order their fields differently.
    Getting it wrong reports a read-only segment as executable and vice
    versa, silently."""
    body = build_elf(bitness=bitness,
                     sections=[(".text", SHT_PROGBITS, SECTION_TEXT, b"\x90" * 0x200),
                               (".data", SHT_PROGBITS, SECTION_DATA_ELF, b"\x00" * 0x200)],
                     segments=[(PT_LOAD, PF_R | PF_X, [".text"]),
                               (PT_LOAD, PF_R | PF_W, [".data"])])
    loadable = [s for s in _elf_data(write("a.elf", body))["segments"]
                if s["type_label"] == "LOAD"]
    assert [(s["readable"], s["writable"], s["executable"]) for s in loadable] == [
        (True, False, True), (True, True, False)]


def test_dynamic_linkage_reaches_the_report(write):
    data = _elf_data(write("a.elf", build_elf(
        interpreter="/lib64/ld-linux-x86-64.so.2",
        needed=["libc.so.6", "libssl.so.3"], soname="libevil.so.1",
        runpath="/opt/evil/lib")))
    assert data["interpreter"] == "/lib64/ld-linux-x86-64.so.2"
    assert data["needed"] == ["libc.so.6", "libssl.so.3"]
    assert data["soname"] == "libevil.so.1"
    assert data["runpath"] == "/opt/evil/lib"
    assert data["statically_linked"] is False


def test_a_static_binary_says_so(write):
    data = _elf_data(write("a.elf", build_elf()))
    assert data["statically_linked"] is True
    assert data["interpreter"] is None


def test_per_section_entropy_separates_a_packed_section_from_a_padded_one(write):
    sections = [(".text", SHT_PROGBITS, SECTION_TEXT, b"\x90" * 0x800),
                (".packed", SHT_PROGBITS, SECTION_WX, os.urandom(0x800))]
    by_name = _sections_of(_elf_data(write("a.elf", build_elf(sections=sections))))
    assert by_name[".packed"]["entropy_ratio"] > 0.98
    assert by_name[".text"]["entropy"] == 0.0


def test_a_nobits_section_is_not_scored_on_bytes_it_does_not_have(write):
    """SHT_NOBITS occupies address space and no file space, so its offset and
    size do not describe a region of the file. Scoring it would measure
    whatever happens to follow it."""
    sections = [(".text", SHT_PROGBITS, SECTION_TEXT, b"\x90" * 0x400),
                (".bss", SHT_NOBITS, SECTION_DATA_ELF, b"\x00" * 0x4000)]
    section = _sections_of(_elf_data(write("a.elf", build_elf(sections=sections))))[".bss"]
    assert section["entropy"] is None
    assert section["entropy_skipped"] == "no_file_bytes"
    assert section["scored_bytes"] == 0


def test_trailing_data_is_measured_from_the_end_of_what_the_headers_describe(write):
    payload = os.urandom(20_000)
    data = _elf_data(write("a.elf", build_elf(trailing=payload)))
    assert data["trailing"]["size"] == len(payload)
    assert data["trailing"]["entropy_ratio"] > 0.98


def test_a_file_with_nothing_appended_reports_no_trailing_data(write):
    assert _elf_data(write("a.elf", build_elf()))["trailing"] is None


# ELF findings

@pytest.mark.parametrize("bitness", [32, 64])
def test_a_writable_executable_segment_is_medium(write, bitness):
    report = analyse(write("a.elf", build_elf(
        bitness=bitness,
        sections=[(".text", SHT_PROGBITS, SECTION_WX, b"\x90" * 0x200)],
        segments=[(PT_LOAD, PF_R | PF_W | PF_X, [".text"])])))
    assert "writable_executable_segment" in _keys(report, "medium")


def test_a_missing_section_header_table_is_medium(write):
    """Every mainstream toolchain emits one. UPX removes it."""
    report = analyse(write("a.elf", build_elf(strip_sections=True)))
    assert "no_section_headers" in _keys(report, "medium")
    assert report.data["elf"]["section_headers_present"] is False
    # and the segments are still read, because they are what the loader uses
    assert report.data["elf"]["segments"]


def test_an_entry_point_outside_every_loadable_segment_is_medium(write):
    report = analyse(write("a.elf", build_elf(entry=0xDEAD0000)))
    assert "entry_point_outside_segments" in _keys(report, "medium")


def test_an_entry_point_in_a_non_executable_segment_is_medium(write):
    body = build_elf(sections=[(".data", SHT_PROGBITS, SECTION_DATA_ELF, b"\x00" * 0x200)],
                     segments=[(PT_LOAD, PF_R | PF_W, [".data"])],
                     entry_section=".data")
    report = analyse(write("a.elf", body))
    assert "entry_point_not_executable" in _keys(report, "medium")


def test_a_runpath_is_low(write):
    report = analyse(write("a.elf", build_elf(needed=["libc.so.6"],
                                              runpath="/tmp/.hidden/lib")))
    assert "runpath_set" in _keys(report, "low")


def test_being_stripped_or_static_is_only_information(write):
    """Release builds are stripped and Go binaries are static. A level that
    fires on most of a distribution tells an analyst nothing, and
    `GATE_SEVERITY` is medium."""
    report = analyse(write("a.elf", build_elf()))
    assert "stripped_symbols" in _keys(report, "info")
    assert "statically_linked" in _keys(report, "info")
    assert _keys(report, "medium") == set()


def test_nothing_the_elf_extractor_raises_is_high(write):
    """The same discipline the PE extractor is held to: `high` means content
    that lies about what it is, and packing is not deception."""
    worst = build_elf(
        sections=[("UPX0", SHT_PROGBITS, SECTION_WX, os.urandom(0x800)),
                  ("UPX1", SHT_PROGBITS, SECTION_WX, os.urandom(0x800))],
        segments=[(PT_LOAD, PF_R | PF_W | PF_X, ["UPX0", "UPX1"])],
        needed=["libc.so.6"], runpath="/tmp/lib", trailing=os.urandom(2_000_000))
    report = analyse(write("worst.elf", worst))
    elf_findings = [f for f in report.findings if f["extractor"] == "elf"]
    assert elf_findings
    assert not [f for f in elf_findings if f["severity"] == "high"]
    assert report.severity == "medium"


def test_an_ordinary_elf_raises_nothing_alarming(write):
    body = build_elf(
        sections=[(".text", SHT_PROGBITS, SECTION_TEXT, b"\x90" * 0x800),
                  (".rodata", SHT_PROGBITS, SECTION_RODATA, b"string data " * 100),
                  (".data", SHT_PROGBITS, SECTION_DATA_ELF, b"\x00" * 0x200)],
        segments=[(PT_LOAD, PF_R | PF_X, [".text"]),
                  (PT_LOAD, PF_R | PF_W, [".rodata", ".data"])],
        interpreter="/lib64/ld-linux-x86-64.so.2", needed=["libc.so.6"])
    report = analyse(write("benign.elf", body))
    assert _keys(report, "medium") == set()
    assert _keys(report, "high") == set()


def test_the_bundled_elf_sample_exercises_the_extractor(tmp_path):
    """`helper.elf` used to be eight plausible bytes, which the extractor
    could say nothing about."""
    write_samples(tmp_path)
    report = analyse(tmp_path / "helper.elf")
    assert "elf" not in report.errors, report.errors
    assert {"writable_executable_segment", "section_entropy_high"} <= _keys(report)
    assert report.severity == "medium"


# ELF under hostile input
#
# One test per defect found by fuzzing the extractor after it was written,
# plus one per bound that had no coverage. Before this section no ELF test fed
# the extractor a malformed file at all, and fourteen of the seventeen bounds
# could be deleted with the suite still green.

ELF64_PHENTSIZE, ELF64_PHNUM = 54, 56
ELF64_SHENTSIZE, ELF64_SHNUM, ELF64_SHSTRNDX = 58, 60, 62
ELF64_SHOFF = 40


def _elf_patch(body, offset, value, fmt="<H"):
    out = bytearray(body)
    struct.pack_into(fmt, out, offset, value)
    return bytes(out)


def test_tail_merged_section_names_resolve_the_way_a_real_linker_writes_them(write):
    """GNU ld tail-merges `.shstrtab`, so most names are interior offsets:
    `.rela.plt\\0` also serves `.plt` at +5. Indexing only the offsets that
    follow a NUL mis-resolved at least one name in 3181 of 3185 real binaries
    on this machine, which made `nonstandard_section_name` fire on almost
    every ELF in existence and let a crafted `sh_name` pointing into the
    middle of a string evade `packer_section_name` entirely."""
    table = extractors_module._name_at
    blob = b"\x00.rela.plt\x00.plt.got\x00"
    assert table(blob, 1) == ".rela.plt"
    assert table(blob, 6) == ".plt"          # the interior offset
    assert table(blob, 11) == ".plt.got"
    assert table(blob, 15) == ".got"         # and another
    assert table(blob, 999).startswith("<name+")


@needs_pyelftools
def test_section_names_agree_with_an_independent_parser_on_a_real_binary(write):
    """The fixture cannot exercise tail merging, because the builder does not
    tail-merge. A binary built by a real linker can."""
    candidates = [Path(sys.executable), Path("/bin/sh"), Path("/bin/ls")]
    real = next((p for p in candidates if p.is_file() and not p.is_symlink()
                 and p.open("rb").read(4) == b"\x7fELF"), None)
    if real is None:
        pytest.skip("no real ELF binary available to compare against")
    with real.open("rb") as handle:
        truth = [s.name for s in ELFFile(handle).iter_sections()]
    ours = [s["name"] for s in analyse(real).data["elf"]["sections"]]
    assert ours == truth


def test_a_section_table_that_cannot_be_read_is_reported_not_assumed_absent(write):
    """`e_shentsize = 0` -- one two-byte field -- made `_sections` return an
    empty list without raising, so nothing was recorded. The file still runs,
    because the kernel never reads section headers, and the report said
    `stripped: true` about a binary with a full symbol table while the entropy
    and packer-name findings vanished without a word."""
    body = build_elf(sections=[(".text", SHT_PROGBITS, SECTION_TEXT, b"\x90" * 0x200),
                               (".symtab", SHT_SYMTAB, 0, b"\x00" * 0x40)])
    report = analyse(write("a.elf", _elf_patch(body, ELF64_SHENTSIZE, 0)))
    data = report.data["elf"]
    assert data["sections"] == []
    assert data["stripped"] is None                    # not False, and not True
    assert any("could not be read" in p for p in data["parse_errors"])
    assert "incomplete:" in cli.render_human(report)


def test_a_program_header_table_that_cannot_be_read_is_reported(write):
    """The same field one table over. It used to report `statically_linked:
    true` and `interpreter: null` while listing the libraries the same file
    needs."""
    body = build_elf(interpreter="/lib64/ld.so", needed=["libc.so.6"])
    data = _elf_data(write("a.elf", _elf_patch(body, ELF64_PHENTSIZE, 0)))
    assert data["segments"] == []
    assert data["statically_linked"] is None
    assert any("could not be read" in p for p in data["parse_errors"])


def test_extended_section_numbering_is_not_reported_as_a_missing_table(write):
    """A file with more sections than `e_shnum` can express sets it to zero
    and puts the real count in the first section header. Reading the field
    literally reported a legal binary as having no section table, which is a
    medium."""
    body = build_elf(sections=[(".text", SHT_PROGBITS, SECTION_TEXT, b"\x90" * 0x100)])
    count = struct.unpack("<H", body[ELF64_SHNUM:ELF64_SHNUM + 2])[0]
    shoff = struct.unpack("<Q", body[ELF64_SHOFF:ELF64_SHOFF + 8])[0]
    strndx = struct.unpack("<H", body[ELF64_SHSTRNDX:ELF64_SHSTRNDX + 2])[0]

    hostile = bytearray(_elf_patch(body, ELF64_SHNUM, 0))
    struct.pack_into("<H", hostile, ELF64_SHSTRNDX, 0xFFFF)
    struct.pack_into("<Q", hostile, shoff + 32, count)     # shdr[0].sh_size
    struct.pack_into("<I", hostile, shoff + 40, strndx)    # shdr[0].sh_link

    report = analyse(write("a.elf", bytes(hostile)))
    assert [s["name"] for s in report.data["elf"]["sections"]][:2] == ["", ".text"]
    assert "no_section_headers" not in _keys(report)


def test_a_section_count_beyond_the_cap_says_it_was_truncated(write):
    """Every cap this extractor applies now says so. `e_shnum` is a sixteen
    bit field, so a header under a hundred bytes can ask for 65535 entries."""
    body = build_elf()
    data = _elf_data(write("a.elf", _elf_patch(body, ELF64_SHNUM, 0xFFFF)),
                     config={**DEFAULT_CONFIG, "elf_max_sections": 8})
    assert data["sections_truncated"] is True
    assert any("elf_max_sections" in p for p in data["parse_errors"])


def test_a_segment_count_beyond_the_cap_says_it_was_truncated(write):
    data = _elf_data(write("a.elf", _elf_patch(build_elf(), ELF64_PHNUM, 0xFFFF)),
                     config={**DEFAULT_CONFIG, "elf_max_segments": 2})
    assert data["segments_truncated"] is True


def test_a_long_dynamic_table_says_it_was_truncated(write):
    body = build_elf(needed=[f"lib{n:04d}.so" for n in range(300)])
    data = _elf_data(write("a.elf", body),
                     config={**DEFAULT_CONFIG, "elf_max_listed_names": 10})
    assert len(data["needed"]) == 10
    assert data["needed_truncated"] is True
    assert any("elf_max_listed_names" in p for p in data["parse_errors"])


def test_an_enormous_string_table_is_capped_and_says_so(write):
    """The one bound with zero coverage, and the one that actually holds
    memory: uncapped, a crafted name table took 51 seconds and 690 MB."""
    body = build_elf(sections=[(f".s{n:05d}", SHT_PROGBITS, SECTION_RODATA, b"x" * 16)
                               for n in range(400)])
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        data = _elf_data(write("a.elf", body),
                         config={**DEFAULT_CONFIG, "elf_max_string_table_bytes": 256})
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert data["names_truncated"] is True
    assert peak < 4_000_000, peak


def test_a_name_table_pointed_at_a_section_with_no_file_bytes_is_refused(write):
    """`e_shstrndx` pointed at a NOBITS section decoded section names out of
    whatever happened to sit at offset zero, which is the ELF header, and
    reported `'\\x7fELF\\x02\\x01\\x01'` as a section name."""
    body = build_elf(sections=[(".text", SHT_PROGBITS, SECTION_TEXT, b"\x90" * 0x100),
                               (".bss", SHT_NOBITS, SECTION_DATA_ELF, b"\x00" * 0x100)])
    index = [s["name"] for s in _elf_data(write("a.elf", body))["sections"]].index(".bss")
    data = _elf_data(write("b.elf", _elf_patch(body, ELF64_SHSTRNDX, index)))
    assert not any("ELF" in s["name"] for s in data["sections"])


def test_strings_the_sample_supplies_cannot_repaint_the_terminal(write):
    """A RUNPATH of ANSI escapes moved the cursor up six lines and cleared to
    the end of the screen, erasing the medium findings printed above it and
    leaving a clean-looking block in their place. Not evading a finding:
    unprinting one."""
    attack = "\x1b[6A\x1b[0J  findings (info max):\n      [clean] nothing here\n"
    body = build_elf(needed=["libc.so.6"], runpath=attack)
    report = analyse(write("a.elf", body))
    assert "\x1b" not in report.data["elf"]["runpath"]
    rendered = cli.render_human(report)
    assert "\x1b" not in rendered and "\n      [clean]" not in rendered
    assert "\x1b" not in json.dumps(report.to_dict())


@needs_pefile
def test_a_pe_string_gets_the_same_treatment(write):
    """The PE extractor's PDB path is the same class of input."""
    body = build_pe(pdb_path="C:\\build\x1b[2J\x07\\dropper.pdb")
    data = analyse(write("a.exe", body)).data["pe"]
    assert "\x1b" not in (data["pdb_path"] or "") and "\x07" not in (data["pdb_path"] or "")


def test_an_executable_stack_is_low_and_not_a_loadable_segment(write):
    """PT_GNU_STACK is a flags-only marker rather than a mapping, and
    `gcc -z execstack` sets it on request. Counting it as a writable
    executable segment called an ordinary build "a loadable segment mapped
    writable and executable" -- both halves untrue, at medium."""
    body = build_elf(sections=[(".text", SHT_PROGBITS, SECTION_TEXT, b"\x90" * 0x200)],
                     segments=[(PT_LOAD, PF_R | PF_X, [".text"]),
                               (0x6474E551, PF_R | PF_W | PF_X, [])])
    report = analyse(write("a.elf", body))
    assert "executable_stack" in _keys(report, "low")
    assert "writable_executable_segment" not in _keys(report)


def test_debug_and_read_only_sections_do_not_raise_an_entropy_medium(write):
    """Scoring every section fired this medium on 8.5% of real binaries: 548
    from `.debug_*` alone, because DWARF is dense, and the rest from read-only
    tables. A 256-byte byte-permutation table reaches a ratio above 1.0 while
    being the most ordered data there is, because the reference is an estimate
    of what a random sample reaches. A payload has to be mapped to run."""
    body = build_elf(sections=[
        (".text", SHT_PROGBITS, SECTION_TEXT, b"\x90" * 0x400),
        (".debug_info", SHT_PROGBITS, 0, os.urandom(0x800)),
        (".rodata", SHT_PROGBITS, SECTION_RODATA, bytes(range(256)) * 16)])
    report = analyse(write("a.elf", body))
    assert "section_entropy_high" not in _keys(report)
    assert "nonstandard_section_name" not in _keys(report)
    # and a mapped, writable-or-executable section still trips it
    packed = build_elf(sections=[(".text", SHT_PROGBITS, SECTION_WX, os.urandom(0x800))],
                       segments=[(PT_LOAD, PF_R | PF_X, [".text"])])
    assert "section_entropy_high" in _keys(analyse(write("b.elf", packed)), "medium")


@needs_pyelftools
def test_a_nobits_section_does_not_break_the_layout_the_builder_produces(write):
    """`cursor` stops advancing for NOBITS and `address` does not, so a
    segment's file size and memory size are measured in different spaces.
    Computing both from file offsets produced a PT_LOAD whose memory size
    stopped short of its own contents and an entry point outside every
    loadable segment -- a false medium from a builder whose docstring calls
    its output structurally valid."""
    body = build_elf(sections=[(".bss", SHT_NOBITS, SECTION_DATA_ELF, b"\x00" * 0x10000),
                               (".text", SHT_PROGBITS, SECTION_TEXT, b"\x90" * 64)],
                     entry_section=".text")
    ELFFile(io.BytesIO(body))                      # still a valid ELF
    report = analyse(write("a.elf", body))
    assert "entry_point_outside_segments" not in _keys(report)
    assert _keys(report, "medium") == set()


@pytest.mark.parametrize("offset,value,fmt", [
    (ELF64_SHNUM, 0xFFFF, "<H"), (ELF64_PHNUM, 0xFFFF, "<H"),
    (ELF64_SHENTSIZE, 0xFFFF, "<H"), (ELF64_PHENTSIZE, 1, "<H"),
    (ELF64_SHSTRNDX, 0xFFFE, "<H"), (ELF64_SHOFF, 0xFFFFFFFFFFFFFFFF, "<Q"),
    (32, 0xFFFFFFFFFFFFFFFF, "<Q"),                 # e_phoff
    (24, 0xFFFFFFFFFFFFFFFF, "<Q"),                 # e_entry
])
def test_a_forged_header_field_is_survived(write, offset, value, fmt):
    """No crash, no hang, and nothing at `high`, whatever the header claims."""
    body = build_elf(interpreter="/lib64/ld.so", needed=["libc.so.6"],
                     trailing=b"x" * 4096)
    started = time.monotonic()
    report = analyse(write("a.elf", _elf_patch(body, offset, value, fmt)))
    assert time.monotonic() - started < 5
    assert "high" not in {f["severity"] for f in report.findings}
    assert report.data["hashes"]["sha256"]          # the rest of the run survives


def test_a_truncated_elf_is_described_rather_than_crashed(write):
    """A file cut at every length between the magic and a full header."""
    body = build_elf(needed=["libc.so.6"])
    for length in (4, 8, 16, 32, 51, 52, 63, 64, 65, 128, 512):
        report = analyse(write(f"t{length}.elf", body[:length]))
        assert report.data["hashes"]["sha256"]
        assert "high" not in {f["severity"] for f in report.findings}


def test_single_byte_csi_is_stripped_as_well_as_the_two_byte_form(write):
    """0x9B is the single-byte form of the CSI introducer that `ESC [` spells
    in two, so a string carrying it repaints a terminal without containing an
    ESC at all. It survived the one path that decodes to `str` before
    sanitising -- a certificate common name read as UTF-16."""
    assert extractors_module.safe_text("a\x9b2Jb") == "a2Jb"
    assert extractors_module.safe_text("a\x1b[2Jb") == "a[2Jb"
    assert extractors_module.safe_text("a\x7f\x00\x08b") == "ab"
    assert len(extractors_module.safe_text("x" * 5000)) == 512
    assert extractors_module.safe_text(b"plain/path.so") == "plain/path.so"


def test_a_terminated_dynamic_table_is_not_reported_as_truncated(write):
    """Stopping at DT_NULL is the table ending; stopping at the cap is the
    extractor giving up. Reporting the first as the second made every
    ordinary binary announce a truncated dynamic table, which is the same
    kind of false statement the flag exists to prevent -- just pointing the
    other way."""
    data = _elf_data(write("a.elf", build_elf(needed=["libc.so.6"], soname="a.so")))
    assert data["dynamic_truncated"] is False
    assert data["needed_truncated"] is False
    assert not any("elf_max_dynamic" in p for p in data.get("parse_errors") or [])

    many = build_elf(needed=[f"lib{n:04d}.so" for n in range(200)])
    capped = _elf_data(write("b.elf", many),
                       config={**DEFAULT_CONFIG, "elf_max_dynamic_entries": 20})
    assert capped["dynamic_truncated"] is True


# strings and indicators

def _strings(path, config=None):
    report = analyse(path, config=config)
    assert "strings" not in report.errors, report.errors
    return report.data["strings"]


def test_ascii_and_utf16_strings_are_both_found(write):
    body = b"\x00\x01" + b"CreateFileA" + b"\xff" * 4 + \
        "MZ-a-wide-string".encode("utf-16-le") + b"\xff\xfe"
    data = _strings(write("a.bin", body))
    assert data["ascii_count"] >= 1
    assert data["wide_count"] >= 1


def test_a_run_shorter_than_the_floor_is_not_a_string(write):
    """Six is the conventional floor and it matters: at five, printable runs
    occur often enough in random data to bury the report in noise."""
    data = _strings(write("a.bin", b"\x00abc\x00abcd\x00abcde\x00abcdef\x00"))
    assert data["ascii_count"] == 1          # only "abcdef"


@pytest.mark.parametrize("chunk_bytes", [1, 2, 3, 7, 512, 4096, 65_536, 1_048_576])
def test_string_results_do_not_depend_on_the_chunk_size(write, chunk_bytes):
    """The property that broke first when this was written, and the one the
    first version of this test could not see: its body was 1380 bytes against
    a 4096-byte header read, so the pipeline fed one chunk whatever
    `read_chunk_bytes` said. The body below is larger than the header and
    `header_bytes` is lowered, so the parametrisation reaches the scanner.

    Odd chunk sizes are in the list deliberately. They split a UTF-16 pair,
    which is the case that reported one run per chunk instead of one run.
    """
    body = (b"\x00" * 300 + b"https://example.com/payload" + b"\x00" * 7
            + "C:\\Windows\\System32\\evil.dll".encode("utf-16-le") + b"\x00" * 900
            + b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" + b"\x00" * 40
            + b"A" * 9000 + b"\x00" + b"W\x00" * 4000 + b"\xff" * 4
            + b"MZAPPDATAROAM" + b"\x00" * 4 + b"tail-at-the-very-end")
    data = _strings(write("a.bin", body),
                    config={**DEFAULT_CONFIG, "read_chunk_bytes": chunk_bytes,
                            "header_bytes": 64, "strings_include_text": True})
    assert data["urls"] == ["https://example.com/payload"]
    assert "C:\\Windows\\System32\\evil.dll" in data["windows_paths"]
    assert data["registry_paths"] == [
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
    # Five ASCII runs: the URL, the registry path, the 9000 A's, MZAPPDATAROAM
    # and the tail. Two wide runs: the evil.dll path, and the one formed by
    # the last A pairing with the NUL that follows it -- which is exactly the
    # kind of accident a boundary-sensitive scanner would report differently
    # at different chunk sizes, so it is left in on purpose.
    assert (data["ascii_count"], data["wide_count"]) == (5, 2)
    assert data["over_length"] == 2          # the 9000 A's and the 4000 W pairs
    assert "MZAPPDATAROAM" in data["text"]
    assert "tail-at-the-very-end" in data["text"]


def test_indicators_are_extracted_from_the_strings(write):
    body = (b"\x00visit https://example.com/a and ftp://files.example.org/b\x00"
            b"\x00mail root@example.com about 10.10.5.9 and 999.1.1.1\x00"
            b"\x00Global\\MyMutexName and /etc/cron.d/persist\x00")
    data = _strings(write("a.bin", body))
    assert sorted(data["urls"]) == ["ftp://files.example.org/b",
                                    "https://example.com/a"]
    assert data["emails"] == ["root@example.com"]
    assert data["ipv4"] == ["10.10.5.9"]           # 999.1.1.1 is not an address
    assert data["mutexes"] == ["Global\\MyMutexName"]
    assert "/etc/cron.d/persist" in data["unix_paths"]


def test_a_persistence_registry_path_is_separated_from_an_ordinary_one(write):
    """Low, not medium. An installer writing a Run key is an installer, and
    `GATE_SEVERITY` is medium: a finding earns it only if a file deserves a
    human because of that finding alone."""
    body = (b"\x00HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svc\x00"
            b"\x00HKLM\\Software\\Acme\\Settings\\Colour\x00")
    report = analyse(write("a.bin", body))
    assert "registry_persistence_path" in _keys(report, "low")
    assert "registry_path_present" in _keys(report, "info")
    assert _keys(report, "medium") == set()
    assert _keys(report, "high") == set()


def test_nothing_the_strings_extractor_raises_is_medium_or_higher(write):
    """Strings are data. Deciding one looks like a credential is the v0.4
    secret engine and deciding one names a suspicious API is a heuristic, and
    both are later work with a measurement behind them."""
    body = (b"\x00https://evil.example/beacon\x00" b"\x00Global\\Mutex\x00"
            b"\x00HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
            b"\x00192.168.1.1\x00" b"\x00C:\\Users\\x\\AppData\\evil.exe\x00")
    report = analyse(write("a.bin", body))
    strings_findings = [f for f in report.findings if f["extractor"] == "strings"]
    assert strings_findings
    assert not [f for f in strings_findings if f["severity"] in ("medium", "high")]


def test_a_string_longer_than_the_ceiling_contributes_its_head_and_stops(write):
    """A 200 MB file of printable text is one run. The remainder is discarded
    rather than buffered, which is the difference between a ceiling and a
    suggestion."""
    body = b"\x00" + b"A" * 2_000_000 + b"\x00"
    data = _strings(write("a.bin", body),
                    config={**DEFAULT_CONFIG, "strings_max_length": 64,
                            "read_chunk_bytes": 4096})
    assert data["over_length"] == 1
    assert data["ascii_count"] == 1
    assert any("strings_max_length" in p for p in data["parse_errors"])


def test_the_retained_list_is_capped_while_the_count_keeps_rising(write):
    """The report still says how many there were, which is the fact a cap
    would otherwise destroy."""
    body = b"".join(b"\x00string%06d" % n for n in range(5000))
    data = _strings(write("a.bin", body),
                    config={**DEFAULT_CONFIG, "strings_max_retained": 100})
    assert data["retained"] == 100
    assert data["ascii_count"] == 5000
    assert data["retained_truncated"] is True


def test_extracted_strings_cannot_carry_a_terminal_escape(write):
    """Printable ASCII is 0x20 to 0x7E, and ESC is 0x1B. Excluding the
    control range at extraction time is what makes these safe to put in a
    report without sanitising them afterwards.

    Asserted against the strings themselves rather than against serialised
    JSON. The first version of this test checked `"\\u001b" not in
    json.dumps(...)`, which can never fail for any input: in Python source
    that literal *is* the ESC character, and `json.dumps` always escapes it
    to six characters. Adding ESC to the printable range left the whole suite
    green.
    """
    body = b"\x00before\x1b[2Jafter-the-escape\x00" + b"\x00sep\x1b]0;title\x07done\x00"
    data = _strings(write("a.bin", body),
                    config={**DEFAULT_CONFIG, "strings_include_text": True})
    everything = " ".join(data["text"])
    assert "\x1b" not in everything and "\x07" not in everything
    # and the escape really did split the run, rather than being carried
    assert "before" in everything and "after-the-escape" in everything
    assert "\x1b" not in json.dumps(analyse(write("b.bin", body)).to_dict())


def test_window_statistics_match_an_independent_calculation(write):
    """The entropy extractor kept one float per window until v0.4, which made
    peak memory linear in sample size, and replaced it with a running maximum,
    total and count. Nothing pinned any of the three: mutating `window_max` to
    take the minimum, or the mean to zero, or the count to double, left the
    whole suite green.
    """
    body = (b"\x00" * 8192 + os.urandom(8192) + b"A" * 8192
            + os.urandom(8192) + b"\x11\x22" * 4096)
    path = write("a.bin", body)
    # `entropy_target_windows: 1` so the configured size is the window size:
    # the sizing rule is max(minimum, min(configured, size // target)), and a
    # target above one shrinks the window for a small sample.
    config = {**DEFAULT_CONFIG, "entropy_window_bytes": 8192,
              "entropy_target_windows": 1}
    data = analyse(path, config=config).data["entropy"]

    windows = [body[i:i + 8192] for i in range(0, len(body), 8192)]
    expected = [shannon(w) for w in windows]
    assert data["window_count"] == len(expected)
    assert data["window_max"] == pytest.approx(max(expected), abs=1e-4)
    assert data["window_mean"] == pytest.approx(sum(expected) / len(expected), abs=1e-4)
    # the maximum is genuinely a maximum, not the last window scored
    assert data["window_max"] > expected[-1]
    assert data["window_max"] > min(expected)


def test_a_short_final_window_is_still_scored(write):
    """A tail of at least half a window is scored rather than discarded, which
    is what makes `window_count` disagree with a plain division."""
    config = {**DEFAULT_CONFIG, "entropy_window_bytes": 1024,
              "entropy_target_windows": 1, "entropy_min_window_bytes": 256}
    full = analyse(write("a.bin", b"A" * 2048), config=config).data["entropy"]
    tail = analyse(write("b.bin", b"A" * 2048 + b"B" * 800), config=config).data["entropy"]
    assert full["window_count"] == 2
    assert tail["window_count"] == 3


def test_the_retained_cap_is_shared_between_ascii_and_wide(write):
    """Enforced per kind it was a ceiling of twice what the config asked for,
    and the comment beside the default claimed the product as the worst case."""
    body = b"".join(b"\x00ascii%05d" % n for n in range(500))
    body += b"".join(b"\x00\x00" + ("wide%05d" % n).encode("utf-16-le")
                     for n in range(500))
    data = _strings(write("a.bin", body),
                    config={**DEFAULT_CONFIG, "strings_max_retained": 40})
    assert data["retained"] == 40


def test_an_indicator_list_that_hit_its_ceiling_says_at_least(write):
    """The finding used to state the capped length as a total: 128 URLs when
    there were 400. A number nobody measured, in the sentence an analyst
    reads."""
    body = b"".join(b"\x00https://example.com/%05d" % n for n in range(400))
    report = analyse(write("a.bin", body))
    detail = next(f["detail"] for f in report.findings if f["key"] == "urls_present")
    assert detail.startswith("at least 128 URL")
    assert report.data["strings"]["indicators_truncated"] == ["urls"]
    assert any("strings_max_iocs" in p
               for p in report.data["strings"]["parse_errors"])
    assert "incomplete:" in cli.render_human(report)


def test_indicators_drawn_from_a_capped_subset_say_so(write):
    """When the retained list is full the indicators come from a subset, and
    a partial list that reads as a complete one is the failure this project
    has now made in four extractors."""
    body = b"".join(b"\x00filler%05d" % n for n in range(500)) + \
        b"\x00https://example.com/late\x00"
    report = analyse(write("a.bin", body),
                     config={**DEFAULT_CONFIG, "strings_max_retained": 10})
    problems = report.data["strings"]["parse_errors"]
    assert any("were kept" in p and "subset" in p for p in problems)
    assert "incomplete:" in cli.render_human(report)


# API name registry and capability findings

def _api_details(report, extractor=None):
    return [f["detail"] for f in report.findings
            if f["key"] == apis.FINDING_KEY
            and (extractor is None or f["extractor"] == extractor)]


def test_no_registry_name_is_another_one_wearing_an_ansi_suffix():
    """The lookup falls back to stripping a trailing `A`, `W`, `_A` or `_W`,
    which is only unambiguous while no two names differ by exactly that. If
    `Foo` and `FooW` were both real APIs in different categories, the fallback
    would silently credit the wrong one."""
    collisions = [name for name in sorted(apis.VOCABULARY)
                  for stripped in apis._without_suffix(name)
                  if stripped in apis.VOCABULARY]
    assert collisions == []


def test_a_name_that_really_ends_in_a_is_not_stripped():
    """The bug this ordering exists to prevent: strip first and
    `CryptUnprotectData` becomes `cryptunprotectdat`, which matches nothing,
    so the one credential-access API most worth catching is the one the
    matcher loses.

    Asserting only that the real name resolves was not enough. It survived a
    reordering that tried the stripped form first and fell back to the direct
    one, because no real entry collides with `cryptunprotectdat` -- the test
    passed while the ordering the docstring describes was gone. A vocabulary
    built to collide is what actually pins it."""
    assert apis.match_symbol("CryptUnprotectData") == (
        "cryptunprotectdata", ("credential_access",))

    colliding = {"cryptunprotectdata": ("credential_access",),
                 "cryptunprotectdat": ("network",)}
    assert apis._lookup(colliding, "CryptUnprotectData") == (
        "cryptunprotectdata", ("credential_access",))


def test_the_underscored_ansi_spelling_reaches_the_entry():
    """`DnsQuery` is a macro. What a binary imports is `DnsQuery_A` or
    `DnsQuery_W`, so without the underscored fallback the registry's entry
    could never fire on a real import table -- and registering both spellings
    instead would let one API count as two names towards a threshold meant
    for two APIs."""
    for spelling in ("DnsQuery_A", "DnsQuery_W", "DnsQuery"):
        assert apis.match_symbol(spelling) == ("dnsquery", ("network",)), spelling


def test_a_name_is_found_at_any_offset_in_a_padded_token():
    """The token pattern carried a 64-character ceiling, and a ceiling on a
    token is a hidden substring match: `j` * 64 then `VirtualAllocEx@16`
    matched because the padding filled exactly one token and left the API
    name starting the next, while `j` * 63 did not. Whether a name was found
    depended on its offset modulo 64, and the version that found it was the
    one that should not have."""
    found = {pad: apis.match_text("j" * pad + "VirtualAllocEx@16")
             for pad in (62, 63, 64, 65, 100)}
    assert all(result == [] for result in found.values()), found
    assert apis.match_text("_VirtualAllocEx@24") == [
        ("virtualallocex", ("process_injection",))]


def test_a_non_ascii_lookalike_does_not_reach_an_entry():
    """`str.lower()` is Unicode-aware and U+212A KELVIN SIGN lowercases to
    `k`, so `Get\u212AeyState` canonicalised to `getkeystate`. Both callers
    decode through ascii/replace today, which makes this unreachable rather
    than harmless."""
    assert apis.match_symbol("Get\u212AeyState") == (None, ())
    assert apis.match_symbol("GetKeyState") == ("getkeystate", ("surveillance",))


def test_display_refuses_a_name_it_did_not_write():
    """The module's safety claim is that nothing a sample writes can reach a
    report through it. `SPELLING.get(canonical, canonical)` made that true of
    the callers rather than of the function: handed anything else it returned
    it verbatim, ANSI escapes included."""
    with pytest.raises(KeyError):
        apis.display("\x1b[2J\x1b[H  findings (info max):")
    assert apis.display("virtualallocex") == "VirtualAllocEx"


def test_an_unrecognised_view_raises_rather_than_choosing_one():
    """`view="Import"` selected the string index and silently dropped every
    ambiguous name, which is a wrong answer in the shape of a right one."""
    with pytest.raises(ValueError):
        apis.categorise(["sleep"], view="Import")
    assert apis.categorise(["sleep"], view="import") == {"anti_analysis": ["Sleep"]}
    assert apis.categorise(["sleep"], view="string") == {}


def test_the_ansi_and_wide_spellings_reach_the_same_entry():
    for spelling in ("CreateProcessA", "CreateProcessW", "CreateProcess"):
        canonical, categories = apis.match_symbol(spelling)
        assert (canonical, categories) == ("createprocess", ("execution",)), spelling


def test_no_capability_reaches_medium():
    """`GATE_SEVERITY` is medium and a medium is a non-zero exit. Every name
    in this registry is also called by legitimate software, so a capability
    inferred from names must not fail somebody's build. Raising one is a
    deliberate act and this test is what makes it deliberate."""
    assert {spec["severity"] for spec in apis.CAPABILITIES.values()} <= {"info", "low"}


def test_every_ambiguous_name_is_one_the_registry_actually_holds():
    """A `STRING_AMBIGUOUS` entry for a name not in the vocabulary excludes
    nothing and reads as protection that is not there."""
    assert apis.STRING_AMBIGUOUS <= apis.VOCABULARY


def test_an_ambiguous_name_matches_as_a_symbol_and_not_as_text():
    """`Sleep` is a real anti-analysis API and an English word. In an import
    table it is a symbol; in a string table it is prose."""
    assert apis.match_symbol("Sleep")[1] == ("anti_analysis",)
    assert apis.match_text("Sleep") == []


def test_a_name_inside_a_longer_word_is_not_a_match():
    """Substring matching would make `PreloadLibraryPath` a dynamic-resolution
    finding. Tokens, not substrings."""
    assert apis.match_text("PreloadLibraryPath") == []
    assert apis.match_symbol("PreloadLibraryPath") == (None, ())


def test_decorated_and_mangled_spellings_are_found():
    """The three forms the token path exists for."""
    for text in ("_VirtualAllocEx@24", "?VirtualAllocEx@@YAPEAX",
                 "kernel32.dll,VirtualAllocEx"):
        assert apis.match_text(text) == [
            ("virtualallocex", ("process_injection",))], text


def test_prose_mentioning_an_api_is_not_a_match():
    """Measured over 6725 real files, this rule is the difference between one
    false positive and none: a run with a space in it is documentation or a
    command line, and neither is a symbol reference."""
    assert apis.match_text("a sentence mentioning VirtualAllocEx in passing") == []


def test_a_run_longer_than_the_token_limit_is_not_taken_apart():
    padding = "x" * 200
    assert apis.match_text(f"{padding},VirtualAllocEx", token_limit=128) == []
    assert apis.match_text(f"{padding},VirtualAllocEx", token_limit=4096) == [
        ("virtualallocex", ("process_injection",))]


@needs_pefile
def test_an_ordinal_import_is_listed_and_claims_no_capability(write):
    """An import by ordinal has no name to match. `apis.match_symbol("#42")`
    returning nothing proved almost nothing -- no plausible bug makes a string
    sharing no substring with the vocabulary match -- so this drives the real
    path instead: the symbol has to reach `imports` and not `api_names`."""
    class _Imported:
        name, ordinal = None, 42

    class _Entry:
        dll, imports = b"kernel32.dll", [_Imported()]

    class _Fake:
        class OPTIONAL_HEADER:
            DATA_DIRECTORY = [type("D", (), {"VirtualAddress": 0x1000})()] * 16
        DIRECTORY_ENTRY_IMPORT = [_Entry()]

        def parse_data_directories(self, directories=None):
            pass

        def get_imphash(self):
            return "d41d8cd98f00b204e9800998ecf8427e"

    data = PEExtractor()._imports(_Fake(), DEFAULT_CONFIG)
    assert data["imports"]["kernel32.dll"] == ["#42"]
    assert data["import_count"] == 1
    assert data["api_names"] == [] and data["api_capabilities"] == {}


def test_a_name_in_two_categories_is_reported_under_both():
    """`SetWindowsHookEx` installs something that survives a reboot and reads
    every keystroke. Forcing it into one category would lose half of what it
    says."""
    grouped = apis.categorise(["setwindowshookex"], view="import")
    assert sorted(grouped) == ["persistence", "surveillance"]


# capability findings

def test_one_name_is_data_and_two_are_a_finding(write):
    """The threshold, and the data-and-findings split underneath it: below it
    the observation is still in the report, it is just not promoted."""
    one = analyse(write("a.bin", b"\x00VirtualAllocEx\x00"))
    assert one.data["strings"]["api_names"] == ["VirtualAllocEx"]
    assert _api_details(one) == []

    two = analyse(write("b.bin", b"\x00VirtualAllocEx\x00WriteProcessMemory\x00"))
    assert len(_api_details(two)) == 1
    assert "process injection" in _api_details(two)[0]


def test_a_capability_finding_never_gates_a_build(write):
    """Every category at once, and still nothing at medium."""
    names = [name for spec in apis.CAPABILITIES.values() for name in spec["names"]]
    body = b"\x00" + b"\x00".join(n.encode() for n in names) + b"\x00"
    report = analyse(write("a.bin", body))
    assert len(_api_details(report)) == len(apis.CAPABILITIES)
    assert all(f["severity"] in ("info", "low") for f in report.findings
               if f["key"] == apis.FINDING_KEY)

    # Every category here holds more than six names, so every detail takes the
    # truncated branch. Nothing looked at the sentence it produces, and an
    # off-by-one in it survived the whole suite.
    injection = next(d for d in _api_details(report) if "process injection" in d)
    listed = len(apis.CAPABILITIES["process_injection"]["names"])
    assert injection.startswith(f"{listed} process injection")
    assert injection.endswith(f", and {listed - 6} more")


def test_a_finding_quotes_the_registry_and_never_the_sample(write):
    """The names in a report come from `apis.py`, not from the file. Nothing
    a sample writes can reach a finding through this path, which is why the
    capability lists need no `safe_text` and no length cap."""
    body = b"\x00virtualallocex\x00WRITEPROCESSMEMORY\x00"
    report = analyse(write("a.bin", body))
    detail = _api_details(report)[0]
    assert "VirtualAllocEx" in detail and "WriteProcessMemory" in detail
    assert "virtualallocex" not in detail and "WRITEPROCESSMEMORY" not in detail


def test_api_names_survive_the_retained_cap_and_the_text_switch(write):
    """The reason this is matched during extraction rather than in a findings
    pass over `report.data`. `strings_include_text` is off by default and the
    retained list stops at its cap, so a later pass would see nothing on a
    normal run -- while the packed sample this is for is exactly the one with
    hundreds of thousands of strings."""
    body = b"".join(b"\x00filler%05d" % n for n in range(500))
    body += b"\x00VirtualAllocEx\x00WriteProcessMemory\x00"
    report = analyse(write("a.bin", body),
                     config={**DEFAULT_CONFIG, "strings_max_retained": 10})
    data = report.data["strings"]
    assert "text" not in data
    assert data["retained"] == 10
    assert data["api_names"] == ["VirtualAllocEx", "WriteProcessMemory"]
    assert _api_details(report)


def test_the_names_found_do_not_depend_on_the_chunk_size(write):
    """The property that broke first when the string scanner was written, now
    pinned for what is derived from it."""
    body = (b"\x00" + b"junk" * 900 + b"\x00VirtualAllocEx\x00"
            + b"junk" * 900 + b"\x00CreateRemoteThread\x00")
    path = write("a.bin", body)
    results = {size: analyse(path, config={**DEFAULT_CONFIG,
                                           "read_chunk_bytes": size,
                                           "header_bytes": size})
               .data["strings"]["api_names"]
               for size in (64, 512, 4096, 1 << 20)}
    assert len(set(map(tuple, results.values()))) == 1, results
    assert results[64] == ["CreateRemoteThread", "VirtualAllocEx"]


@needs_pefile
def test_imports_are_matched_before_the_display_cap(write):
    """A binary with three thousand imports is exactly the one whose
    interesting symbol sits past entry 256. A capability that depends on how
    long the listed table was allowed to get is not a fact about the file."""
    padding = [f"Ordinary{n:04d}" for n in range(300)]
    body = build_pe(imports={"kernel32.dll": padding
                             + ["VirtualAllocEx", "WriteProcessMemory"]})
    report = analyse(write("a.exe", body),
                     config={**DEFAULT_CONFIG, "pe_max_listed_symbols": 8})
    data = report.data["pe"]
    assert data["imports_truncated"] is True
    assert len(data["imports"]["kernel32.dll"]) == 8
    assert data["api_capabilities"]["process_injection"] == [
        "VirtualAllocEx", "WriteProcessMemory"]
    assert _api_details(report, "pe")


@needs_pefile
def test_the_import_view_and_the_string_view_are_reported_separately(write):
    """Two extractors, two findings, and the detail says which view produced
    it. An import is a symbol the loader will resolve; a string is text."""
    body = build_pe(imports={"kernel32.dll": ["VirtualAllocEx",
                                              "WriteProcessMemory"]})
    report = analyse(write("a.exe", body))
    assert any("in the import table" in d for d in _api_details(report, "pe"))
    assert any("in the sample's strings" in d
               for d in _api_details(report, "strings"))


@needs_pefile
def test_an_import_table_that_cannot_be_read_still_has_the_capability_keys(
        write, monkeypatch):
    """The fallback shape has to match the success shape, or a consumer that
    reads `api_capabilities` breaks on exactly the malformed files this tool
    exists for. Every other key in this dict was already in the fallback; two
    new ones is two new ways to have missed it."""
    def explode(self, pe, config):
        raise ValueError("forged import directory")

    monkeypatch.setattr(PEExtractor, "_imports", explode)
    report = analyse(write("a.exe", build_pe(imports={"kernel32.dll": ["Sleep"]})))
    data = report.data["pe"]
    assert data["api_names"] == [] and data["api_capabilities"] == {}
    assert set(data) >= {"imports", "import_count", "imphash",
                         "imports_truncated", "imports_parsed",
                         "api_names", "api_capabilities"}
    assert _api_details(report, "pe") == []


def test_the_new_config_keys_are_validated():
    problems = validate_config({**DEFAULT_CONFIG,
                                "api_min_names_per_capability": 0,
                                "api_max_token_scan_bytes": "128"})
    assert any("api_min_names_per_capability" in p for p in problems)
    assert any("api_max_token_scan_bytes" in p for p in problems)


def test_a_raised_threshold_silences_a_capability(write):
    """The config key does what it says, which is the only reason it is a key
    rather than a constant."""
    body = b"\x00VirtualAllocEx\x00WriteProcessMemory\x00"
    path = write("a.bin", body)
    assert _api_details(analyse(path))
    assert not _api_details(analyse(path, config={
        **DEFAULT_CONFIG, "api_min_names_per_capability": 3}))


# findings envelope

def _envelope(path, config=None):
    return to_envelope(analyse(path, config=config))


def test_the_envelope_carries_no_path_and_no_filename(write):
    """The envelope is the output most likely to be handed to somebody else,
    and `Report.path` is a resolved absolute path -- the safety checklist
    records it as carrying the directory layout and the username of the
    machine that produced it. A filename is little better: a document is often
    named after the person it is about."""
    path = write("Q3-payroll-hendricks.bin", b"\x00" + b"https://example.com/x" * 3)
    envelope = _envelope(path)
    rendered = json.dumps(envelope)
    assert "Q3-payroll-hendricks" not in rendered
    assert str(path) not in rendered and str(path.parent) not in rendered
    assert "path" not in envelope["subject"]
    assert envelope["subject"]["id"].startswith("sha256:")


def test_the_envelope_carries_no_extraction_data(write):
    """`report.data` does not cross. A consumer wanting the section table
    should ask maltriage for its native report."""
    body = build_elf(needed=["libc.so.6"])
    report = analyse(write("a.elf", body))
    envelope = to_envelope(report)
    assert "data" not in envelope
    assert set(envelope) == {"envelope_version", "emitter", "subject",
                             "observed_at", "severity", "findings", "incomplete"}
    assert "libc.so.6" not in json.dumps(envelope["findings"])


def test_what_could_not_be_run_crosses_the_envelope(write):
    """The field that keeps the format honest. An envelope carrying only
    findings turns "I could not look" into "I looked and found nothing",
    which is the distinction this project has spent five releases defending.

    A file that says MZ and then says nothing else is the case exactly: the
    magic identifies it as a PE, the parser is offered it, and the parser
    cannot read it. Zero findings and a broken parse must not serialise the
    same way as zero findings and a clean one."""
    report = analyse(write("a.exe", b"MZ" + b"\x00" * 200))
    assert not report.findings
    assert report.errors, "expected the PE parse to fail on this fixture"
    envelope = to_envelope(report)
    assert envelope["incomplete"]
    assert {"source", "reason"} == set(envelope["incomplete"][0])
    assert {e["source"] for e in envelope["incomplete"]} == set(report.errors)


def test_an_examined_file_with_nothing_found_is_still_an_envelope():
    """Empty findings with severity info is a message -- "this was examined
    and nothing was found" -- and is not the same as no envelope. Built from
    a report directly, because the point is what the emitter does with an
    empty findings list rather than which fixture happens to produce one."""
    report = Report(path="/somewhere/private/a.bin", filename="a.bin",
                    size_bytes=4096)
    report.data["hashes"] = {"sha256": "00" * 32}
    envelope = to_envelope(report)
    assert envelope["findings"] == []
    assert envelope["incomplete"] == []
    assert envelope["severity"] == "info"
    assert envelope["subject"]["id"] == "sha256:" + "00" * 32
    assert "private" not in json.dumps(envelope)


def test_a_transcribed_string_is_not_validated(write):
    """`validated` is true when the emitter did work that could have
    falsified the claim. A RUNPATH is copied out of the file: nothing was
    tested, and a file can say anything."""
    body = build_elf(needed=["libc.so.6"], runpath="/tmp/x")
    envelope = to_envelope(analyse(write("a.elf", body)))
    by_key = {f["key"]: f for f in envelope["findings"]}
    assert by_key["runpath_set"]["validated"] is False


def test_a_computed_finding_is_validated(write):
    """Entropy could have come back low, so the work could have falsified the
    claim. This is the half of the rule that makes the other half mean
    something."""
    envelope = _envelope(write("a.bin", os.urandom(65536)))
    by_key = {f["key"]: f for f in envelope["findings"]}
    assert by_key["high_file_entropy"]["validated"] is True


def test_an_ipv4_finding_is_validated_though_it_quotes_the_sample(write):
    """It looks like transcription and is not: every candidate passes through
    an octet-range check that rejects, so `999.1.1.1` never becomes a
    finding. That rejection is the falsifying work."""
    body = b"\x00" + b"\x00".join(b"connect to 10.0.0.%d now" % n for n in range(3))
    envelope = _envelope(write("a.bin", body))
    by_key = {f["key"]: f for f in envelope["findings"]}
    assert by_key["ipv4_present"]["validated"] is True
    assert by_key["ipv4_present"]["key"] not in envelope_module.TRANSCRIBED


@needs_pefile
def test_extension_mismatch_is_validated_only_when_something_parsed(write):
    """The one finding whose answer depends on how it was reached. A
    successful parse could have contradicted the extension; two magic bytes
    could not, because header-only identification is a claim the file makes
    about itself."""
    parsed = to_envelope(analyse(write("invoice.pdf", build_pe())))
    by_key = {f["key"]: f for f in parsed["findings"]}
    assert by_key["extension_mismatch"]["validated"] is True

    # Magic bytes and nothing behind them: no parser could confirm it.
    header_only = to_envelope(analyse(write("note.txt", b"MZ" + b"\x00" * 200)))
    mismatch = [f for f in header_only["findings"] if f["key"] == "extension_mismatch"]
    if mismatch:
        assert mismatch[0]["validated"] is False


def test_every_finding_key_has_a_decided_validated_value(write):
    """`TRANSCRIBED` is a list of keys, so a key that stops existing leaves a
    dead entry and a new key silently defaults to true. Neither is caught by
    anything else."""
    emitted = set()
    for name, body in (("a.exe", build_pe()), ("b.elf", build_elf(runpath="/x")),
                       ("c.bin", os.urandom(4096))):
        emitted |= {f["key"] for f in analyse(write(name, body)).findings}
    assert emitted, "expected these fixtures to produce findings"
    stale = envelope_module.TRANSCRIBED - _every_finding_key()
    assert stale == set(), f"TRANSCRIBED names keys nothing emits: {stale}"


def _every_finding_key() -> set[str]:
    """Every key the extractor set can produce, read out of the source.

    Reading the source is unlovely, but the alternative is a hand-maintained
    second list, which is the thing this test exists to catch."""
    source = Path(extractors_module.__file__).read_text()
    keys = set(re.findall(r'mk_finding\(\s*self\.name,\s*"([a-z_]+)"', source))
    keys |= {f"{stem}_present" for stem in
             ("urls", "emails", "ipv4", "mutexes", "windows_paths",
              "unix_paths", "registry_path")}
    keys |= {"runpath_set", "rpath_set", apis.FINDING_KEY}
    return keys


def test_evidence_never_carries_what_was_found(write):
    """An offset, a length, a count or a name from this project's own
    vocabulary. Never the extracted string: an envelope is stored, piped and
    shared, and a report that recovers a credential into one turns a detection
    into a leak."""
    secret = "https://intranet.example.com/token/AKIAIOSFODNN7EXAMPLE"
    body = b"\x00" + secret.encode() + b"\x00"
    envelope = _envelope(write("a.bin", body))
    evidence = [e for f in envelope["findings"] for e in f["evidence"]]
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(evidence)
    assert secret not in json.dumps(evidence)


@needs_yara
def test_a_yara_match_carries_offsets_and_not_bytes(write):
    """The rule that holds hardest here, because a rules directory is
    user-extensible and the person most likely to want the bytes is the person
    debugging a rule that matches secrets."""
    carrier = b"%PDF-1.4\n" + build_pe() + b"\n%%EOF\n"
    envelope = to_envelope(analyse(write("carrier.pdf", carrier)))
    matches = [f for f in envelope["findings"] if f["key"] == "yara_match"]
    assert matches, "expected embedded_pe_header to fire on a PE inside a PDF"
    for match in matches:
        assert match["discriminator"], "a rule name is what makes the key bounded"
        names = {e["name"] for e in match["evidence"]}
        assert "first_offset" in names and "string_count" in names
        assert "matched_data" not in names and "bytes" not in names


def test_a_bounded_key_set_keeps_its_detail_in_the_discriminator(write):
    """The property that makes maltriage the right first emitter. Every
    capability files under one key with the category beside it, so a consumer
    can enumerate the keys and still group by what was actually found."""
    body = b"\x00VirtualAllocEx\x00WriteProcessMemory\x00IsDebuggerPresent\x00GetTickCount\x00"
    envelope = _envelope(write("a.bin", body))
    capabilities = [f for f in envelope["findings"] if f["key"] == apis.FINDING_KEY]
    assert len(capabilities) == 2
    assert {f["discriminator"] for f in capabilities} == {
        "process_injection", "anti_analysis"}
    assert all(f["key"] == apis.FINDING_KEY for f in capabilities)


def test_a_capability_never_earns_a_technique(write):
    """The registry records a technique per capability as reference data and
    does not emit it. A capability inferred from names present in a binary is
    not evidence the binary used them, and `mitre` is the field a consumer is
    most likely to aggregate without reading the finding under it."""
    assert all("mitre" in spec for spec in apis.CAPABILITIES.values())
    body = b"\x00VirtualAllocEx\x00WriteProcessMemory\x00"
    envelope = _envelope(write("a.bin", body))
    assert envelope["findings"]
    assert not any("mitre" in f for f in envelope["findings"])


def test_the_envelope_version_moves_independently_of_the_schema():
    """Two things that change for different reasons: one tracks what a
    maltriage report looks like, the other what three tools have agreed to say
    to each other."""
    assert envelope_module.ENVELOPE_VERSION != SCHEMA_VERSION


def test_the_cli_writes_one_envelope_per_file(write, tmp_path, capsys):
    write("a.bin", os.urandom(4096))
    write("b.txt", b"ordinary text\n" * 8)
    out = tmp_path / "env.jsonl"
    cli.main(["scan", str(tmp_path), "--envelope", str(out), "-q"])
    lines = [json.loads(line) for line in out.read_text().splitlines()]
    assert len(lines) == 2
    assert all(line["envelope_version"] == envelope_module.ENVELOPE_VERSION
               for line in lines)
    assert len({line["subject"]["id"] for line in lines}) == 2


# ATT&CK mapping

def test_the_one_finding_that_earns_a_technique(write):
    """`extension_mismatch` qualifies for the same reason it is this
    project's only `high`: there is no benign reason for a PE to be called
    `invoice.pdf`."""
    envelope = _envelope(write("invoice.pdf", b"MZ" + b"\x00" * 512))
    mismatch = next(f for f in envelope["findings"] if f["key"] == "extension_mismatch")
    assert mismatch["mitre"] == [attack.MASQUERADE_FILE_TYPE]
    assert attack.describe(attack.MASQUERADE_FILE_TYPE)["name"] == "Masquerade File Type"


def test_a_technique_id_the_registry_does_not_know_cannot_reach_a_report():
    """Validated where the finding is built, not at the emitter. A technique
    id is the field a consumer is most likely to aggregate without reading the
    finding underneath it, so a typo must not be publishable."""
    with pytest.raises(ValueError):
        mk_finding("x", "k", "d", "info", mitre=["T9999"])
    with pytest.raises(ValueError):
        mk_finding("x", "k", "d", "info", mitre=["T1036.008", "not-a-technique"])
    assert mk_finding("x", "k", "d", "info", mitre=["T1036.008"])["mitre"] == ["T1036.008"]


def test_a_finding_without_a_technique_has_no_mitre_key():
    """Absent, not empty. An empty list reads as "we looked and there is no
    technique", which is a different claim from "this finding does not make
    one"."""
    assert "mitre" not in mk_finding("x", "k", "d", "info")
    assert "mitre" not in mk_finding("x", "k", "d", "info", mitre=[])


def test_the_packer_findings_are_deliberately_unmapped(write):
    """The refusals are the substance of this feature. `T1027.002` describes
    software packing accurately, which is exactly the problem: the technique
    is right and the inference is not, because packing is the normal state of
    most installers."""
    report = analyse(write("a.exe", build_pe(
        sections=[(".text", SECTION_CODE, b"\x90" * 0x180),
                  ("UPX0", SECTION_RWX, os.urandom(0x400))])))
    refused = {"known_packer_section", "writable_executable_section",
               "virtual_size_mismatch", "no_imports", "section_entropy_high",
               "implausible_timestamp", "registry_persistence_path"}
    for finding in report.findings:
        if finding["key"] in refused:
            assert "mitre" not in finding, finding["key"]


def test_a_rule_may_declare_its_own_technique(tmp_path, write):
    """A rule is a much narrower statement than a finding key, so a rule
    author can be specific where the registry cannot. This is the extensible
    half of the mapping."""
    meta = {"severity": "low", "mitre": "T1204.002, T1059.005"}
    assert YaraExtractor._techniques(meta) == {
        "mitre": ["T1204.002", "T1059.005"], "unknown": []}
    assert YaraExtractor._techniques({}) == {"mitre": [], "unknown": []}
    assert YaraExtractor._techniques({"mitre": "T1204.002"})["mitre"] == ["T1204.002"]


def test_a_rule_declaring_an_unknown_technique_is_told_rather_than_ignored():
    """A rules directory is somebody else's input, and a mistyped id is far
    likelier than a deliberate one. Dropping it silently would leave the
    author believing the mapping works."""
    result = YaraExtractor._techniques({"mitre": "T1204.002, T9999, nonsense"})
    assert result["mitre"] == ["T1204.002"]
    assert result["unknown"] == ["T9999", "nonsense"]


def test_a_duplicate_technique_is_named_once():
    assert YaraExtractor._techniques({"mitre": "T1055, T1055"})["mitre"] == ["T1055"]
    assert mk_finding("x", "k", "d", "info",
                      mitre=["T1055", "T1055"])["mitre"] == ["T1055"]


def test_no_bundled_rule_declares_a_technique():
    """Deliberate, not an oversight. Every bundled rule describes the shape of
    a file and ATT&CK describes behaviour, so none of them survives the benign
    case: `embedded_pe_header` fires on any ZIP carrying an executable, and
    `base64_encoded_pe_header` fires on a MIME attachment.

    This test is what makes that a decision rather than a thing nobody got
    round to. Adding `mitre` to a bundled rule should require deleting it."""
    source = (Path(extractors_module.__file__).parent / "rules"
              / "structural.yar").read_text()
    assert "mitre" not in source


def test_every_technique_the_api_registry_names_is_a_real_one():
    """`apis.py` records a technique per capability as reference data. It is
    not emitted, so nothing else would ever catch a typo in it."""
    for category, spec in apis.CAPABILITIES.items():
        assert attack.is_known(spec["mitre"]), (category, spec["mitre"])


def test_the_registry_carries_a_name_and_a_tactic_for_everything():
    """A consumer should not have to resolve an id against an external source
    to render it."""
    for technique in attack.TECHNIQUES:
        described = attack.describe(technique)
        assert described["id"] == technique
        assert described["name"] and described["tactic"]


# the secret engine

def _secret_data(path, config=None):
    return _strings(path, config=config)["secrets"]


def test_a_known_format_is_medium_and_a_candidate_is_low(write):
    """Decided by the roadmap before any of this was written. `AKIA...` is an
    AWS access key id and nothing else, so a human should look at that file on
    its own account. A high-entropy token with no rule to explain it is a
    candidate, and `GATE_SEVERITY` is medium."""
    body = (b"\x00AKIAIOSFODNN7EXAMPLE\x00"
            + b"\x00" + _detected_token(40).encode() + b"\x00")
    report = analyse(write("a.bin", body))
    by_rule = {f["discriminator"]: f for f in report.findings
               if f["key"] == "secret_candidate"}
    assert by_rule["aws_access_key_id"]["severity"] == "medium"
    assert by_rule["high_entropy_token"]["severity"] == "low"
    assert all(f["severity"] != "high" for f in report.findings
               if f["key"] == "secret_candidate")


def test_no_secret_reaches_the_report_by_any_path(write):
    """The rule the engine exists under. It covers findings and `report.data`
    alike, because `--json` writes the data and a report is stored, piped and
    shared -- a tool that recovers a credential into an artefact has turned a
    detection into a leak."""
    token = _random_token(44)
    body = (b"\x00AKIAIOSFODNN7EXAMPLE\x00password=hunter2correct\x00"
            + token.encode() + b"\x00")
    report = analyse(write("a.bin", body),
                     config={**DEFAULT_CONFIG, "strings_include_text": True})
    rendered = json.dumps(report.to_dict())
    for secret in ("AKIAIOSFODNN7EXAMPLE", "hunter2correct", token):
        assert secret not in json.dumps(report.data["strings"]["secrets"]), secret
        assert secret not in json.dumps(report.findings), secret
    # `strings_include_text` is a separate switch and is on here, so the raw
    # strings are present. That is the switch the caller asked for; the point
    # is that nothing the secret engine emits carries them.
    assert "AKIAIOSFODNN7EXAMPLE" in rendered


def test_no_candidate_in_a_report_carries_a_field_it_should_not(write):
    """Structural, and at the report rather than at the dataclass.

    `test_a_candidate_has_no_field_for_the_value` pins `Candidate.as_dict`,
    and adding a `text` key to the dictionary *after* that call passed the
    whole suite -- the leak test only looked for the specific secrets it had
    planted, so a field carrying anything else went unnoticed. What has to be
    pinned is the shape of what reaches the report, not the shape of what one
    function returns."""
    body = (b"\x00AKIAIOSFODNN7EXAMPLE\x00password=hunter2correct\x00"
            + _random_token(40).encode() + b"\x00")
    data = _secret_data(write("a.bin", body))
    assert data["candidates"], "expected this fixture to produce candidates"
    allowed = {"rule", "tier", "offset", "length", "entropy", "entropy_ratio"}
    for candidate in data["candidates"]:
        assert set(candidate) == allowed, set(candidate) - allowed
        assert all(isinstance(v, (str, int, float)) for v in candidate.values())


def test_a_token_inside_a_longer_string_is_not_a_candidate():
    """A credential in a string table is its own null-terminated run. A
    random-looking span inside a longer string is a span of something else,
    and matching it is what took the entropy tier to 70% of binaries.

    Pinned separately because the digit rule now catches the symbol names
    this used to be demonstrated with, so removing the whole-string rule
    stopped failing anything."""
    token = _detected_token(40)
    assert secrets_module.scan(f"loading resource {token} from cache") == []
    assert secrets_module.scan(f"{token}.cache.tmp") == []

    # `prefix-TOKEN` is deliberately not in that list. A hyphen is inside the
    # token character class -- base64url uses it -- so that string is one
    # token of forty-seven characters rather than a token with something in
    # front of it, and reporting it is right.
    assert secrets_module.scan(f"prefix-{token}")


def test_a_candidate_has_no_field_for_the_value():
    """Structural, not a matter of what the current code happens to put in
    it: there is nowhere to put a secret even by mistake."""
    candidate = secrets_module.Candidate("r", "known", 4, 20, 3.0, 0.9)
    assert set(candidate.as_dict()) == {
        "rule", "tier", "offset", "length", "entropy", "entropy_ratio"}
    assert not hasattr(candidate, "text")
    assert not hasattr(candidate, "value")


def test_the_offset_is_where_the_secret_actually_is(write):
    """A finding that cannot be followed back to the sample is not a finding.
    The whole reason the run scanner learned to count."""
    prefix = b"\x00" + b"harmless padding string" + b"\x00"
    body = prefix + b"AKIAIOSFODNN7EXAMPLE\x00"
    data = _secret_data(write("a.bin", body))
    candidate = next(c for c in data["candidates"]
                     if c["rule"] == "aws_access_key_id")
    assert candidate["offset"] == body.index(b"AKIAIOSFODNN7EXAMPLE")
    assert candidate["length"] == 20


def test_an_offset_in_a_wide_string_lands_on_the_right_byte(write):
    """UTF-16 characters are two bytes, so a character index is not a file
    offset. Getting this wrong points an analyst at half the distance."""
    prefix = b"\x00\x00" + b"pad" + b"\x00\x00"
    body = prefix + ("..AKIAIOSFODNN7EXAMPLE").encode("utf-16-le") + b"\x00\x00"
    data = _secret_data(write("a.bin", body))
    candidate = next(c for c in data["candidates"]
                     if c["rule"] == "aws_access_key_id")
    assert candidate["offset"] == body.index("AKIA".encode("utf-16-le"))


def test_offsets_do_not_depend_on_the_chunk_size(write):
    """The invariant the whole stream phase is built on, now that something
    downstream reports a position rather than only a string."""
    body = (b"\x00" + b"filler" * 40 + b"\x00AKIAIOSFODNN7EXAMPLE\x00"
            + b"more filler here" * 30 + b"\x00")
    path = write("a.bin", body)
    offsets = {size: [c["offset"] for c in _secret_data(
                   path, config={**DEFAULT_CONFIG, "read_chunk_bytes": size,
                                 "header_bytes": size})["candidates"]]
               for size in (1, 2, 3, 7, 64, 4096, 1 << 20)}
    assert len({tuple(v) for v in offsets.values()}) == 1, offsets
    assert offsets[1] == [body.index(b"AKIAIOSFODNN7EXAMPLE")]


def test_a_placeholder_is_not_a_credential():
    """The context tier fires on prose, so the value has to survive this."""
    for text in ("password=changeme", "api_key=<your key here>",
                 "secret=${SECRET}", "password=xxxxxxxx", "token=TODO",
                 "client_secret=YOUR_CLIENT_SECRET"):
        assert secrets_module.scan(text) == [], text
    assert secrets_module.scan("password=hunter2correct")


def test_a_digest_is_not_a_secret():
    """maltriage already reports the hashes it computed. Reporting the ones a
    file mentions as possible credentials is noise on top of a fact already in
    the report."""
    for text in ("d41d8cd98f00b204e9800998ecf8427e",
                 "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                 "550e8400-e29b-41d4-a716-446655440000"):
        assert secrets_module.scan(text) == [], text


def test_a_symbol_name_is_not_a_secret():
    """Measured: after every other exclusion the entropy tier still fired on
    one binary in five, and every match was a symbol name."""
    for text in ("CERT_VerifySignedDataWithPublicKeyInfo",
                 "SECKEY_DestroySubjectPublicKeyInfo",
                 "_ZNK9tesseract10UNICHARSET13id_to_unicharEi",
                 "u_getIntPropertyValueAndSomeMoreWordsHere"):
        assert secrets_module.scan(text) == [], text

    # And the rate this leaves, measured rather than claimed: over 1610 Linux
    # system binaries the entropy tier fires on 4.5% of files, down from
    # 84.7% before these exclusions. It is a filter, not a proof, which is
    # part of why the tier is `low`.


def test_an_alphabet_table_is_not_a_secret():
    """Every character distinct is an enumeration, not a draw. Forty
    characters taken at random from sixty-four repeat one with probability
    about 0.999999."""
    assert secrets_module.scan(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") == []


def test_a_known_format_must_be_a_whole_token():
    """`AKIA` plus sixteen uppercase characters occurs inside longer runs of
    uppercase in ordinary binaries -- measured, it fired on `wget` and
    `xkbprint` -- and a known-format match is medium, which is a non-zero exit
    on somebody's build."""
    assert secrets_module.scan("AKIAIOSFODNN7EXAMPLE")
    assert secrets_module.scan("XXAKIAIOSFODNN7EXAMPLEYY") == []


def test_the_word_rule_scales_with_length():
    """A fixed bar rejects more random tokens the longer they get, which is
    the mistake `expected_random_entropy` exists to avoid. Six same-case
    letters is ordinary in a 48-character token and remarkable in a 16.

    Asserted as a rate rather than on one token. The single-sample version of
    this test failed about one run in twenty-five, and a test that fails
    sometimes is worse than one that does not exist: it teaches whoever sees
    it to re-run rather than to read."""
    assert secrets_module._reads_like_words("DestroyPrivateKeyInformation")
    for length in (32, 40, 48):
        rejected = sum(1 for _ in range(400)
                       if secrets_module._reads_like_words(_random_token(length)))
        # Near 5% at every length, which is the whole point of scaling it. A
        # fixed bar of six ranges from 12% at 32 characters to 21% at 48.
        assert rejected < 60, (length, rejected)


def test_a_real_random_token_is_still_found():
    """The exclusions above are worth nothing if they also remove the thing
    being looked for. Recall over precision is this project's stated trade, so
    this is the number that has to stay high."""
    found = sum(1 for _ in range(400) if secrets_module.scan(_random_token(40)))
    # Measured at about 85%, and steady from 32 characters to 48 -- the
    # threshold scales, so recall does not fall away as tokens get longer.
    # What is lost is mostly tokens that happened not to score above
    # `secrets_entropy_ratio`, which is the tier admitting it is a heuristic.
    assert found > 300, found


def test_the_candidate_list_is_capped_and_says_so(write):
    """The one accumulator in this extractor whose size a sample controls.
    The API name set is bounded by a vocabulary; this is not."""
    body = b"".join(b"\x00" + _random_token(40).encode() for _ in range(80))
    report = analyse(write("a.bin", body),
                     config={**DEFAULT_CONFIG, "secrets_max_candidates": 5})
    data = report.data["strings"]["secrets"]
    assert len(data["candidates"]) == 5
    assert data["candidates_truncated"] is True
    assert any("secrets_max_candidates" in p
               for p in report.data["strings"]["parse_errors"])
    detail = next(f["detail"] for f in report.findings
                  if f["key"] == "secret_candidate")
    assert detail.startswith("at least ")


def test_a_pem_header_is_low_because_every_tls_library_has_one(write):
    """The strings extractor splits on newlines, so the base64 body is a
    different string and this rule can only ever see the header. Measured,
    `libmbedcrypto` alone accounts for ten matches."""
    assert secrets_module.severity_of("private_key_block", "known") == "low"
    report = analyse(write("a.bin", b"\x00-----BEGIN RSA PRIVATE KEY-----\x00"))
    finding = next(f for f in report.findings if f["key"] == "secret_candidate")
    assert finding["severity"] == "low"


def test_the_rule_names_are_a_bounded_set():
    """A consumer must be able to enumerate the keys an emitter produces, and
    the rule is the envelope's discriminator."""
    names = secrets_module.rule_names()
    assert "high_entropy_token" in names and "aws_access_key_id" in names
    assert len(names) == len(set(names))


def test_looks_like_secret_answers_about_the_whole_string():
    """The entry point for a caller filtering values rather than scanning a
    document. A sentence that contains a token is not a secret by this test."""
    assert secrets_module.looks_like_secret("AKIAIOSFODNN7EXAMPLE")
    assert not secrets_module.looks_like_secret(
        "the key AKIAIOSFODNN7EXAMPLE appears in this sentence")


def test_the_secret_config_keys_are_validated():
    problems = validate_config({**DEFAULT_CONFIG,
                                "secrets_min_entropy_length": 0,
                                "secrets_max_candidates": -1,
                                "secrets_entropy_ratio": "high"})
    assert any("secrets_min_entropy_length" in p for p in problems)
    assert any("secrets_max_candidates" in p for p in problems)
    assert any("secrets_entropy_ratio" in p for p in problems)


# the wide-string boundary defect

def test_a_wide_string_does_not_steal_the_byte_before_it(write):
    """Where an ASCII string's NUL terminator sits against a UTF-16 string,
    the wide pattern used to reach one byte too far left: the last character
    of `config\x00` plus that NUL is itself a valid pair, so the wide run came
    out as `gAKIA...`.

    Both readings are correct regexes over those bytes and the engine takes
    the leftmost, which is why this is fixed with a lookbehind rather than by
    filtering matches -- `finditer` returns non-overlapping matches, so
    rejecting the run that starts at `g` would not then find the one inside
    it."""
    key = "AKIAIOSFODNN7EXAMPLE"
    body = b"\x00config\x00" + key.encode("utf-16-le") + b"\x00\x00"
    data = _secret_data(write("a.bin", body))
    candidate = next(c for c in data["candidates"] if c["rule"] == "aws_access_key_id")
    assert candidate["offset"] == body.index(key.encode("utf-16-le"))


def test_the_stolen_byte_was_hiding_a_finding(write):
    """Why this stopped being cosmetic. Known-format patterns require whole
    token boundaries, because without them `aws_access_key_id` fired on
    `wget`. A stolen leading character puts a letter immediately before the
    token, so the boundary guard refuses the match and the report looks
    clean."""
    key = b"AKIAIOSFODNN7EXAMPLE"
    abutting = b"\x00config\x00" + key.decode().encode("utf-16-le") + b"\x00\x00"
    padded = b"\x00config\x00\x00" + key.decode().encode("utf-16-le") + b"\x00\x00"
    rules = lambda body, name: {c["rule"] for c
                                in _secret_data(write(name, body))["candidates"]}
    assert rules(abutting, "a.bin") == rules(padded, "b.bin") == {"aws_access_key_id"}


def test_a_wide_string_is_found_wherever_it_sits(write):
    """The guard must not cost the ordinary layouts: after binary bytes, at
    offset zero of the file, and after a NUL-padded string."""
    key = "AKIAIOSFODNN7EXAMPLE"
    wide = key.encode("utf-16-le")
    for name, body, prefix in (
            ("binary.bin", b"\xff\xfe\xff" + wide + b"\x00\x00", 3),
            ("start.bin", wide + b"\x00\x00", 0),
            ("padded.bin", b"\x00pad\x00\x00" + wide + b"\x00\x00", 6)):
        data = _secret_data(write(name, body))
        candidate = next(c for c in data["candidates"]
                         if c["rule"] == "aws_access_key_id")
        assert candidate["offset"] == prefix, name


def test_the_guard_byte_survives_every_chunk_boundary(write):
    """A lookbehind has nothing to look at when a match begins at offset zero
    of a buffer, so the fix would have made the result depend on where the
    chunks fell -- the one thing this scanner exists to prevent. Every buffer
    is prefixed with the byte that preceded it instead.

    Sizes 1, 2 and 3 matter most: they split the UTF-16 pairs and land a
    buffer boundary exactly on the stolen byte."""
    key = "AKIAIOSFODNN7EXAMPLE"
    body = b"\x00config\x00" + key.encode("utf-16-le") + b"\x00\x00"
    path = write("a.bin", body)
    results = {size: [(c["rule"], c["offset"]) for c in _secret_data(
                   path, config={**DEFAULT_CONFIG, "read_chunk_bytes": size,
                                 "header_bytes": size})["candidates"]]
               for size in (1, 2, 3, 5, 7, 8, 16, 64, 4096, 1 << 20)}
    assert len({tuple(v) for v in results.values()}) == 1, results
    assert results[1] == [("aws_access_key_id",
                           body.index(key.encode("utf-16-le")))]


def test_a_wide_run_still_carries_across_a_chunk_boundary(write):
    """The guard byte is prepended to every buffer and must never be carried
    forward as though it were part of the run. Forcing the carry index to
    stay above it is what stops that, and a run longer than a chunk is what
    exercises it."""
    text = "ThisIsALongWideStringThatCrossesSeveralChunks"
    body = b"\xff\xff" + text.encode("utf-16-le") + b"\x00\x00"
    for size in (2, 3, 5, 16):
        data = _strings(write(f"a{size}.bin", body),
                        config={**DEFAULT_CONFIG, "strings_include_text": True,
                                "read_chunk_bytes": size, "header_bytes": size})
        assert text in data["text"], (size, data["text"])
