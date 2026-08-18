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

import pytest

import cli
from extractors import (
    FileTypeExtractor,
    HashExtractor,
    expected_random_entropy,
    shannon,
)
from models import SEVERITIES, mk_finding
from pipeline import analyse, analyse_directory
from sample_data import (
    DEFAULT_CONFIG,
    config_int,
    config_ratio,
    validate_config,
    write_samples,
)


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
    data = HashExtractor().extract(write("h.bin", content), {}, DEFAULT_CONFIG)
    assert data["sha256"] == hashlib.sha256(content).hexdigest()
    assert data["md5"] == hashlib.md5(content).hexdigest()


def test_hash_extractor_publishes_sha256_to_context(write):
    import hashlib
    ctx = {}
    HashExtractor().extract(write("h.bin", b"x"), ctx, DEFAULT_CONFIG)
    assert ctx["sha256"] == hashlib.sha256(b"x").hexdigest()


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
    data = FileTypeExtractor().extract(path, {}, DEFAULT_CONFIG)
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
    data = FileTypeExtractor().extract(write("a.bin", b"MZ\x00\x00"), {}, config)
    assert data["family"] == "pe"


# models

def test_mk_finding_rejects_unknown_severity():
    with pytest.raises(ValueError):
        mk_finding("x", "y", "z", "hihg")


@pytest.mark.parametrize("severity", SEVERITIES)
def test_mk_finding_accepts_every_declared_severity(severity):
    assert mk_finding("x", "y", "z", severity)["severity"] == severity


# pipeline

def test_failing_extractor_does_not_lose_other_results(write):
    class Exploding(FileTypeExtractor):
        name = "exploding"

        def extract(self, path, ctx, config):
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
    assert parsed["schema_version"] == "1.1"
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


def test_zero_chunk_size_does_not_produce_an_empty_file_hash(write):
    """v0.1.0 returned the digest of an empty file, silently, with no error."""
    import hashlib
    content = b"hello world"
    path = write("h.bin", content)
    report = analyse(path, config={**DEFAULT_CONFIG, "hash_chunk_bytes": 0})
    assert report.data["hashes"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert "config" in report.errors
    assert "hash_chunk_bytes" in report.errors["config"]


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
