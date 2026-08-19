"""
maltriage pipeline.

Runs the extraction engine over a file and assembles the report.

The file is opened once and read once. The first `header_bytes` are taken so
the header phase can publish to `ctx` before anything gates on it, and those
same bytes are then fed into the stream phase along with the rest of the file,
so no byte is read twice and nothing seeks backwards.

Five properties are deliberate and should survive future changes:

1. One sequential read, bounded memory. The pipeline reads the sample exactly
   once and nothing holds it whole. This is what makes the corpus harness in
   v0.7 possible, and it is why a stream extractor must not buffer the chunks
   it is handed. A random-access extractor in phase 3 may map the file and
   address bounded regions of it; the memory half of this property is
   absolute, the single-read half describes the pipeline's own pass.
2. Three phases, so gating still works. Header extractors run first and write
   to `ctx`; stream extractors are then selected with `applies_to` using what
   the header phase learned; random-access extractors run last and see both.
   A single undivided pass would leave the PE parser unable to know it is
   looking at a PE before it starts.
3. Per-extractor error isolation. Malformed headers are an anti-analysis
   technique, not an accident. One extractor raising must never lose the
   results of the others. An extractor that raises mid-stream is dropped for
   the rest of the pass while the others keep receiving chunks.
4. A broken heuristic does not lose the data. `findings` runs after
   extraction, so if it raises, the extracted data is still filed and the
   failure is recorded under `<name>.findings`.
5. A bad config is reported, not absorbed. Values that fail validation fall
   back to defaults, and the substitution is recorded under `config` in
   `report.errors`, so a report never looks clean while quietly ignoring what
   the caller asked for. Analysis that was declined rather than attempted,
   such as a parse refused for exceeding `max_parse_bytes`, is recorded the
   same way and for the same reason.
"""

from __future__ import annotations
import logging
from pathlib import Path
from typing import Any

from extractors import (
    Extractor,
    HeaderExtractor,
    RandomAccessExtractor,
    StreamExtractor,
    default_extractors,
)
from models import Report
from sample_data import DEFAULT_CONFIG, config_int, validate_config

log = logging.getLogger(__name__)


def _file(report: Report, extractor: Extractor, data: dict[str, Any],
          config: dict[str, Any]) -> None:
    """File one extractor's data, then derive its findings separately.

    The two are isolated from each other on purpose: a heuristic that raises
    should cost its own findings, not the extraction that produced them.
    """
    report.data[extractor.name] = data
    try:
        report.findings.extend(extractor.findings(data, config))
    except Exception as exc:
        log.warning("findings for %s failed on %s: %s",
                    extractor.name, report.filename, exc)
        report.errors[f"{extractor.name}.findings"] = f"{type(exc).__name__}: {exc}"


def analyse(
    path: Path | str,
    config: dict[str, Any] | None = None,
    extractors: list[Extractor] | None = None,
) -> Report:
    """Analyse a single file. Never executes it."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"not a file: {path}")

    config = config if config is not None else DEFAULT_CONFIG
    extractors = extractors if extractors is not None else default_extractors()

    size = path.stat().st_size
    report = Report(path=str(path.resolve()), filename=path.name, size_bytes=size)

    problems = validate_config(config)
    if problems:
        log.warning("config problems on %s: %s", path, "; ".join(problems))
        report.errors["config"] = "; ".join(problems)

    header_bytes = config_int(config, "header_bytes", 8192)
    chunk_bytes = config_int(config, "read_chunk_bytes", 1048576)

    ctx: dict[str, Any] = {
        "path": str(path.resolve()),
        "filename": path.name,
        "extension": path.suffix.lower(),
        "size": size,
    }

    with path.open("rb") as fh:
        header = fh.read(header_bytes)
        ctx["header"] = header

        # Phase 1: header extractors, in order, so each sees what the
        # previous one published.
        stream: list[StreamExtractor] = []
        random_access: list[RandomAccessExtractor] = []
        for extractor in extractors:
            if isinstance(extractor, StreamExtractor):
                stream.append(extractor)
                continue
            if isinstance(extractor, RandomAccessExtractor):
                random_access.append(extractor)
                continue
            try:
                if not extractor.applies_to(path, ctx, config):
                    continue
                if not isinstance(extractor, HeaderExtractor):
                    # Every extractor belongs to one of the three kinds. An
                    # object that belongs to none of them has no contract for
                    # the pipeline to honour, so say that rather than calling
                    # a method it may not have and reporting the AttributeError
                    # as though the extractor had failed at its job.
                    raise TypeError(
                        f"{type(extractor).__name__} is not a HeaderExtractor, "
                        "StreamExtractor or RandomAccessExtractor")
                data = extractor.read_header(header, path, ctx, config)
            except Exception as exc:  # isolation is the point
                log.warning("extractor %s failed on %s: %s", extractor.name, path, exc)
                report.errors[extractor.name] = f"{type(exc).__name__}: {exc}"
                continue
            _file(report, extractor, data, config)

        # Phase 2: gate the stream extractors on what phase 1 learned, then
        # feed them all from the one read.
        active: list[StreamExtractor] = []
        for extractor in stream:
            try:
                if not extractor.applies_to(path, ctx, config):
                    continue
                extractor.begin(path, ctx, config)
                active.append(extractor)
            except Exception as exc:
                log.warning("extractor %s failed to start on %s: %s",
                            extractor.name, path, exc)
                report.errors[extractor.name] = f"{type(exc).__name__}: {exc}"

        if active:
            # The header was the first slice of this read, so it is fed in
            # rather than re-read. `fh` is already positioned after it.
            chunk = header
            while chunk:
                for extractor in list(active):
                    try:
                        extractor.feed(chunk)
                    except Exception as exc:
                        # Drop this one for the rest of the pass. The others
                        # keep receiving chunks.
                        log.warning("extractor %s failed on %s: %s",
                                    extractor.name, path, exc)
                        report.errors[extractor.name] = f"{type(exc).__name__}: {exc}"
                        active.remove(extractor)
                chunk = fh.read(chunk_bytes)

            for extractor in active:
                try:
                    data = extractor.finish(path, ctx, config)
                except Exception as exc:
                    log.warning("extractor %s failed on %s: %s", extractor.name, path, exc)
                    report.errors[extractor.name] = f"{type(exc).__name__}: {exc}"
                    continue
                _file(report, extractor, data, config)

    # Phase 3: random access. Runs after the pipeline's own handle has closed,
    # because these extractors address the file themselves rather than being
    # fed from the shared read. They see everything both earlier phases
    # published to `ctx`, which is how a parser gates on `family`.
    _parse_phase(report, random_access, path, ctx, config)

    return report


def _parse_phase(report: Report, extractors: list[RandomAccessExtractor],
                 path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> None:
    """Run the random-access extractors, subject to the size ceiling.

    This is the one phase whose cost is not bounded by the configured read
    sizes, because a parser decides for itself how much structure to walk and
    the file it is walking is hostile by assumption. The ceiling is therefore
    enforced here rather than trusted to each extractor, and a sample that
    exceeds it is declined out loud: a report must not look clean while
    quietly omitting the analysis nobody ran.
    """
    if not extractors:
        return

    ceiling = config_int(config, "max_parse_bytes", 536870912)
    for extractor in extractors:
        try:
            if not extractor.applies_to(path, ctx, config):
                continue
            if ctx["size"] > ceiling:
                log.warning("extractor %s skipped on %s: above max_parse_bytes",
                            extractor.name, path)
                report.errors[extractor.name] = (
                    f"skipped: {ctx['size']} bytes is above "
                    f"max_parse_bytes={ceiling}")
                continue
            data = extractor.parse(path, ctx, config)
        except Exception as exc:
            log.warning("extractor %s failed on %s: %s", extractor.name, path, exc)
            report.errors[extractor.name] = f"{type(exc).__name__}: {exc}"
            continue
        _file(report, extractor, data, config)


def analyse_directory(
    directory: Path | str,
    recursive: bool = False,
    config: dict[str, Any] | None = None,
) -> list[Report]:
    directory = Path(directory)
    globber = directory.rglob("*") if recursive else directory.glob("*")
    return [analyse(p, config) for p in sorted(globber) if p.is_file()]
