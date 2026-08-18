"""
maltriage pipeline.

Runs the extraction engine over a file and assembles the report.

Three properties are deliberate and should survive future changes:

1. Per-extractor error isolation. Malformed headers are an anti-analysis
   technique, not an accident. One extractor raising must never lose the
   results of the others, so failures are captured into `report.errors` and
   the run continues.
2. Ordered context. Extractors run in registration order and share a `ctx`
   dict, so file-type detection can gate the format-specific parsers.
3. A bad config is reported, not absorbed. Values that fail validation fall
   back to defaults, and the substitution is recorded under `config` in
   `report.errors`, so a report never looks clean while quietly ignoring what
   the caller asked for.
"""

from __future__ import annotations
import logging
from pathlib import Path
from typing import Any

from extractors import Extractor, default_extractors
from models import Report
from sample_data import DEFAULT_CONFIG, validate_config

log = logging.getLogger(__name__)


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

    report = Report(
        path=str(path.resolve()),
        filename=path.name,
        size_bytes=path.stat().st_size,
    )

    problems = validate_config(config)
    if problems:
        log.warning("config problems on %s: %s", path, "; ".join(problems))
        report.errors["config"] = "; ".join(problems)

    ctx: dict[str, Any] = {}

    for extractor in extractors:
        try:
            if not extractor.applies_to(path, ctx, config):
                continue
            data = extractor.extract(path, ctx, config)
            report.data[extractor.name] = data
            report.findings.extend(extractor.findings(data, config))
        except Exception as exc:  # isolation is the point
            log.warning("extractor %s failed on %s: %s", extractor.name, path, exc)
            report.errors[extractor.name] = f"{type(exc).__name__}: {exc}"

    return report


def analyse_directory(
    directory: Path | str,
    recursive: bool = False,
    config: dict[str, Any] | None = None,
) -> list[Report]:
    directory = Path(directory)
    globber = directory.rglob("*") if recursive else directory.glob("*")
    return [analyse(p, config) for p in sorted(globber) if p.is_file()]
