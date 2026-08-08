"""
maltriage CLI

Command line front end for the maltriage static triage pipeline.

Run locally:

    python cli.py scan suspicious_file.bin
    python cli.py scan ./samples --recursive --json-lines out.jsonl
    python cli.py samples ./demo

maltriage is a static analysis tool. It reads bytes from disk and never
executes, launches or modifies a sample.
"""

from __future__ import annotations
import argparse
import json
import logging
import sys
from pathlib import Path

from models import SEVERITY_RANK, Report, max_severity
from pipeline import analyse, analyse_directory
from sample_data import write_samples

APP_NAME = "maltriage"
VERSION = "0.1.0"

SEVERITY_MARK = {"info": "  ", "low": " ~", "medium": " !", "high": "!!"}

# Any file scoring at or above this exits non-zero, so the tool can be used
# as a shell or CI gate.
GATE_SEVERITY = "medium"


# Rendering

def render_human(report: Report) -> str:
    filetype = report.data.get("filetype", {})
    hashes = report.data.get("hashes", {})
    entropy = report.data.get("entropy", {})

    lines = [
        f"{report.filename}  ({report.size_bytes:,} bytes)",
        f"  type     {filetype.get('magic_label', '?')}",
        f"  sha256   {hashes.get('sha256', '?')}",
    ]
    if entropy:
        lines.append(
            f"  entropy  {entropy['overall']} overall, {entropy['window_max']} max window"
        )

    if report.findings:
        lines.append("")
        lines.append(f"  findings ({report.severity} max):")
        for f in report.findings:
            lines.append(f"   {SEVERITY_MARK[f['severity']]} [{f['key']}] {f['detail']}")
    else:
        lines.append("")
        lines.append("  no findings")

    if report.errors:
        lines.append("")
        lines.append("  errors:")
        for name, err in report.errors.items():
            lines.append(f"    {name}: {err}")

    return "\n".join(lines)


# Commands

def cmd_scan(args: argparse.Namespace) -> int:
    target = args.target
    if target.is_file():
        reports = [analyse(target)]
    elif target.is_dir():
        reports = analyse_directory(target, recursive=args.recursive)
    else:
        raise FileNotFoundError(target)

    if not args.quiet:
        for report in reports:
            print(render_human(report))
            print()

    if args.json:
        payload = reports[0].to_dict() if len(reports) == 1 else [r.to_dict() for r in reports]
        args.json.write_text(json.dumps(payload, indent=2))

    if args.json_lines:
        with args.json_lines.open("w") as fh:
            for report in reports:
                fh.write(report.to_json(indent=None) + "\n")

    worst = max_severity([{"severity": r.severity} for r in reports])
    return 1 if SEVERITY_RANK[worst] >= SEVERITY_RANK[GATE_SEVERITY] else 0


def cmd_samples(args: argparse.Namespace) -> int:
    written = write_samples(args.directory)
    print(f"wrote {len(written)} synthetic sample(s) to {args.directory}")
    for path in written:
        print(f"  {path.name}")
    return 0


# Entry point

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Static triage for suspicious files. Never executes samples.",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="analyse a file or directory")
    scan.add_argument("target", type=Path)
    scan.add_argument("-r", "--recursive", action="store_true")
    scan.add_argument("--json", type=Path, help="write a JSON report here")
    scan.add_argument("--json-lines", type=Path, help="write one JSON object per file")
    scan.add_argument("-q", "--quiet", action="store_true", help="suppress human output")
    scan.add_argument("-v", "--verbose", action="store_true")
    scan.set_defaults(func=cmd_scan)

    samples = sub.add_parser("samples", help="write synthetic test files")
    samples.add_argument("directory", type=Path)
    samples.set_defaults(func=cmd_samples)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
