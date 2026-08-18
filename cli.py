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
VERSION = "0.1.1"

SEVERITY_MARK = {"info": "  ", "low": " ~", "medium": " !", "high": "!!"}

# Any file scoring at or above this exits non-zero, so the tool can be used
# as a shell or CI gate.
GATE_SEVERITY = "medium"

# Exit codes. Kept distinct so a caller can tell "found something" from
# "could not run", which a shell pipeline needs and v0.1.0 conflated.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


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
        if entropy["window_max"] is None:
            # Too small for even one window. Say so rather than printing None.
            lines.append(
                f"  entropy  {entropy['overall']} overall "
                f"({entropy['overall_ratio']} of random), file too small to window"
            )
        else:
            lines.append(
                f"  entropy  {entropy['overall']} overall, {entropy['window_max']} max "
                f"window of {entropy['window_count']} x {entropy['window_size']}B"
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
        print(f"{APP_NAME}: no such file or directory: {target}", file=sys.stderr)
        return EXIT_USAGE

    if not reports:
        print(f"{APP_NAME}: no files found in {target}", file=sys.stderr)
        return EXIT_CLEAN

    if not args.quiet:
        for report in reports:
            print(render_human(report))
            print()

    # Always a JSON array, one object per file, whatever the file count.
    # v0.1.0 wrote a bare object for a single file, so a consumer had to
    # branch on the shape of its own input.
    if args.json:
        args.json.write_text(json.dumps([r.to_dict() for r in reports], indent=2))

    if args.json_lines:
        with args.json_lines.open("w") as fh:
            for report in reports:
                fh.write(report.to_json(indent=None) + "\n")

    worst = max_severity([{"severity": r.severity} for r in reports])
    return EXIT_FINDINGS if SEVERITY_RANK[worst] >= SEVERITY_RANK[GATE_SEVERITY] else EXIT_CLEAN


def cmd_samples(args: argparse.Namespace) -> int:
    written = write_samples(args.directory)
    print(f"wrote {len(written)} synthetic sample(s) to {args.directory}")
    for path in written:
        print(f"  {path.name}")
    return EXIT_CLEAN


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
    scan.add_argument("--json", type=Path, help="write a JSON array of reports here")
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
    try:
        return args.func(args)
    except OSError as exc:
        # Unreadable file, permission denied, broken symlink. A triage tool
        # is pointed at hostile input by definition, so this is expected
        # rather than exceptional and should not print a traceback.
        print(f"{APP_NAME}: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
