"""
maltriage CLI

Command line front end for the maltriage static triage pipeline.

Run locally:

    maltriage scan suspicious_file.bin
    maltriage scan ./samples --recursive --json-lines out.jsonl
    maltriage samples ./demo

Or without installing, from the repository root:

    python -m maltriage.cli scan suspicious_file.bin

maltriage is a static analysis tool. It reads bytes from disk and never
executes, launches or modifies a sample.
"""

from __future__ import annotations
import argparse
import json
import logging
import sys
from pathlib import Path

from . import __version__
from .models import SEVERITY_RANK, Report, max_severity
from .pipeline import analyse, analyse_directory
from .fixtures import write_samples

APP_NAME = "maltriage"

# One source of truth. These were two constants until v0.4, and they had
# already drifted by the time anybody looked: `--version` said 0.3.1 while the
# package metadata said 0.4.0. Version drift between a file and its own
# documentation is a defect this project has fixed three times in other
# places, and a second literal is how it happens.
VERSION = __version__

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

    # Read with `.get` throughout. A renderer that raises on a thin report
    # turns a file the parser found hard into a run that produced nothing at
    # all, which is the opposite of what a triage tool should do with a
    # difficult sample.
    strings = report.data.get("strings")
    if strings and (strings.get("ascii_count") or strings.get("wide_count")):
        lines.append(
            f"  strings  {strings['ascii_count']:,} ascii, {strings['wide_count']:,} "
            f"wide, {strings['retained']:,} kept"
            f"{' (capped)' if strings.get('retained_truncated') else ''}")
        for key, label in (("urls", "urls"), ("ipv4", "ips"),
                           ("registry_paths", "registry"), ("mutexes", "mutexes")):
            values = strings.get(key) or []
            if values:
                shown = ", ".join(values[:3])
                more = "" if len(values) <= 3 else f", +{len(values) - 3}"
                lines.append(f"  {label:8} {shown}{more}")

    pe = report.data.get("pe")
    if pe and pe.get("pe_type"):
        lines.append(
            f"  pe       {pe['pe_type']} {pe.get('machine_label', '?')} "
            f"{pe.get('subsystem_label', '?')}, {len(pe.get('sections') or [])} "
            f"section(s), built {pe.get('timestamp_iso') or 'unknown'}")
        if pe.get("imphash"):
            lines.append(
                f"  imphash  {pe['imphash']} ({pe['import_count']} symbol(s))")
        if pe.get("pdb_path"):
            lines.append(f"  pdb      {pe['pdb_path']}")
        overlay = pe.get("overlay")
        if overlay:
            lines.append(
                f"  overlay  {overlay['size']:,} bytes at offset {overlay['offset']:,}")
        certificate = pe.get("certificate") or {}
        if certificate.get("present"):
            named = ", ".join(certificate.get("common_names") or []) or "no name found"
            lines.append(f"  signed   {named} (not validated)")

    elf = report.data.get("elf")
    if elf and elf.get("elf_class"):
        lines.append(
            f"  elf      {elf['elf_class']} {elf.get('machine_label', '?')} "
            f"{elf.get('type_label', '?')}, {len(elf.get('segments') or [])} "
            f"segment(s), {len(elf.get('sections') or [])} section(s)")
        if elf.get("interpreter"):
            lines.append(f"  interp   {elf['interpreter']}")
        if elf.get("needed"):
            shown = ", ".join(elf["needed"][:6])
            more = "" if len(elf["needed"]) <= 6 else ", ..."
            lines.append(f"  needs    {shown}{more}")
        for key in ("runpath", "rpath"):
            if elf.get(key):
                lines.append(f"  {key:8} {elf[key]}")
        trailing = elf.get("trailing")
        if trailing:
            lines.append(
                f"  trailing {trailing['size']:,} bytes at offset {trailing['offset']:,}")

    yara = report.data.get("yara")
    if yara and yara.get("match_count"):
        shown = ", ".join(m["rule"] for m in yara.get("matches", [])[:5])
        more = "" if len(yara.get("matches", [])) <= 5 else ", ..."
        lines.append(f"  yara     {yara['match_count']} match(es): {shown}{more}")

    if report.findings:
        lines.append("")
        lines.append(f"  findings ({report.severity} max):")
        for f in report.findings:
            lines.append(f"   {SEVERITY_MARK[f['severity']]} [{f['key']}] {f['detail']}")
    else:
        lines.append("")
        lines.append("  no findings")

    # `report.errors` is analysis that did not run at all. `parse_errors` and
    # `warnings` are analysis that ran and came back thinner than it looks:
    # one directory of a PE that could not be followed, or a structure the
    # parser had to guess at. Both mean the same thing to an analyst reading
    # an absence, so both are printed rather than left in the JSON.
    # Two blocks rather than one, because they are two different facts and a
    # single heading that changed wording depending on which was present made
    # the more serious one disappear into the other whenever both occurred.
    thin: dict[str, str] = {}
    for name, data in report.data.items():
        if not isinstance(data, dict):
            continue
        for note in data.get("parse_errors") or []:
            # Two rule files with the same basename, or two directories that
            # both fail, produce the same label. A plain assignment rendered
            # them as one line, which understates how thin the report is --
            # the exact failure this block was split out to prevent.
            label = f"{name}.{note.split(':')[0]}"
            suffix, index = "", 2
            while label + suffix in thin:
                suffix, index = f" ({index})", index + 1
            thin[label + suffix] = note.partition(": ")[2]
        for index, warning in enumerate(data.get("warnings") or [], start=1):
            # Numbered, because a malformed PE routinely produces five or more
            # distinct warnings and a fixed key would print only the first.
            thin[f"{name}.warning {index}"] = warning

    for heading, entries in (("errors", report.errors), ("incomplete", thin)):
        if not entries:
            continue
        lines.append("")
        lines.append(f"  {heading}:")
        for name, err in entries.items():
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
