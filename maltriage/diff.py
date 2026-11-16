"""
What changed between two corpus runs, file by file.

Every release since v0.5.17 was checked the same way: run the corpus again
with `--per-file`, then compare the two JSON files by SHA-256 to see which
files changed their keys or severity, which were added, and which went
missing. That comparison was done by hand, and a check done by hand is one
that gets skipped the time it matters. This module does it.

The unit is the file's content. A file renamed or moved between runs is
the same file; a file edited is one removed and one added. Copies count:
two copies of one content are two files in both runs, as they are in every
rate the corpus states.

Nothing here carries a name or a path, because neither input does. The
per-file records are keyed by hash by design, and a diff of them is too.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .corpus import GATE_SEVERITY
from .models import SEVERITY_RANK


class DiffInputError(ValueError):
    """An input that cannot be compared, said in words."""


def load(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DiffInputError(f"{path}: not JSON ({exc.msg})") from None
    if not isinstance(payload, dict) or "files" not in payload:
        raise DiffInputError(f"{path}: not a corpus result")
    if "per_file" not in payload:
        raise DiffInputError(
            f"{path}: written without --per-file, so there is nothing to compare "
            "file by file; rerun the corpus with --per-file")
    return payload


def _gated(record: dict[str, Any]) -> bool:
    return SEVERITY_RANK.get(record.get("severity", "info"), 0) >= SEVERITY_RANK[GATE_SEVERITY]


def _by_hash(payload: dict[str, Any]) -> tuple[Counter, dict[str, dict[str, Any]]]:
    counts: Counter = Counter()
    records: dict[str, dict[str, Any]] = {}
    for record in payload["per_file"]:
        digest = record.get("sha256")
        if not digest:
            continue
        counts[digest] += 1
        records.setdefault(digest, record)
    return counts, records


def compare(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Every difference between two runs, as counts and hashes."""
    old_counts, old_records = _by_hash(old)
    new_counts, new_records = _by_hash(new)
    added = new_counts - old_counts
    removed = old_counts - new_counts

    changed = []
    for digest in sorted(set(old_records) & set(new_records)):
        before, after = old_records[digest], new_records[digest]
        before_keys, after_keys = set(before.get("keys", [])), set(after.get("keys", []))
        if before_keys == after_keys and before.get("severity") == after.get("severity"):
            continue
        changed.append({
            "sha256": digest,
            "label": after.get("label"),
            "copies": min(old_counts[digest], new_counts[digest]),
            "severity": [before.get("severity"), after.get("severity")],
            "gate": [_gated(before), _gated(after)],
            "keys_added": sorted(after_keys - before_keys),
            "keys_removed": sorted(before_keys - after_keys),
        })

    def described(counts: Counter, records: dict[str, dict[str, Any]]) -> dict[str, Any]:
        families: Counter = Counter()
        gated = 0
        for digest, count in counts.items():
            families[records[digest].get("family", "unknown")] += count
            gated += count if _gated(records[digest]) else 0
        return {"files": sum(counts.values()), "gated": gated,
                "families": dict(sorted(families.items(), key=lambda kv: (-kv[1], kv[0]))),
                "sha256": sorted(counts)}

    keys_before = {k: sum(v.get("fired", {}).values()) for k, v in (old.get("keys") or {}).items()}
    keys_after = {k: sum(v.get("fired", {}).values()) for k, v in (new.get("keys") or {}).items()}
    key_moves = {key: [keys_before.get(key, 0), keys_after.get(key, 0)]
                 for key in sorted(set(keys_before) | set(keys_after))
                 if keys_before.get(key, 0) != keys_after.get(key, 0)}

    return {
        "files": [sum(old_counts.values()), sum(new_counts.values())],
        "gate": [(old.get("gate") or {}).get("false_positive_rate"),
                 (new.get("gate") or {}).get("false_positive_rate")],
        "added": described(added, new_records),
        "removed": described(removed, old_records),
        "changed": changed,
        "newly_gated": sum(c["copies"] for c in changed if c["gate"] == [False, True]),
        "no_longer_gated": sum(c["copies"] for c in changed if c["gate"] == [True, False]),
        "keys": key_moves,
        # Said when the two runs looked at different populations, because a
        # rate compared across two selections is two different claims.
        "selection": [old.get("selected_extensions") or [], new.get("selected_extensions") or []],
    }


def _rate(value: float | None) -> str:
    return "none" if value is None else f"{value:.1%}"


def render(result: dict[str, Any], show: int = 20) -> str:
    """The comparison as text, newest change first in importance."""
    before, after = result["files"]
    lines = [f"diff: {before} -> {after} file(s)"]
    if result["selection"][0] != result["selection"][1]:
        lines.append("  selections differ: "
                     f"{', '.join(result['selection'][0]) or 'everything'} -> "
                     f"{', '.join(result['selection'][1]) or 'everything'}")
    lines.append(f"  gate ({GATE_SEVERITY}+) on benign files: "
                 f"{_rate(result['gate'][0])} -> {_rate(result['gate'][1])}")

    changed = result["changed"]
    both = after - result["added"]["files"]
    lines.append(f"  in both runs: {both} file(s), {len(changed)} content(s) changed"
                 + (f"; {result['newly_gated']} newly held at the gate" if result["newly_gated"] else "")
                 + (f"; {result['no_longer_gated']} no longer held" if result["no_longer_gated"] else ""))
    # Newly held first: that is the change a CI user feels.
    order = sorted(changed, key=lambda c: (c["gate"] != [False, True], c["gate"] != [True, False],
                                           c["sha256"]))
    for change in order[:show]:
        moves = [f"+{k}" for k in change["keys_added"]] + [f"-{k}" for k in change["keys_removed"]]
        severity = ("" if change["severity"][0] == change["severity"][1]
                    else f"  {change['severity'][0]} -> {change['severity'][1]}")
        copies = f" x{change['copies']}" if change["copies"] > 1 else ""
        lines.append(f"    {change['sha256'][:12]}{copies}  {change['label']}{severity}  "
                     + " ".join(moves))
    if len(changed) > show:
        lines.append(f"    and {len(changed) - show} more; the JSON has every one")

    for name in ("added", "removed"):
        part = result[name]
        if part["files"]:
            families = ", ".join(f"{family} {count}" for family, count in part["families"].items())
            held = f"; {part['gated']} held at the gate" if part["gated"] else ""
            lines.append(f"  {name}: {part['files']} file(s) ({families}){held}")

    if result["keys"]:
        lines.append("  keys, files fired on:")
        for key, (was, now) in result["keys"].items():
            lines.append(f"    {key:<34} {was} -> {now}")
    return "\n".join(lines)
