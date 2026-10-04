"""
YARA matching, against the bundled structural rules and any the caller adds.

Rules are an extension point, so this module treats them as input: each rule
file is compiled in isolation, a file that will not compile costs only itself,
and match context carries offsets and never the matched bytes.
"""

from __future__ import annotations
import logging
import time
from pathlib import Path
from typing import Any

from . import attack
from .base import RandomAccessExtractor, ParserUnavailable, safe_text
from .config import config_bool, config_int, config_list
from .models import SEVERITY_RANK, mk_finding

log = logging.getLogger(__name__)


# YARA

try:  # optional, needs libyara, so not a hard requirement
    import yara as _yara

    HAVE_YARA = True
except ImportError:
    _yara = None
    HAVE_YARA = False


#: Rules shipped with the project. User paths from config are added to these
#: rather than replacing them.
BUNDLED_RULES = Path(__file__).resolve().parent / "rules"

RULE_SUFFIXES = (".yar", ".yara")


def rule_files(config: dict[str, Any]) -> tuple[list[Path], list[str]]:
    """Every rule file to compile, bundled first, then configured paths.

    Returns the files and whatever was wrong with the configuration, because
    an unusable rule path has to reach the report. A path that does not exist,
    is not a regular file, is a `Path` where a string was expected, or cannot
    be read produced a scan that looked like a full run while the configured
    rules never executed. Silence there is the failure this project names most
    often: a report that looks clean for a reason the reader cannot see.

    Paths are resolved and de-duplicated. Naming the bundled directory in
    `yara_rule_paths` is a natural thing to do, since configured paths add to
    the bundled set rather than replacing it, and without this every rule in
    it would match twice and emit two findings.

    The filesystem work is deliberately independent of yara: it answers "is
    there anything to scan with" without the library installed, which is what
    lets the extractor tell "no rules" apart from "no parser".
    """
    problems: list[str] = []
    roots: list[Path] = [BUNDLED_RULES]
    for entry in config_list(config, "yara_rule_paths", []):
        if not isinstance(entry, str) or not entry.strip():
            problems.append(f"config: yara_rule_paths entry {entry!r} is not a path, skipped")
            continue
        roots.append(Path(entry))

    found: list[Path] = []
    seen: set[str] = set()

    def take(path: Path) -> None:
        try:
            key = str(path.resolve())
        except OSError as exc:
            problems.append(f"config: {path} could not be resolved: {exc}")
            return
        if key not in seen:
            seen.add(key)
            found.append(path)

    for root in roots:
        try:
            if root.is_file():
                take(root)
            elif root.is_dir():
                # Suffix only. An entry that is a dangling symlink, a symlink
                # loop or a directory named `sub.yar` used to fail an
                # `is_file()` test here and disappear without a word, which
                # silently shortened the rule set: a moved rules repository or
                # an unchecked-out submodule is ordinary breakage and it must
                # not read as "these rules found nothing". Passing it to the
                # compiler instead means the failure is reported by the same
                # path as a syntax error.
                for entry in sorted(root.iterdir()):
                    if entry.suffix.lower() in RULE_SUFFIXES:
                        take(entry)
            elif root != BUNDLED_RULES:
                # The bundled directory being absent is a checkout problem and
                # is reported by the extractor declining; a configured path
                # that is not there is a configuration problem and is this.
                problems.append(f"config: {root} is not a rule file or directory")
        except OSError as exc:
            problems.append(f"config: {root} is unreadable: {exc}")
    return found, problems


def rule_fingerprint(paths: list[Path]) -> tuple:
    """What a compiled rule set was compiled from.

    The extractor caches its compiled rules, and `analyse_directory` hands one
    instance to every file, so the cache needs a key or it answers with
    whichever rule set it happened to see first. That is worse than
    recompiling: a report says which rule files ran, and a stale cache makes
    that statement false rather than merely slow.
    """
    stamps = []
    for path in paths:
        try:
            stat = path.stat()
            stamps.append((str(path), stat.st_mtime_ns, stat.st_size))
        except OSError:
            stamps.append((str(path), None, None))
    return tuple(stamps)


def compile_rules(paths: list[Path], allow_includes: bool = False
                  ) -> tuple[list[tuple[str, Any]], list[str]]:
    """Compile each rule file separately.

    One file at a time rather than one `yara.compile` over all of them,
    because a syntax error anywhere in a combined compile loses every rule in
    it. That is the same isolation the pipeline gives extractors and the PE
    extractor gives directories, applied to rule files: a rule someone is
    halfway through writing must not disable the bundled set.

    `include` is disabled unless `yara_allow_includes` turns it on. An include
    is resolved relative to the rule file and is not confined to the rules
    directory, so `include "/etc/passwd"` is opened and parsed, and YARA
    quotes offending tokens in its syntax errors - which puts a rule file in
    reach of the whole filesystem and of the report. A bundled set does not
    need includes, and a rules directory fed from somewhere else is exactly
    the case that should not have them by default.

    The namespace is the file's stem, so a match can say which file claimed it.
    """
    compiled, problems = [], []
    for path in paths:
        try:
            compiled.append(
                (path.stem, _yara.compile(filepath=str(path), includes=allow_includes)))
        except Exception as exc:
            log.warning("yara rule file %s failed to compile: %s", path, exc)
            problems.append(f"{path.name}: {type(exc).__name__}: {exc}")
    return compiled, problems


class YaraExtractor(RandomAccessExtractor):
    """Pattern matching against the bundled and configured rule sets.

    Random-access because yara maps the file itself. `match(filepath=...)`
    hands libyara the path and it does its own bounded read, which is the
    third kind's contract exactly; the alternative, `match(data=...)`, needs
    the sample whole in memory and is therefore not available to this project.

    It is also the first extractor that can bound its own execution time.
    `architecture.md` records that isolation covers a parser that raises and
    not one that hangs, and a rule set is the easiest way to write a hang by
    accident. yara takes a timeout and raises on it, and the timeout here is
    spent across the whole rule set rather than granted to each file in it,
    because the number of rule files is a directory listing and not a bound.

    Findings carry offsets and never bytes. A rule that matches a credential
    pattern would otherwise put the credential into a report that gets stored,
    piped and shared, which turns a detection into a leak. The extractor never
    reads `matched_data`, so there is no flag to leave switched on - and
    `console_callback` is installed for the same reason, because YARA's
    `console` module writes to the process's own stdout when nothing captures
    it, which put sample bytes on the terminal from inside a rule, under
    `--quiet`, without appearing anywhere in the report.

    Every match is filed under one finding key, `yara_match`, with the rule
    name carried in the finding's data rather than promoted to a key of its
    own. Rules are user-extensible, and a key set that grows with somebody's
    rules directory is not a key set a dashboard can count on.
    """

    name = "yara"

    def __init__(self) -> None:
        self._rules: list[tuple[str, Any]] = []
        self._fingerprint: tuple | None = None
        self._problems: list[str] = []
        self._loaded_from: list[str] = []

    def applies_to(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> bool:
        # Nothing configured is not a failure. No parser for what *is*
        # configured is, and that is decided in `parse`.
        paths, problems = rule_files(config)
        return bool(paths or problems)

    def _load(self, config: dict[str, Any], paths: list[Path]) -> list[tuple[str, Any]]:
        """Compile once per rule set, not once per sample.

        Compilation is the expensive part of a yara run and the samples are
        the cheap part, which is why `analyse_directory` builds its extractors
        once and hands the same instances to every file. This is the first
        extractor for which that reuse is worth anything - and the first that
        therefore needs to notice when the thing it cached has changed.
        """
        # Both inputs to the compile, not just one. Keying on the files alone
        # meant that flipping `yara_allow_includes` off after a permissive
        # compile kept running the include-bearing rule set, with empty
        # parse_errors, after the caller had explicitly asked for it not to.
        allow = config_bool(config, "yara_allow_includes", False)
        fingerprint = (allow, rule_fingerprint(paths))
        if fingerprint != self._fingerprint:
            self._rules, self._problems = compile_rules(paths, allow)
            self._loaded_from = [p.name for p in paths]
            self._fingerprint = fingerprint
        return self._rules

    def parse(self, path: Path, ctx: dict[str, Any],
              config: dict[str, Any]) -> dict[str, Any]:
        paths, problems = rule_files(config)
        if not HAVE_YARA:
            raise ParserUnavailable(
                f"yara-python is not installed, so {len(paths)} rule file(s) were "
                "not run; install it with 'pip install yara-python'")

        rules = self._load(config, paths)
        problems = problems + list(self._problems)

        ceiling = config_int(config, "yara_max_scan_bytes", 67108864)
        if ctx["size"] > ceiling:
            # The same refusal `max_parse_bytes` makes, for the same reason
            # and at a lower threshold. Fast matching bounds the common case
            # but libyara ignores it for any string whose condition reads its
            # count, offset or length, and a rule can allocate through the
            # console module until the deadline fires. Neither cost is bounded
            # by anything this extractor controls, so the one thing it can
            # bound is how much file it hands over.
            return {
                "rule_files": self._loaded_from,
                "namespaces": [namespace for namespace, _ in rules],
                "matches": [], "match_count": 0, "matches_truncated": False,
                "parse_errors": problems + [
                    f"scan: skipped, {ctx['size']} bytes is above "
                    f"yara_max_scan_bytes={ceiling}"],
            }

        budget = config_int(config, "yara_timeout_seconds", 10)
        limit = config_int(config, "yara_max_rules_reported", 64)
        fast = config_bool(config, "yara_fast_matching", True)

        matches: list[dict[str, Any]] = []
        deadline = time.monotonic() + budget
        for namespace, compiled in rules:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                problems.append(
                    f"{namespace}: not run, the {budget}s scan budget was already spent")
                continue
            try:
                found = compiled.match(
                    filepath=str(path),
                    timeout=max(1, int(remaining)),
                    fast=fast,
                    # Discarded rather than printed. See the class docstring.
                    console_callback=lambda line, ns=namespace: log.debug(
                        "yara console (%s): %s", ns, line),
                )
            except Exception as exc:
                # A timeout is the interesting case and it is reported like
                # any other failure: a rule set that could not finish is not
                # a rule set that found nothing.
                log.warning("yara namespace %s failed on %s: %s", namespace, path, exc)
                problems.append(f"{namespace}: {type(exc).__name__}: {exc}")
                continue
            for match in found:
                matches.append(self._describe(match, namespace, config, not fast))

        data: dict[str, Any] = {
            "rule_files": self._loaded_from,
            "namespaces": [namespace for namespace, _ in rules],
            "fast_matching": fast,
            "matches": matches[:limit],
            "match_count": len(matches),
            "matches_truncated": len(matches) > limit,
        }

        # A rule that declares an ATT&CK id this project does not recognise is
        # a rule whose author should be told. Dropping it silently would leave
        # the author believing the mapping works, which is the failure this
        # channel exists for - and a mistyped id in somebody's rule set is
        # far likelier than a deliberate one.
        for match in matches[:limit]:
            for technique in match.get("mitre_unknown") or []:
                problems.append(
                    f"{match['rule']}: mitre '{safe_text(technique, 64)}' is not a "
                    "technique this build knows, so it was not attached")

        if problems:
            data["parse_errors"] = problems
        return data

    def _describe(self, match, namespace: str, config: dict[str, Any],
                  complete: bool = True) -> dict[str, Any]:
        limit = config_int(config, "yara_max_matches", 64)
        meta = dict(getattr(match, "meta", {}) or {})
        strings = []
        for string in getattr(match, "strings", []) or []:
            instances = list(getattr(string, "instances", []) or [])
            strings.append({
                "identifier": string.identifier,
                # Offsets and lengths only. `matched_data` is never read.
                "offsets": [i.offset for i in instances[:limit]],
                "lengths": [i.matched_length for i in instances[:limit]],
                "count": len(instances),
                "truncated": len(instances) > limit,
                # Whether `count` is a total. Under fast matching libyara
                # stops after the first occurrence of a string, so a bomb with
                # seven hundred thousand hits reported `count: 1` and
                # `truncated: false` - and `truncated` is the field whose
                # whole job is to say that nothing was left out.
                "complete": complete and len(instances) <= limit,
            })
        declared = self._techniques(meta)
        return {
            "rule": match.rule,
            "namespace": namespace,
            "tags": list(getattr(match, "tags", []) or []),
            "severity": self._severity(meta, config),
            "description": meta.get("description"),
            "meta": meta,
            "strings": strings,
            "mitre": declared["mitre"],
            "mitre_unknown": declared["unknown"],
        }

    @staticmethod
    def _techniques(meta: dict[str, Any]) -> dict[str, list[str]]:
        """ATT&CK ids a rule declared, split into recognised and not.

        A rule is a much narrower statement than a finding key, so a rule
        author can be specific where the registry cannot - which is what
        makes this the extensible half of the mapping, in the same way the
        rule set itself is extensible.

        Unrecognised ids are kept separately rather than dropped, because a
        rules directory is somebody else's input and a rule declaring an id
        this project does not know is a rule whose author should be told. They
        surface in `parse_errors`.
        """
        raw = meta.get("mitre")
        if isinstance(raw, str):
            # YARA meta values are scalars, so a rule declaring more than one
            # technique writes them comma separated.
            candidates = [part.strip() for part in raw.split(",") if part.strip()]
        elif isinstance(raw, (list, tuple)):
            candidates = list(raw)
        else:
            candidates = []
        return {"mitre": attack.validate(candidates),
                "unknown": attack.unknown(candidates)}

    @staticmethod
    def _severity(meta: dict[str, Any], config: dict[str, Any]) -> str:
        """A rule's own severity, if it declared one this project recognises.

        The default is `info` rather than something louder, because a rule
        that forgot to say how much it matters should not be able to fail
        somebody's build by forgetting.
        """
        for candidate in (meta.get("severity"), config.get("yara_default_severity")):
            # `isinstance` before the membership test, and not after: an
            # unhashable config value raises on `in` against a dict, and that
            # exception would cost the whole extractor every match it had
            # already found.
            if isinstance(candidate, str) and candidate in SEVERITY_RANK:
                return candidate
        return "info"

    def findings(self, data: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        for match in data.get("matches") or []:
            where = match["strings"][0]["offsets"] if match["strings"] else []
            detail = (match.get("description")
                      or f"rule '{match['rule']}' matched")
            if where:
                detail += f", first at offset {where[0]}"
            tags = match.get("tags") or []
            if tags:
                detail += f" [{', '.join(tags)}]"
            out.append(mk_finding(self.name, "yara_match",
                f"{match['rule']}: {detail}", match["severity"],
                mitre=match.get("mitre") or None,
                # Offsets and counts. Never `matched_data`: the rule that
                # holds everywhere else in this project holds hardest here,
                # because a rules directory is user-extensible and the person
                # most likely to want the bytes is the person debugging a rule
                # that matches secrets.
                evidence=[{"name": "rule", "value": match["rule"]},
                          {"name": "string_count", "value": len(match.get("strings") or [])},
                          {"name": "first_offset",
                           "value": (match.get("strings") or [{}])[0].get("offset")}],
                discriminator=match["rule"]))
        return out
