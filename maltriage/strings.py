"""
ASCII and UTF-16 string extraction, and the indicators drawn from them.

The largest stream extractor, and the one with the most ways to go wrong: it
runs over attacker-controlled bytes, it must stay bounded on a file that is
nothing but strings, and every run it reports crosses chunk boundaries it did
not choose.
"""

from __future__ import annotations
import re
from pathlib import Path
from typing import Any

from . import apis
from . import secrets as secret_engine
from .base import StreamExtractor
from .config import config_bool, config_int, config_list, config_ratio
from .models import mk_finding


# strings

#: Printable ASCII, and deliberately nothing else. Excluding the control
#: range at extraction time is what makes these strings safe to put in a
#: report without sanitising: ESC is 0x1B and cannot appear in a run.
PRINTABLE = rb"\x20-\x7e"

ASCII_RUN = re.compile(rb"[" + PRINTABLE + rb"]{%d,}")
WIDE_RUN = re.compile(rb"(?:[" + PRINTABLE + rb"]\x00){%d,}")

# Indicators, matched against extracted strings rather than raw bytes, which
# bounds the work by `strings_max_retained` instead of by the sample.
# Every pattern here is linear: no nested quantifier, no backtracking trap.
IOC_PATTERNS = {
    "urls": re.compile(r"\b(?:https?|ftps?)://[^\s\"'<>\\)\]}]{4,}"),
    "emails": re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b"),
    # Lookarounds rather than `\b`, because a word boundary sits happily in
    # the middle of a longer dotted run: `1.3.6.1.5.5.7.3.1` is one object
    # identifier and the old pattern read four addresses out of it. Measured
    # over 1,200 ordinary files, this removed 32 of 98 distinct values without
    # touching a single real address.
    "ipv4": re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
    "registry_paths": re.compile(
        r"\b(?:HKEY_[A-Z_]{4,24}|HKLM|HKCU|HKCR|HKU)\\[^\s\"'<>|]{2,200}"),
    "mutexes": re.compile(r"\b(?:Global|Local)\\[^\s\"'<>|]{2,200}"),
    "windows_paths": re.compile(r"\b[A-Za-z]:\\\\?[^\s\"'<>|]{2,200}"),
    "unix_paths": re.compile(
        r"(?:^|[\s\"'=:])(/(?:usr|etc|tmp|var|opt|home|bin|sbin|lib|dev|proc)"
        r"/[^\s\"'<>|]{1,200})"),
}

# Registry locations that survive a reboot. Kept in config rather than here so
# the list can grow without a code change.
RUN_KEY_MARKERS = ("currentversion\\run", "currentversion\\runonce",
                   "currentversion\\policies\\explorer\\run",
                   "winlogon", "\\services\\", "image file execution options")


class StringsExtractor(StreamExtractor):
    """Printable ASCII and UTF-16LE strings, taken off the shared pass.

    A stream extractor rather than a random-access one, because strings are
    the one thing in this tool that genuinely wants every byte in order and
    nothing else. That makes bounded memory the whole problem: the naive
    version keeps every string it finds, and a 400 MB text file has tens of
    millions of them.

    So three ceilings, and each says when it bit. `strings_max_retained`
    caps how many are kept while the count keeps rising, so the report can
    still say how many there were. `strings_max_length` caps one string, and
    a run longer than it contributes its first that-many bytes and no more.
    `strings_max_iocs` caps each indicator list.

    Runs are found with one regex per chunk rather than a Python loop over
    bytes, because the loop costs about a minute on a 200 MB sample and the
    regex costs under a second. A run crossing a chunk boundary is carried
    forward, and the tests pin that the result does not depend on the chunk
    size - which is the property that broke first when this was written.

    Extraction only. These strings are data; deciding that one looks like a
    credential is the v0.4 secret engine's job and deciding that one names a
    suspicious API is a heuristic that belongs in `findings`. Nothing here
    reaches medium: an installer writing a Run key is an installer, and
    `GATE_SEVERITY` is medium.
    """

    name = "strings"

    def begin(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> None:
        self._min = config_int(config, "strings_min_length", 6)
        self._max = config_int(config, "strings_max_length", 1024)
        self._keep = config_int(config, "strings_max_retained", 2048)
        self._ascii_re = re.compile(rb"[" + PRINTABLE + rb"]{%d,}" % self._min)
        # The lookbehind is the fix for a wide run stealing the last character
        # of the ASCII string in front of it. See `_RunScanner` for why it is
        # in the pattern rather than applied to the matches afterwards.
        self._wide_re = re.compile(
            rb"(?<![" + PRINTABLE + rb"])(?:[" + PRINTABLE + rb"]\x00){%d,}" % self._min)
        self._scanners = {
            "ascii": _RunScanner(self._ascii_re, self._max, step=1),
            "wide": _RunScanner(self._wide_re, self._max, step=2),
        }
        self._found = {"ascii": [], "wide": []}
        self._counts = {"ascii": 0, "wide": 0}
        self._long = 0
        self._tokens = config_int(config, "api_max_token_scan_bytes", 128)
        self._secret_min = config_int(config, "secrets_min_entropy_length", 24)
        self._secret_ratio = config_ratio(config, "secrets_entropy_ratio", 0.95)
        self._secret_cap = config_int(config, "secrets_max_candidates", 32)
        # Candidates, never the strings behind them. Capped because a file can
        # hold any number of them and this list is the one accumulator here
        # that a sample controls the size of - the API set is bounded by a
        # vocabulary, this is not.
        self._secrets: list[Any] = []
        self._secrets_dropped = 0
        # Bounded by the registry, not by the sample: this can never hold more
        # than the vocabulary, whatever the file does. It is the only
        # accumulator in this extractor that needs no cap, and the reason is
        # worth stating - what goes in comes from `apis`, not from the bytes.
        self._api: set[str] = set()

    def feed(self, chunk: bytes) -> None:
        for kind, scanner in self._scanners.items():
            for run, over_length, offset in scanner.feed(chunk):
                self._record(kind, run, over_length, offset)

    def _record(self, kind: str, run: bytes, over_length: bool, offset: int) -> None:
        self._counts[kind] += 1
        if over_length:
            self._long += 1
        text = run.decode("ascii", "replace") if kind == "ascii" else \
            run[::2].decode("ascii", "replace")

        # API matching runs here rather than over the retained list, and that
        # placement is the whole point of doing it in the extractor. The
        # retained list stops at `strings_max_retained`, and `text` is off by
        # default, so a findings pass over `report.data` would see a truncated
        # subset on a verbose run and nothing at all on a normal one - while
        # the packed sample this is meant to catch is exactly the one with
        # hundreds of thousands of strings. Every string is matched; only what
        # matched is kept.
        for canonical, _categories in apis.match_text(text, self._tokens):
            self._api.add(canonical)

        # The detector runs here because this is the only place the strings
        # exist: `strings_include_text` is off by default and the retained
        # list has a ceiling, so a pass over `report.data` would have nothing
        # to read. What it produces is a candidate with an offset and no text,
        # and deciding which candidates deserve a finding stays in
        # `findings()` where a heuristic belongs.
        stride = 1 if kind == "ascii" else 2
        for candidate in secret_engine.scan(text, base=offset,
                                            min_length=self._secret_min,
                                            entropy_ratio=self._secret_ratio,
                                            stride=stride):
            if len(self._secrets) >= self._secret_cap:
                self._secrets_dropped += 1
                continue
            self._secrets.append(candidate)

        # The cap is shared across both kinds, not granted to each. Per-kind
        # it was a ceiling of twice what the config asked for, and the comment
        # beside the default claimed the product as the worst case.
        if len(self._found["ascii"]) + len(self._found["wide"]) < self._keep:
            self._found[kind].append(text)

    def finish(self, path: Path, ctx: dict[str, Any],
               config: dict[str, Any]) -> dict[str, Any]:
        for kind, scanner in self._scanners.items():
            for run, over_length, offset in scanner.flush():
                self._record(kind, run, over_length, offset)

        strings = self._found["ascii"] + self._found["wide"]
        data: dict[str, Any] = {
            "ascii_count": self._counts["ascii"],
            "wide_count": self._counts["wide"],
            "retained": len(strings),
            "retained_truncated": (self._counts["ascii"] + self._counts["wide"]
                                   > len(strings)),
            "over_length": self._long,
            "min_length": self._min,
        }
        indicators, truncated = self._indicators(strings, config)
        data.update(indicators)

        # Which known API names appeared, and under which capabilities. Not
        # the strings themselves, and not subject to the switch below: this
        # list is drawn from the registry's fixed vocabulary, so it is text
        # this project wrote about a file rather than text taken out of one.
        # That is what makes it safe to publish unconditionally, and it is
        # also why it needs no truncation flag - unlike every other list in
        # this extractor, it cannot grow with the sample.
        data["api_names"] = sorted(apis.display(n) for n in self._api)
        data["api_capabilities"] = apis.categorise(self._api, view="string")

        # Offsets, lengths, entropies and rule names. No secret reaches here,
        # and there is no switch that would let one: `--json` writes this
        # dictionary to a file somebody keeps.
        data["secrets"] = {
            "candidates": [c.as_dict() for c in self._secrets],
            "counts": secret_engine.summarise(self._secrets),
            "candidates_truncated": bool(self._secrets_dropped),
        }

        # The strings themselves are off by default, and this is the one
        # switch in the extractor set. What it controls is a dump rather than
        # a finding: the indicators above are the triage value and are always
        # present, while the raw list is two megabytes of somebody else's file
        # in an artefact that gets stored, piped and shared. A sample that
        # harvests credentials has them among its strings.
        #
        # Unlike YARA's match bytes there is no argument for making this
        # unconditional, and unlike YARA's console output there is no way for
        # it to leak without being asked: the default is off and the caller
        # has to say otherwise.
        if config_bool(config, "strings_include_text", False):
            data["text"] = strings

        # Every cap says when it bit, through the channel the CLI already
        # renders. A capped list that reads as a total is the failure this
        # project has now made four times in four extractors.
        problems = []
        if data["retained_truncated"]:
            problems.append(
                f"strings: only the first {len(strings)} of "
                f"{data['ascii_count'] + data['wide_count']} strings were kept, so "
                "the indicators below were found in a subset")
        if truncated:
            problems.append(
                f"indicators: {', '.join(sorted(truncated))} reached "
                "strings_max_iocs, so those lists are partial")
        if self._long:
            problems.append(
                f"strings: {self._long} run(s) were longer than "
                "strings_max_length and contributed only their first bytes")
        if self._secrets_dropped:
            problems.append(
                f"secrets: {self._secrets_dropped} candidate(s) beyond "
                "secrets_max_candidates were not kept, so the counts below are "
                "a floor")
        if problems:
            data["parse_errors"] = problems
        return data

    def _indicators(self, strings: list[str], config: dict[str, Any]) -> dict[str, Any]:
        limit = config_int(config, "strings_max_iocs", 128)
        found = {name: [] for name in IOC_PATTERNS}
        truncated = set()
        for text in strings:
            for name, pattern in IOC_PATTERNS.items():
                for match in pattern.finditer(text):
                    value = match.group(match.lastindex or 0)
                    if name == "ipv4" and not _is_ipv4(value):
                        continue
                    bucket = found[name]
                    if value in bucket:
                        continue
                    if len(bucket) >= limit:
                        truncated.add(name)
                        continue
                    bucket.append(value)
        result: dict[str, Any] = dict(found)
        result["indicators_truncated"] = sorted(truncated)
        # Counted, not removed. An analyst reading `report.data` sees every
        # value; what these change is how many the finding is about, which is
        # the same arrangement the entropy rule uses for a compressed format.
        result["urls_boilerplate"] = sum(
            1 for url in found["urls"] if _is_boilerplate(url, config))
        result["ipv4_oid_shaped"] = sum(
            1 for value in found["ipv4"] if _is_oid(value, config))
        return result, truncated

    def findings(self, data: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        out = []
        for key, label, severity in (
                ("urls", "URL", "info"),
                ("emails", "email address", "info"),
                ("ipv4", "hardcoded IPv4 address", "low"),
                ("mutexes", "named mutex", "low"),
                ("windows_paths", "absolute Windows path", "info"),
                ("unix_paths", "absolute Unix path", "info")):
            values = data.get(key) or []
            # The two measured exclusions. The values stay in `report.data`;
            # the finding is about the ones that could be a destination.
            if key == "urls":
                values = [v for v in values if not _is_boilerplate(v, config)]
                set_aside = (data.get("urls_boilerplate") or 0)
            elif key == "ipv4":
                values = [v for v in values if not _is_oid(v, config)]
                set_aside = (data.get("ipv4_oid_shaped") or 0)
            else:
                set_aside = 0
            if not values:
                continue
            shown = ", ".join(values[:4])
            more = "" if len(values) <= 4 else f", and {len(values) - 4} more"
            # Said out loud, because a count that quietly excludes things is a
            # count nobody can check.
            aside = (f" ({set_aside} boilerplate or identifier(s) set aside)"
                     if set_aside else "")
            # "at least", not a total, when the list hit its ceiling. The
            # count is of what was kept, and saying otherwise is a number
            # nobody measured.
            capped = key in (data.get("indicators_truncated") or [])
            how_many = f"at least {len(values)}" if capped else str(len(values))
            out.append(mk_finding(self.name, f"{key}_present",
                f"{how_many} {label}(s) in the sample's strings: "
                f"{shown}{more}{aside}", severity))

        markers = [m.lower() for m in config_list(config, "strings_run_keys",
                                                  list(RUN_KEY_MARKERS))]
        persistence = [p for p in data.get("registry_paths") or []
                       if any(m in p.lower() for m in markers)]
        others = [p for p in data.get("registry_paths") or [] if p not in persistence]
        capped = "registry_paths" in (data.get("indicators_truncated") or [])
        if persistence:
            # Low, not medium. An installer writing a Run key is an installer,
            # and `GATE_SEVERITY` is medium: a finding earns it only if a file
            # deserves a human because of that finding alone. Turning this
            # into evidence is the classifier's job, once the cost is known.
            # The corpus harness landed in v0.4.2 and cannot state it: this
            # never fired over 6,688 ordinary Linux files, which says nothing
            # about Windows ones. It waits on a Windows corpus, which the
            # roadmap now carries as an item rather than as a release.
            out.append(mk_finding(self.name, "registry_persistence_path",
                f"{'at least ' if capped else ''}{len(persistence)} registry "
                f"path(s) that survive a reboot: "
                f"{', '.join(persistence[:3])}", "low"))
        if others:
            out.append(mk_finding(self.name, "registry_path_present",
                f"{'at least ' if capped else ''}{len(others)} registry path(s): "
                f"{', '.join(others[:3])}", "info"))

        # A name in the string table is weaker evidence than the same name in
        # an import table - text is text - but it is the only evidence there
        # is when a sample resolves its imports at runtime, which is the case
        # worth catching. The registry holds the severities; none reaches
        # medium.
        out.extend(apis.capability_findings(
            self.name, data.get("api_capabilities") or {},
            config_int(config, "api_min_names_per_capability", 2),
            view="string"))
        out.extend(self._secret_findings(data))
        return out

    def _secret_findings(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """The policy half of the secret engine.

        The detector ran during extraction because that is where the strings
        were. What happens here is the decision: one finding per rule, its
        severity taken from the tier, and the offsets carried so somebody can
        go and look. A known format is medium because a human should look at
        that file on its own account; entropy and context are low because they
        are candidates and `GATE_SEVERITY` is medium.
        """
        block = data.get("secrets") or {}
        grouped: dict[str, list[dict[str, Any]]] = {}
        for candidate in block.get("candidates") or []:
            grouped.setdefault(candidate["rule"], []).append(candidate)

        capped = block.get("candidates_truncated")
        out = []
        for rule, found in sorted(grouped.items()):
            tier = found[0]["tier"]
            offsets = ", ".join(str(c["offset"]) for c in found[:4])
            more = "" if len(found) <= 4 else f", and {len(found) - 4} more"
            out.append(mk_finding(self.name, "secret_candidate",
                f"{'at least ' if capped else ''}{len(found)} string(s) matching "
                f"{rule} at offset(s) {offsets}{more}. The value is not in this "
                "report; seek to the offset in the sample to see it.",
                secret_engine.severity_of(rule, tier),
                # Offsets, lengths and entropies. Never the value, and there
                # is no configuration that would add it.
                evidence=[{"name": "tier", "value": tier},
                          {"name": "count", "value": len(found)}]
                         + [{"name": "offset", "value": c["offset"]}
                            for c in found[:4]]
                         + [{"name": "entropy_ratio",
                             "value": found[0]["entropy_ratio"]}],
                discriminator=rule))
        return out


class _RunScanner:
    """Finds runs of a pattern across chunk boundaries, in bounded memory.

    The rule that makes this correct: **carry the trailing bytes that could
    still be part of a run, not the trailing bytes that already matched one.**

    The first version carried a run only when the regex had matched and the
    match reached the end of the buffer. A fragment shorter than the minimum
    length can never match `{6,}`, so it was silently dropped and the next
    buffer restarted inside the run: `MZAPPDATAROAM` split at a 4096-byte
    boundary was reported as `PPDATAROAM`. Worse for UTF-16, where a
    continuation that resumed one byte late was emitted as a fresh run, so
    `wide_count` on 100 MB of `A\x00` was literally the number of chunks. The
    result depended on `read_chunk_bytes`, which is the one thing a stream
    extractor may never let a reader see.

    So the tail is found by walking backwards over what could continue a run,
    which covers the matched case and the too-short case with the same code,
    and matches are emitted only where they end before that tail begins.

    **The guard byte.** A UTF-16 run may not begin at a printable byte whose
    predecessor is also printable. Without that rule the wide pattern reaches
    one byte too far left wherever an ASCII string's NUL terminator sits
    against a wide string: the last character of `config\x00` plus that NUL is
    itself a valid `(printable, NUL)` pair, so `config\x00` followed by a
    wide `AKIA...` extracted as `gAKIA...`. Both readings are correct regexes
    over those bytes and the engine takes the leftmost.

    It is a lookbehind in the pattern rather than a filter over the matches
    because `finditer` returns non-overlapping matches: rejecting the run that
    starts at `g` afterwards would not then find the one that starts at `A`,
    since it lies inside the rejected span.

    A lookbehind has nothing to look at when a match starts at offset zero of
    a buffer, which would make the result depend on where the chunks fell --
    the one thing this class exists to prevent. So every buffer is prefixed
    with the byte that preceded it, and offsets are shifted back by one to
    compensate. That byte cannot seed a false match of its own: it is only
    printable when the carry is non-empty, and a non-empty carry always begins
    with a printable byte rather than the NUL a pair would need.

    What this gives up is a wide string that begins immediately after ASCII
    text with no NUL between them, which is ambiguous in the bytes and rare in
    practice, since strings in a string table are terminated.
    """

    def __init__(self, pattern, maximum: int, step: int) -> None:
        self.pattern, self.step = pattern, step
        self.ceiling = maximum * step
        self.carry = b""
        self.skipping = False
        self.skip_half = False
        # The byte immediately before the current buffer, so the wide
        # pattern's lookbehind has something to look at even when a run
        # begins at a chunk boundary. NUL rather than None at the start of a
        # file: nothing precedes the first byte, and a run may begin there.
        self.prior = 0
        # Absolute position in the file of the next byte `feed` has not seen.
        # A run's offset is what makes a secret finding actionable - "there
        # is a credential in this 40 MB file" is not a finding - and it is
        # the one thing a scanner working a chunk at a time has to be told to
        # remember, because every position it computes is relative to a buffer
        # that will not exist a moment later.
        self.fed = 0

    def _continuable_from(self, buffer: bytes) -> int:
        """Where the trailing bytes that could still extend a run begin."""
        index = len(buffer)
        if self.step == 1:
            while index and 0x20 <= buffer[index - 1] <= 0x7E:
                index -= 1
            return index
        # A UTF-16LE run is (printable, NUL) pairs, so its prefixes are whole
        # pairs optionally followed by a lone printable byte - the half pair
        # a boundary can split.
        if index and 0x20 <= buffer[index - 1] <= 0x7E:
            index -= 1
        while index >= 2 and buffer[index - 1] == 0 and 0x20 <= buffer[index - 2] <= 0x7E:
            index -= 2
        return index

    def _leading_run_end(self, buffer: bytes) -> tuple[int, bool]:
        """Where the run a previous buffer left unfinished stops.

        Returns the length consumed and whether it ended on half a UTF-16
        pair. The parity has to be carried: a chunk size that is odd, or that
        does not divide the run, leaves the next buffer starting on the NUL
        of a pair rather than on its printable half. Treating that lone NUL
        as the end of the run made a 200 000-pair file report one run per
        chunk at a chunk size of one, three or seven bytes.
        """
        index = 0
        if self.step == 1:
            while index < len(buffer) and 0x20 <= buffer[index] <= 0x7E:
                index += 1
            return index, False
        if self.skip_half:
            if index < len(buffer) and buffer[index] == 0:
                index += 1
            else:
                return index, False
        while (index + 1 < len(buffer) and 0x20 <= buffer[index] <= 0x7E
               and buffer[index + 1] == 0):
            index += 2
        half = index < len(buffer) and 0x20 <= buffer[index] <= 0x7E
        return (index + 1 if half else index), half

    def feed(self, chunk: bytes):
        # Where this chunk begins in the file, fixed before anything trims it.
        start = self.fed
        self.fed += len(chunk)

        if self.skipping:
            # Inside a run already emitted at its full length. Discard the
            # rest of it, and stop skipping the moment it ends - which the
            # first version never did, so an unrelated later string was
            # thrown away as though it were a tail.
            consumed, half = self._leading_run_end(chunk)
            if consumed == len(chunk):
                self.skip_half = half
                return
            self.skipping = False
            self.skip_half = False
            if consumed:
                self.prior = chunk[consumed - 1]
            chunk = chunk[consumed:]
            start += consumed

        # `carry` holds bytes that end exactly where this chunk begins, so the
        # buffer starts that many bytes earlier in the file; the guard byte in
        # front of it shifts everything one further. Every offset below is
        # buffer-relative until this is added back.
        origin = start - len(self.carry) - 1
        buffer = bytes([self.prior]) + self.carry + chunk
        self.carry = b""
        # Never zero: the guard byte is not part of the run, so it must not be
        # carried into the next buffer as though it were.
        #
        # Defensive rather than demonstrated. For the walk to reach the guard
        # the guard must be printable, which needs an empty carry, and the
        # only branch that produces both is the skipping path. I could not
        # build an input that reaches it, and mutation testing confirms no
        # test fails without this line - which is exactly why it says so here
        # rather than pretending to be pinned.
        tail = max(self._continuable_from(buffer), 1)
        self.prior = buffer[tail - 1]

        for match in self.pattern.finditer(buffer):
            if match.end() > tail:
                break
            run = match.group()
            if len(run) >= self.ceiling:
                yield run[: self.ceiling], True, origin + match.start()
            else:
                yield run, False, origin + match.start()

        pending = buffer[tail:]
        if len(pending) >= self.ceiling:
            yield pending[: self.ceiling], True, origin + tail
            self.skipping = True
            # The ceiling is a whole number of units, so what is left of the
            # run keeps the alignment `pending` started with.
            self.skip_half = self.step == 2 and len(pending) % 2 == 1
        else:
            self.carry = pending

    def flush(self):
        # Guarded the same way, so a run left in the carry is subject to the
        # same rule as one found mid-buffer. `fullmatch` against the bare
        # carry would have no predecessor to look at and would accept a run
        # the buffer path had refused.
        guarded = bytes([self.prior]) + self.carry
        if self.carry and self.pattern.fullmatch(guarded, 1):
            yield self.carry[: self.ceiling], False, self.fed - len(self.carry)
        self.carry = b""
        self.skipping = False
        self.skip_half = False
        self.fed = 0
        self.prior = 0


def _is_boilerplate(url: str, config: dict[str, Any]) -> bool:
    """Whether a URL is a licence, a schema or a translation notice.

    The scheme is stripped before matching: the same notice appears under
    `http` and `https` across a distribution, and a list that had to carry
    both spellings of every entry would be a list somebody maintains wrongly.
    """
    bare = re.sub(r"^[a-z]+://", "", url.strip().lower())
    return any(bare.startswith(prefix.lower())
               for prefix in config_list(config, "ioc_boilerplate_urls", []))


def _is_oid(value: str, config: dict[str, Any]) -> bool:
    """Whether a dotted quad is an ASN.1 arc rather than an address."""
    return any(value.startswith(prefix)
               for prefix in config_list(config, "ioc_oid_prefixes", []))


def _is_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and len(p) <= 3 and int(p) < 256
                                   for p in parts)
