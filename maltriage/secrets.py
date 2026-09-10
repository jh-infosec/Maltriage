"""
Shared secret engine: patterns, entropy and context.

Three detectors over one string, and they exist in that order because they
catch different things. **Known patterns catch what a rule exists for.**
**Entropy catches what no rule exists for**, which is the case that actually
matters, because a company's own API key format has no public matcher and
never will. **Context catches the value that is neither** -- an ordinary
looking string that a name beside it says is a password.

maltriage runs this over extracted strings, claude-recon-agent over JavaScript
and configuration files, and ShadowClip's hand-maintained `SECRET_FILTER`
becomes a caller rather than a fourth list. It is the second module written to
be shared, after `apis.py`, and the reason the package layout landed first.


## The engine never returns the secret

A `Candidate` carries an offset, a length, an entropy and the name of the rule
that fired. It has no field for the string, and neither does anything this
module returns. That is not a default to be overridden -- **there is no
configuration switch**, for the reason v0.3 gave about YARA match context: the
person most likely to enable one is the person debugging a rule that matches
secrets.

The rule extends past findings to `report.data`, because `--json` writes the
data and a report is stored, piped and shared. A tool that recovers a
credential into an artefact has turned a detection into a leak, and it has done
it to the one file its user was least expecting to be dangerous.

What this costs is real: a candidate cannot be verified without going back to
the sample. That is the correct place to verify it, by someone who has decided
to look.


## Severity, decided by the roadmap before any of this was written

Nothing reaches `high`. `extension_mismatch` earns high because content under a
lying extension is near-unambiguous deception, and a credential in a file is
not deception.

- A **known** format is `medium`. `AKIA...` is an AWS access key id and
  nothing else; a human should look at that file on its own account.
- **Entropy** and **context** are `low`. They are candidates, and
  `GATE_SEVERITY` is medium, so anything higher makes every minified bundle a
  CI failure.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Iterable

from .entropy import expected_random_entropy, shannon

#: A vendor format with a distinctive prefix. Medium.
KNOWN = "known"
#: A name beside a value says the value is a secret. Low.
CONTEXT = "context"
#: A token too random for what it sits in, with no rule to explain it. Low.
ENTROPY = "entropy"

TIER_SEVERITY = {KNOWN: "medium", CONTEXT: "low", ENTROPY: "low"}

#: Rules whose severity is not their tier's, with the reason.
#:
#: `private_key_block` matches the PEM header and nothing else, because the
#: strings extractor splits on newlines and the base64 body is therefore a
#: different string. Every TLS library on a machine contains that header as a
#: parser literal -- measured, `libmbedcrypto` alone accounts for ten matches
#: -- so at `medium` it would gate a build on the presence of OpenSSL.
#: Correlating the header with a body needs to read a region rather than a
#: string, which is v0.5's business.
RULE_SEVERITY = {"private_key_block": "low"}


def severity_of(rule: str, tier: str) -> str:
    return RULE_SEVERITY.get(rule) or TIER_SEVERITY.get(tier, "low")


@dataclass(frozen=True)
class Candidate:
    """One possible secret, described without quoting it.

    `rule` is a name from this file. `offset` is absolute in the subject when
    the caller supplied a base, and relative to the string otherwise. There is
    no field for the text and adding one is a change to the design rather than
    a convenience.
    """

    rule: str
    tier: str
    offset: int
    length: int
    entropy: float
    entropy_ratio: float

    def as_dict(self) -> dict[str, Any]:
        return {"rule": self.rule, "tier": self.tier, "offset": self.offset,
                "length": self.length, "entropy": self.entropy,
                "entropy_ratio": self.entropy_ratio}


# Known formats
#
# Every entry here is a prefix or a shape that belongs to one vendor and to
# nothing else, which is what earns `medium`. A pattern that merely looks
# secret-ish belongs in the entropy tier, where the severity matches the
# confidence.

#: Guards on every known pattern. `AKIA` followed by sixteen uppercase
#: characters occurs inside longer runs of uppercase in ordinary binaries --
#: measured, it fired on `wget` and `xkbprint` -- and a known-format match is
#: `medium`, which is a non-zero exit on somebody's build. A credential is a
#: whole token, so requiring it to be one costs nothing and removed both.
_EDGE_LEFT = r"(?<![A-Za-z0-9])"
_EDGE_RIGHT = r"(?![A-Za-z0-9])"


def _bounded(pattern: str) -> re.Pattern:
    return re.compile(_EDGE_LEFT + r"(?:" + pattern + r")" + _EDGE_RIGHT)


_KNOWN_RULES: tuple[tuple[str, re.Pattern], ...] = (
    ("aws_access_key_id", _bounded(r"(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}")),
    ("github_token", _bounded(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("github_fine_grained_token", _bounded(r"github_pat_[A-Za-z0-9_]{60,}")),
    ("gitlab_token", _bounded(r"glpat-[A-Za-z0-9_\-]{20,}")),
    ("slack_token", _bounded(r"xox[abposr]-[A-Za-z0-9-]{10,}")),
    ("slack_webhook",
     _bounded(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+")),
    ("stripe_live_key", _bounded(r"[sr]k_live_[A-Za-z0-9]{20,}")),
    ("google_api_key", _bounded(r"AIza[A-Za-z0-9_\-]{35}")),
    ("openai_key", _bounded(r"sk-proj-[A-Za-z0-9_\-]{20,}")),
    ("npm_token", _bounded(r"npm_[A-Za-z0-9]{36}")),
    ("pypi_token", _bounded(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{16,}")),
    ("sendgrid_key", _bounded(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}")),
    ("telegram_bot_token", _bounded(r"\d{8,10}:AA[A-Za-z0-9_\-]{32,}")),
    ("twilio_key", _bounded(r"SK[0-9a-fA-F]{32}")),
    ("azure_storage_key", re.compile(r"AccountKey=[A-Za-z0-9+/=]{60,}")),
    ("json_web_token",
     _bounded(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    # Not word-guarded: the literal begins and ends with dashes, which are
    # already boundaries, and a guard would refuse a match touching one.
    ("private_key_block",
     re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
)


# Context
#
# A name beside a value. This is the tier that fires on prose, so the value has
# to survive `_is_placeholder` before it counts -- `password=changeme` in a
# sample configuration is not a credential, and neither is
# `api_key=<your key here>`.

_CONTEXT = re.compile(
    r"(?i)\b(?:pass(?:word|wd|phrase)?|secret|api[_\-]?key|access[_\-]?key"
    r"|auth[_\-]?token|client[_\-]?secret|private[_\-]?key|credential)\b"
    r"\s*[=:]\s*[\"']?([^\s\"',;]{8,})")

#: Values that are examples rather than credentials. Anything with a bracket,
#: a brace or a shell expansion in it is a template, and the rest are what
#: people type when they are writing documentation.
_PLACEHOLDER_WORDS = frozenset({
    "password", "passwd", "secret", "changeme", "example", "test", "testing",
    "yourpassword", "your_password", "yourapikey", "your_api_key", "none",
    "null", "true", "false", "todo", "redacted", "removed", "hidden",
    "placeholder", "dummy", "sample", "default", "insertkeyhere",
})
_TEMPLATE = re.compile(r"[<>{}$%\[\]]|\.\.\.|\bxxx|\*\*\*")


# Entropy
#
# The tier that catches what no rule exists for. It is also the noisy one, so
# the exclusions below do most of the work: a long token in a binary is far
# more often a hash, a GUID or a base64 blob than it is a credential.

_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{16,}")
_GUID = re.compile(r"(?i)^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$")
_HEX = re.compile(r"(?i)^[0-9a-f]+$")

#: Lengths at which an all-hex token is a digest rather than a secret. md5,
#: sha1, sha224, sha256, sha384, sha512, and CRC-shaped short ones. maltriage
#: already reports the hashes it computed; reporting the ones a file mentions
#: as possible credentials would be noise on top of a fact already in the
#: report.
_DIGEST_LENGTHS = frozenset({8, 16, 32, 40, 56, 64, 96, 128})


def _reads_like_words(text: str) -> bool:
    """Whether the token is made of words rather than drawn at random.

    The measurement that produced this rule: after every other exclusion, the
    entropy tier still fired on one binary in five, and the matches were all
    symbol names -- `SECKEY_DestroyPrivateKey`, `CERT_DecodeAltNameExtension`,
    `u_getIntPropertyValue_74`. Mixed case, digits, underscores, dense enough
    to score as random, and obviously not credentials to a human.

    What separates them is that words are runs of one case. `Destroy` is six
    lowercase letters in a row; a token drawn from base62 changes case about
    every other character. So the test is the longest run of same-case
    letters.

    The threshold scales with length rather than being a constant, for the
    reason `expected_random_entropy` exists: a longer random token has more
    chances to contain a long run, so a fixed bar would reject more of them
    the longer they got. `log2(n) + 2` holds the false-negative rate near 5%
    from 32 characters to 48, where a fixed bar of six ranges from 12% to 21%.
    """
    longest = current = 0
    previous = None
    for char in text:
        if char.isalpha():
            case = char.isupper()
            current = current + 1 if case == previous else 1
            previous = case
        else:
            current, previous = 0, None
        longest = max(longest, current)
    return longest >= math.log2(max(len(text), 2)) + 2


def _has_all_classes(text: str) -> bool:
    """Lower case, upper case and a digit, all present.

    Punctuation deliberately does not substitute for any of them. Counting
    `_` as a class is how `CERT_VerifySignedDataWithPublicKeyInfo` passed a
    three-of-four test while containing no number at all.
    """
    return (any("a" <= c <= "z" for c in text)
            and any("A" <= c <= "Z" for c in text)
            and any(c.isdigit() for c in text))


def _alphabet_size(text: str) -> int:
    """How many symbols the token could have been drawn from.

    Judged from what it contains rather than from what it is: a token of forty
    lowercase hex characters had sixteen symbols available, and scoring it
    against sixty-four would call an ordinary digest suspiciously random. This
    is the same reasoning as scoring file entropy against what random data of
    that *length* reaches, applied to the other axis.
    """
    has_lower = any("a" <= c <= "z" for c in text)
    has_upper = any("A" <= c <= "Z" for c in text)
    has_digit = any(c.isdigit() for c in text)
    has_other = any(c in "+/=_-" for c in text)
    if _HEX.match(text):
        return 16
    size = (26 if has_lower else 0) + (26 if has_upper else 0) \
        + (10 if has_digit else 0) + (5 if has_other else 0)
    return max(size, 2)


_SCREAMING_SNAKE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")


def _is_placeholder(value: str) -> bool:
    stripped = value.strip("\"'`")
    if not stripped or len(set(stripped)) <= 2:
        return True
    if stripped.lower() in _PLACEHOLDER_WORDS:
        return True
    if _SCREAMING_SNAKE.match(stripped):
        # `client_secret=YOUR_CLIENT_SECRET`. An upper-snake value beside a
        # secret-ish name is an environment variable being named, not a
        # credential being set -- it is the shape of the thing that will later
        # hold the credential.
        return True
    return bool(_TEMPLATE.search(stripped))


def _is_uninteresting_token(text: str) -> bool:
    """Tokens that are long and random and still not secrets.

    Each exclusion here was measured rather than guessed. Without them the
    entropy tier fired on 85% of 1610 Linux system binaries, which is not a
    detector, it is a weather report.
    """
    if _GUID.match(text):
        return True
    if _HEX.match(text) and len(text) in _DIGEST_LENGTHS:
        return True
    if text.isdigit():
        return True
    if text.startswith("_Z"):
        # An Itanium-ABI mangled C++ symbol. `_ZNK9tesseract10UNICHARSET13
        # id_to_unicharEi` is long, mixed-case, has digits, and scores as
        # random because mangling is dense by design. Every C++ binary is full
        # of them.
        return True
    if _reads_like_words(text):
        return True
    if len(set(text)) == len(text):
        # Every character distinct, which is an enumeration and not a draw. A
        # base64 alphabet table is the common case and appears verbatim in
        # anything that encodes -- but the argument is general: forty
        # characters drawn at random from sixty-four repeat one with
        # probability about 0.999999, so not repeating is evidence the token
        # was written out rather than generated.
        return True
    return False


def entropy_of(text: str) -> tuple[float, float]:
    """Shannon entropy of `text`, and what fraction of random it reaches.

    The ratio is against `expected_random_entropy(len, alphabet)`, so a short
    token is not punished for being short and a hex token is not rewarded for
    being hex.
    """
    observed = shannon(text.encode("ascii", "replace"))
    reference = expected_random_entropy(len(text), _alphabet_size(text))
    if reference <= 0:
        return round(observed, 4), 0.0
    return round(observed, 4), round(min(observed / reference, 1.0), 4)


def scan(text: str, base: int = 0, min_length: int = 24,
         entropy_ratio: float = 0.95, stride: int = 1) -> list[Candidate]:
    """Every candidate secret in one string, described without quoting it.

    `base` is where `text` starts in the subject and `stride` is how many
    bytes each of its characters occupies -- two for the UTF-16 half of an
    extracted string table -- so the offsets come back absolute and land on
    the byte an analyst would seek to.

    The three tiers are tried in order and a span is claimed once: a known
    format that also looks random is a known format, and reporting it twice
    would double-count one secret in a queue somebody is ranking.
    """
    if not text:
        return []
    found: list[Candidate] = []
    claimed: list[tuple[int, int]] = []

    def overlaps(start: int, end: int) -> bool:
        return any(start < c_end and end > c_start for c_start, c_end in claimed)

    for name, pattern in _KNOWN_RULES:
        for match in pattern.finditer(text):
            if overlaps(match.start(), match.end()):
                continue
            claimed.append((match.start(), match.end()))
            observed, ratio = entropy_of(match.group())
            found.append(Candidate(name, KNOWN, base + stride * match.start(),
                                   match.end() - match.start(), observed, ratio))

    for match in _CONTEXT.finditer(text):
        value = match.group(1)
        start = match.start(1)
        if overlaps(start, match.end(1)) or _is_placeholder(value):
            continue
        claimed.append((start, match.end(1)))
        observed, ratio = entropy_of(value)
        found.append(Candidate("assigned_to_secret_name", CONTEXT, base + stride * start,
                               len(value), observed, ratio))

    for match in _TOKEN.finditer(text):
        token = match.group()
        if len(token) < min_length or overlaps(match.start(), match.end()):
            continue
        # The token has to be the whole string, not a token inside one. A
        # credential in a string table is its own null-terminated run; a
        # random-looking span inside a longer string is a span of something
        # else. Measured, this one rule takes the entropy tier from 12.3% of
        # Python source files to zero, and from 70.8% of binaries to 27.5%.
        if match.start() != 0 or match.end() != len(text):
            continue
        # Lower case, upper case and at least one digit. The digit is what
        # does the work: `CERT_VerifySignedDataWithPublicKeyInfo` is thirty
        # eight characters of mixed case that scores as random and contains
        # no number, because it is words. A token drawn from base62 omits
        # digits entirely with probability about 0.0007 at this length, so
        # requiring one costs almost nothing and removes a whole class of
        # symbol name that every other rule here lets through.
        if not _has_all_classes(token):
            continue
        if _is_uninteresting_token(token):
            continue
        observed, ratio = entropy_of(token)
        if ratio < entropy_ratio:
            continue
        claimed.append((match.start(), match.end()))
        found.append(Candidate("high_entropy_token", ENTROPY, base + stride * match.start(),
                               len(token), observed, ratio))

    found.sort(key=lambda c: c.offset)
    return found


def looks_like_secret(text: str) -> bool:
    """Whether `text` on its own would be reported.

    The entry point for a caller filtering values rather than scanning a
    document -- ShadowClip's `SECRET_FILTER` is the case this exists for. It
    answers about the whole string, so a sentence that happens to contain a
    token is not a secret by this test.
    """
    for _name, pattern in _KNOWN_RULES:
        if pattern.fullmatch(text):
            return True
    if len(text) < 24 or _is_uninteresting_token(text) or _is_placeholder(text):
        return False
    if not _TOKEN.fullmatch(text):
        return False
    return entropy_of(text)[1] >= 0.95


def rule_names() -> list[str]:
    """Every rule name this engine can report. Bounded, and it must stay so."""
    return sorted({name for name, _ in _KNOWN_RULES}
                  | {"assigned_to_secret_name", "high_entropy_token"})


def summarise(candidates: Iterable[Candidate]) -> dict[str, Any]:
    """Counts by tier and by rule, for the data half of the report."""
    by_tier: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    for candidate in candidates:
        by_tier[candidate.tier] = by_tier.get(candidate.tier, 0) + 1
        by_rule[candidate.rule] = by_rule.get(candidate.rule, 0) + 1
    return {"by_tier": dict(sorted(by_tier.items())),
            "by_rule": dict(sorted(by_rule.items()))}
