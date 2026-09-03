"""
Shared API name registry for maltriage.

What this module is: a vocabulary of Windows API names grouped into
capability categories, plus the matcher that recognises them. What it is not:
a detector. It answers "which of these names did you see", and the two
extractors that call it decide what to say about the answer.

That split is why this lives in its own module rather than inside an
extractor. The same names are wanted in two places -- the PE import table,
where they are symbols the loader will resolve, and the extracted strings,
where they are text the sample will feed to `GetProcAddress` at runtime. A
copy in each extractor would be two vocabularies drifting apart, which is the
problem the v0.4 package layout was added to prevent. This is its first use;
the secret engine and the ATT&CK registry follow.


## The two views are not equally trustworthy

An import table entry is a symbol name. It is unambiguous: the loader will
resolve it, the file will call it, and nothing else in the file looks like it.

A string is text. `CreateRemoteThread` appearing in a binary is good evidence
the binary intends to call it, but the same bytes appear in a debugger, in
this project's own test suite, and in any document that discusses malware. A
name that is also an ordinary English word -- `Sleep`, `connect`, `send`,
`system` -- appears in text that has nothing to do with an API at all, and a
vocabulary that matches those turns every README in a corpus into a finding.

So the vocabulary is filtered for the string view. `STRING_AMBIGUOUS` names
match in imports and never in strings. This is also why the registry is
Windows-only for now: the POSIX equivalents worth naming are almost all
ordinary words, and the ELF extractor reads `DT_NEEDED` library names but not
`.dynsym` function names, so a POSIX vocabulary would today be matched
against strings alone -- exactly the view it is least safe in.


## Nothing here reaches medium

`GATE_SEVERITY` is medium, and a medium finding is a non-zero exit. The rule
this project holds to is that a finding earns medium only if a file deserves a
human because of that finding alone, and no API name clears it:

- Individually, every name here is called by legitimate software. Debuggers
  call `WriteProcessMemory`. Installers call `RegSetValueEx`. Every program
  linked against a C runtime calls `LoadLibrary`.
- In combination they are better evidence, but "better" is not the same as
  measurable, and the false positive rate of a capability cluster is exactly
  what v0.7's corpus harness exists to establish. `registry_persistence_path`
  is already held at low for this reason, and this is the same argument.

So a category carries `info` or `low` and there is no path to medium. When
v0.7 can state the cost, that is the release that may change it.


## `mitre` is recorded and not emitted

Each category carries the ATT&CK technique it corresponds to, because that
mapping is real and writing it down next to the names is where it belongs.
Nothing reads it yet. The roadmap's rule for the ATT&CK item is that `mitre`
stays absent from a finding unless the finding is near-unambiguous, and a
capability inferred from names is not: a writable executable section is
consistent with packing, and so is a binary that resolves its imports by
hand. The field is reference data for the emitter that comes later, not a
claim this release makes.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from .models import mk_finding

#: Severity for a category whose names are unusual enough to rank a queue on.
LOW = "low"
#: Severity for a category common enough that its value is context, not signal.
INFO = "info"


# The registry
#
# `names` are canonical: the ANSI/wide suffix is left off, because `matches`
# strips one trailing `A` or `W` when a direct lookup misses. A name that
# genuinely ends in one of those letters is written out in full and found by
# the direct lookup before the strip is ever reached -- `CryptUnprotectData`
# is the case that makes this the right way round rather than normalising
# everything on the way in.
#
# `Ex` is never stripped. `VirtualAllocEx` allocates in another process and
# `VirtualAlloc` allocates in this one, which is the difference between the
# interesting case and the universal one.

CAPABILITIES: dict[str, dict[str, Any]] = {
    "process_injection": {
        "label": "process injection",
        "severity": LOW,
        "mitre": "T1055",
        "names": (
            "VirtualAllocEx", "VirtualProtectEx", "WriteProcessMemory",
            "ReadProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx",
            "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
            "NtQueueApcThread", "SetThreadContext", "GetThreadContext",
            "NtUnmapViewOfSection", "NtWriteVirtualMemory",
            "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
            "OpenProcess", "SuspendThread", "ResumeThread",
        ),
    },
    "dynamic_resolution": {
        "label": "dynamic API resolution",
        "severity": INFO,
        "mitre": "T1027.007",
        # Ubiquitous on its own -- every C runtime does this -- so it earns a
        # finding only alongside a second name, and never above info. Its
        # value is as context for a binary whose import table is thin.
        "names": (
            "LoadLibrary", "LoadLibraryEx", "GetProcAddress", "GetModuleHandle",
            "GetModuleHandleEx", "LdrLoadDll", "LdrGetProcedureAddress",
            "LdrGetDllHandle",
        ),
    },
    "anti_analysis": {
        "label": "anti-analysis",
        "severity": LOW,
        "mitre": "T1622",
        "names": (
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "NtSetInformationThread",
            "OutputDebugString", "DebugActiveProcess", "BlockInput",
            "GetTickCount", "GetTickCount64", "QueryPerformanceCounter",
            "NtQuerySystemInformation", "NtDelayExecution", "Sleep",
        ),
    },
    "discovery": {
        "label": "host and process discovery",
        "severity": INFO,
        "mitre": "T1057",
        "names": (
            "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
            "Module32First", "Module32Next", "EnumProcesses",
            "EnumProcessModules", "GetComputerName", "GetUserName",
            "GetComputerNameEx", "GetUserNameEx",
            "GetSystemInfo", "GetNativeSystemInfo", "GetVolumeInformation",
            "GetAdaptersInfo", "NetUserEnum", "NetWkstaGetInfo",
            "GetSystemDirectory", "GetWindowsDirectory",
        ),
    },
    "persistence": {
        "label": "persistence",
        "severity": LOW,
        "mitre": "T1547",
        "names": (
            "RegSetValueEx", "RegCreateKeyEx", "RegDeleteValue",
            "CreateService", "OpenSCManager", "OpenService", "StartService",
            "ChangeServiceConfig", "SetWindowsHookEx",
        ),
    },
    "privilege": {
        "label": "privilege and token manipulation",
        "severity": LOW,
        "mitre": "T1134",
        "names": (
            "AdjustTokenPrivileges", "OpenProcessToken", "OpenThreadToken",
            "LookupPrivilegeValue", "DuplicateTokenEx", "SetTokenInformation",
            "ImpersonateLoggedOnUser", "RtlAdjustPrivilege",
        ),
    },
    "credential_access": {
        "label": "credential access",
        "severity": LOW,
        "mitre": "T1555",
        "names": (
            "CredEnumerate", "CredRead", "CredWrite", "CryptUnprotectData",
            "LsaOpenPolicy", "LsaRetrievePrivateData", "SamConnect",
            "SamIConnect", "WNetEnumResource",
        ),
    },
    "surveillance": {
        "label": "input and screen capture",
        "severity": LOW,
        "mitre": "T1056",
        "names": (
            "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
            "GetKeyboardState", "GetRawInputData", "RegisterRawInputDevices",
            "GetForegroundWindow", "GetClipboardData", "BitBlt",
            "GetWindowText",
        ),
    },
    "execution": {
        "label": "process execution",
        "severity": INFO,
        "mitre": "T1106",
        "names": (
            "CreateProcess", "CreateProcessAsUser", "CreateProcessInternal",
            "ShellExecute", "ShellExecuteEx", "WinExec", "NtCreateUserProcess",
        ),
    },
    "network": {
        "label": "network communication",
        "severity": INFO,
        "mitre": "T1071",
        "names": (
            "InternetOpen", "InternetOpenUrl", "InternetConnect",
            "InternetReadFile", "InternetWriteFile", "HttpOpenRequest",
            "HttpSendRequest", "URLDownloadToFile", "URLDownloadToCacheFile",
            "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
            "WinHttpReceiveResponse", "WSAStartup", "WSASocket", "WSAConnect",
            "DnsQuery",
            # `gethostbyname` and `getaddrinfo` were here and are not any
            # more. They are libc, not Win32, and measuring the vocabulary
            # against 1610 Linux system binaries put them in 115 of them and
            # produced 20 of the 21 findings the whole run generated. They are
            # correct matches -- those binaries do resolve names -- and
            # useless ones, which is the distinction this project keeps
            # between data and a finding. They belong to the POSIX vocabulary
            # that arrives with ELF symbol parsing, where the caller is an
            # import table rather than a string table.
        ),
    },
    "crypto": {
        "label": "cryptography",
        "severity": INFO,
        "mitre": "T1486",
        "names": (
            "CryptAcquireContext", "CryptEncrypt", "CryptDecrypt",
            "CryptGenKey", "CryptDeriveKey", "CryptImportKey",
            "CryptExportKey", "CryptHashData", "CryptGenRandom",
            "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
        ),
    },
}


# Names excluded from the string view.
#
# An entry here is a name that is also ordinary text. Matched in an import
# table it is exactly as meaningful as any other symbol, because an import
# table holds symbols and nothing else; matched in strings it fires on prose,
# on log messages and on this project's own source code, and a finding that
# fires on a README is noise wearing a severity.
#
# One entry, because the vocabulary is Windows-only and Windows API names are
# overwhelmingly camel-case compounds that occur nowhere else. `Sleep` is the
# exception, and it is a real anti-analysis API rather than one that could be
# dropped to avoid the problem -- sleeping past a sandbox's observation window
# is the oldest evasion there is. The set exists for the POSIX vocabulary that
# arrives with ELF symbol parsing, where `connect`, `send`, `system`, `fork`
# and `socket` will each need an entry.
STRING_AMBIGUOUS = frozenset({
    "sleep",
})


# Tokens inside a longer string. An import name arrives bare, but the same
# name in the string table can carry a stdcall decoration (`_VirtualAlloc@16`)
# or a C++ mangling (`?CreateRemoteThread@@YAX`), and it can sit inside a
# longer run that the scanner did not split. Pulling identifier-shaped tokens
# out handles all three without the substring matching that would let
# `LoadLibrary` fire on `PreloadLibraryPath`.
#: A token is a whole identifier and is never cut short. It carried an upper
#: bound of 64 characters until that bound was measured: `j` * 64 followed by
#: `VirtualAllocEx@16` matched, and `j` * 63 followed by the same text did
#: not, because the bound split the padding at exactly the point that left the
#: API name starting a token of its own. Whether a name was found depended on
#: its offset modulo 64, and the version that found it was the wrong one --
#: that is the substring match on `PreloadLibraryPath` that this pattern
#: exists to refuse, arriving by a different route. Unbounded, a run of
#: identifier characters is one token whatever its length, and
#: `api_max_token_scan_bytes` is the only length rule.
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")

#: A string that is nothing but one identifier. Its only token is itself, so
#: the whole-string lookup has already decided it and tokenising is wasted.
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _canonical(name: str) -> str:
    """Lowercase, with leading underscores removed.

    ASCII only, and that is a rule rather than an assumption. `str.lower()` is
    Unicode-aware: U+212A KELVIN SIGN lowercases to `k`, so `GetKeyState`
    canonicalises to `getkeystate` and matches `GetKeyState`. Both callers
    decode through `ascii`/`replace` before reaching here, so nothing can
    exploit that today -- but the guard is one line and the POSIX vocabulary
    this module is waiting on will arrive through a different path.

    Not the suffix strip: that is a fallback applied at lookup time only when
    the direct form misses, so a name that really ends in `A` or `W` is found
    before anything is removed from it.
    """
    if not name.isascii():
        return ""
    return name.lstrip("_").lower()


def _build_index():
    """Map canonical name -> the categories that claim it, plus a spelling.

    A name may appear in more than one category, and that is not a mistake to
    be normalised away: `SetWindowsHookEx` installs a hook that survives a
    reboot and reads every keystroke, so it is honestly both persistence and
    surveillance. The value is a tuple rather than a single category so the
    matcher can report it under each.
    """
    every: dict[str, list[str]] = {}
    spelling: dict[str, str] = {}
    for category, spec in CAPABILITIES.items():
        for name in spec["names"]:
            canonical = _canonical(name)
            every.setdefault(canonical, []).append(category)
            spelling.setdefault(canonical, name)
    full = {name: tuple(cats) for name, cats in every.items()}
    strings = {name: cats for name, cats in full.items()
               if name not in STRING_AMBIGUOUS}
    return full, strings, spelling


IMPORT_INDEX, STRING_INDEX, SPELLING = _build_index()

#: Every canonical name, for callers that want the vocabulary itself.
VOCABULARY = frozenset(IMPORT_INDEX)

#: The two views, by name. A dict rather than a conditional so that an
#: unrecognised view is a `KeyError` to be raised rather than an `else`
#: branch to be silently taken.
_VIEW_INDEX = {"import": IMPORT_INDEX, "string": STRING_INDEX}


def _lookup(index: dict[str, tuple[str, ...]], candidate: str
            ) -> tuple[str | None, tuple[str, ...]]:
    """The index key `candidate` matched and its categories, or `(None, ())`.

    Direct first, then one trailing `A` or `W` removed, then a trailing `_A`
    or `_W`. `LoadLibraryW` misses directly and hits as `loadlibrary`;
    `CryptUnprotectData` hits directly and never has its `a` taken off, which
    is why the strip is a fallback rather than a normalisation applied on the
    way in.

    The underscored form is not a second guess at the same thing. `DnsQuery`
    is a macro, and what a binary actually imports is `DnsQuery_A` or
    `DnsQuery_W` -- so without this the registry's `DnsQuery` entry could
    never fire on a real import table. Registering both spellings instead
    would have been worse than useless: they would count as two names towards
    a category threshold, and one API would clear a bar meant for two.

    The key is returned rather than the candidate because the caller records
    what it matched, and what it matched is a name from this file. Returning
    the candidate would put the sample's own spelling into a report.
    """
    canonical = _canonical(candidate)
    hit = index.get(canonical)
    if hit is not None:
        return canonical, hit
    for stripped in _without_suffix(canonical):
        hit = index.get(stripped)
        if hit is not None:
            return stripped, hit
    return None, ()


def _without_suffix(canonical: str):
    """The ANSI/wide spellings of `canonical`, longest suffix first."""
    if len(canonical) > 5 and canonical[-2:] in ("_a", "_w"):
        yield canonical[:-2]
    if len(canonical) > 4 and canonical[-1] in ("a", "w"):
        yield canonical[:-1]


def match_symbol(name: str) -> tuple[str | None, tuple[str, ...]]:
    """The canonical name and categories for one import-table symbol.

    The whole name, not tokens inside it: an import entry is a symbol, so a
    symbol that merely contains a known name is a different symbol.
    """
    if not name:
        return None, ()
    return _lookup(IMPORT_INDEX, name)


def match_text(text: str, token_limit: int = 128) -> list[tuple[str, tuple[str, ...]]]:
    """Every known API name inside one extracted string.

    Returns `(canonical_name, categories)` pairs.

    The fast path is a whole-string lookup, because an API name in a binary's
    string table is normally a run of its own: the null terminators either
    side are what ended the run. A string that misses that way is taken apart
    into tokens, but only if it is short enough to be a symbol reference.

    Three things are never taken apart, and all three are the same rule: a
    symbol reference does not look like that.

    A string containing a space is prose or a command line, not a symbol. The
    forms worth tokenising are a stdcall decoration (`_VirtualAlloc@16`), a
    mangled C++ signature (`?CreateRemoteThread@@YAX`) and a delimited list
    (`kernel32.dll,CreateRemoteThread`), and not one of them has a space in
    it, so this drops nothing the token path was added to find. What it drops
    is `a sentence mentioning CreateRemoteThread`, which is documentation --
    and a triage tool that reports the manual as an injector has learned
    nothing about the file. It is also, measured on a 100 MB sample with 2.8
    million strings, about a third of the cost of matching.

    A string longer than `token_limit` is the same argument by length, and the
    bound on cost for the pathological case.

    A string that is already a bare identifier has been settled by the whole-
    string lookup above; its only token is itself.
    """
    if not text:
        return []
    canonical, categories = _lookup(STRING_INDEX, text)
    if canonical is not None:
        return [(canonical, categories)]
    if len(text) > token_limit or " " in text or _IDENTIFIER.fullmatch(text):
        return []

    out: list[tuple[str, tuple[str, ...]]] = []
    seen: set[str] = set()
    for token in _TOKEN.findall(text):
        canonical, categories = _lookup(STRING_INDEX, token)
        if canonical is None or canonical in seen:
            continue
        seen.add(canonical)
        out.append((canonical, categories))
    return out


def categorise(names: Iterable[str], view: str = "import") -> dict[str, list[str]]:
    """Group already-matched names by category, in this file's spelling.

    `view` selects which index decides membership, so a caller working from
    strings cannot credit a category through a name the string view excludes.
    An unrecognised view raises rather than defaulting: `view="Import"` used
    to select the string index and silently drop every ambiguous name, which
    is a wrong answer wearing the shape of a right one.

    The output carries `display` spellings rather than canonical keys because
    it lands in `report.data` and is read by a person. The canonical form is
    an implementation detail of the lookup and `virtualallocex` is not what
    the API is called.
    """
    if view not in _VIEW_INDEX:
        raise ValueError(
            f"unknown view {view!r}, expected one of {sorted(_VIEW_INDEX)}")
    index = _VIEW_INDEX[view]
    grouped: dict[str, set[str]] = {}
    for name in names:
        for category in index.get(_canonical(name), ()):
            grouped.setdefault(category, set()).add(_canonical(name))
    return {category: sorted(display(n) for n in found)
            for category, found in sorted(grouped.items())}


# Reporting
#
# The finding is built here rather than in each extractor so that the import
# view and the string view cannot word the same observation two different
# ways. What the extractors keep is the decision to call it at all, and which
# view to call it with.

#: The one key every capability finding files under. One key, with the
#: category in the detail and the data, for the reason v0.3 gave for
#: `yara_match`: a key set that grows when somebody adds a category is not one
#: a dashboard can count on, nor one the findings envelope can call bounded.
FINDING_KEY = "api_capability"

_VIEW_PHRASE = {
    "import": "in the import table",
    "string": "in the sample's strings",
}


def capability_findings(extractor: str, capabilities: dict[str, list[str]],
                        min_names: int, view: str = "import") -> list[dict[str, Any]]:
    """One finding per capability that cleared `min_names`.

    Below the threshold nothing is emitted and nothing is lost: the names are
    already in `report.data`, which is where a single observation belongs. A
    lone `GetTickCount` is not evidence of anything and a lone
    `CreateRemoteThread` is one symbol in a table the analyst can read. The
    data-and-findings split is what makes it safe to be strict here.
    """
    out = []
    for category, names in capabilities.items():
        spec = CAPABILITIES.get(category)
        if spec is None or len(names) < max(1, min_names):
            continue
        shown = ", ".join(names[:6])
        more = "" if len(names) <= 6 else f", and {len(names) - 6} more"
        out.append(mk_finding(
            extractor, FINDING_KEY,
            f"{len(names)} {spec['label']} API name(s) "
            f"{_VIEW_PHRASE.get(view, view)}: {shown}{more}",
            spec["severity"]))
    return out


def display(canonical: str) -> str:
    """The registry's spelling of a canonical name, for a finding's detail.

    Findings quote the vocabulary's spelling rather than the sample's, so what
    reaches a report is text this project wrote. That is the reason a
    capability list needs no `safe_text` and no length cap, and it is a
    guarantee rather than a convention: an unknown key raises instead of being
    echoed back.

    It used to be `SPELLING.get(canonical, canonical)`, which made the
    guarantee true only because every caller happened to pass a key that came
    out of `_lookup`. Handed anything else it returned it verbatim -- ANSI
    escapes included -- so the docstring above it was a claim about the
    callers rather than about this function, and one refactor away from being
    false. A `KeyError` here is a bug in this module, never a hostile sample:
    the pipeline isolates it, records it under `<extractor>.findings`, and
    keeps the extracted data.
    """
    return SPELLING[canonical]
