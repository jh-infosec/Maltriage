"""
Script files: what a `.ps1`, `.vbs`, `.js`, `.hta`, `.wsf`, `.bat` or shell
script would do when run.

Since 2022, when Office began blocking macros in files from the internet,
most first-stage attachments have been scripts or shortcuts to them. None of
them has a magic number, so until this module every one came back
`unrecognised_format` and nothing else, however plainly it said what it was
for.

The rule this module keeps is the one the VBA scanner keeps: **what a script
can do is ordinary; one particular shape of it is not.** A build script that
downloads a tool, an installer that starts a process, a logon script that
hides its window: each is a line in somebody's repository, and each is `low`
at most here. What reaches the gate is a dropper's shape, specific enough
that an ordinary script does not take it by accident:

  * a PowerShell download cradle: an expression invoked on what was just
    downloaded, in one statement;
  * an encoded PowerShell launch (`-EncodedCommand` and its prefixes, with a
    base64 argument);
  * base64 decoded and handed to `Invoke-Expression`;
  * a Windows binary fetching a URL it was never meant to fetch: `certutil
    -urlcache`, `bitsadmin /transfer`, `mshta http`, `regsvr32 /i:http`,
    `rundll32 javascript:`, `msiexec /i http`;
  * a Windows Script Host write-and-run: an HTTP object, a stream written to
    disk, and a `Run` or `ShellExecute`, in one script;
  * a shell pipeline that hands a download straight to a shell.

Bytes, not names. Only a file nothing else identified (`unknown`, or a
`script` by its shebang) is read, and only if it reads as text. A document
part is XML and a PDF is a PDF, so a security write-up quoting a cradle in a
`.docx` is never read as one. A plain text file that quotes a working cradle
is, and is reported, because pasted into a console it is one.

The text never reaches a report. What is reported is the language it reads
as, and names from this module's own lists.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from pathlib import Path
from typing import Any

from .base import StreamExtractor
from .config import config_int
from .models import mk_finding

_SAMPLE = 65536
#: How much of a file decides whether it is text at all.
_DECIDE = 4096

#: Features of each language, as (name, pattern). A language is the one with
#: the most distinct features, and needs two: one keyword is a mention, two
#: are a dialect. Case-insensitive except where case is the feature.
LANGUAGES: dict[str, tuple[re.Pattern, ...]] = {
    "hta": (re.compile(r"(?i)<hta:application"),
            re.compile(r"(?i)<script[^>]+language\s*=\s*[\"']?(?:vbscript|jscript|javascript)")),
    "wsf": (re.compile(r"(?i)<job\b"), re.compile(r"(?i)<script[^>]+language\s*="),
            re.compile(r"(?i)<package\b")),
    "powershell": (
        re.compile(r"\b(?:Get|Set|New|Invoke|Start|Stop|Add|Remove|Out|Write|Read|Test|Import|"
                   r"ConvertTo|ConvertFrom|Select|Where|ForEach)-[A-Z][A-Za-z]+"),
        re.compile(r"\$[A-Za-z_][\w:]*\s*="),
        re.compile(r"(?i)\[(?:System\.)?(?:Convert|Text\.Encoding|Net\.WebClient|IO\.File|Reflection\.Assembly)\]"),
        re.compile(r"(?i)-ExecutionPolicy\b|\bparam\s*\("),
        re.compile(r"(?i)\$env:"),
        re.compile(r"(?i)\b(?:IEX|Invoke-Expression)\b"),
    ),
    "vbscript": (
        re.compile(r"(?im)^\s*Dim\s+\w"),
        re.compile(r"(?im)^\s*Set\s+\w+\s*=\s*"),
        re.compile(r"(?i)\bCreateObject\s*\("),
        re.compile(r"(?im)^\s*End\s+(?:Sub|Function|If)\b"),
        re.compile(r"(?i)\bOn\s+Error\s+Resume\s+Next\b"),
        re.compile(r"(?i)\bWScript\.(?:Echo|Sleep|Quit|Arguments|CreateObject)\b"),
    ),
    "jscript": (
        re.compile(r"\bnew\s+ActiveXObject\s*\("),
        re.compile(r"\bvar\s+\w+\s*="),
        re.compile(r"\bfunction\s*\w*\s*\("),
        re.compile(r"\bWScript\.(?:Echo|Sleep|Quit|Arguments|CreateObject)\b"),
        re.compile(r"\btry\s*\{"),
    ),
    "batch": (
        re.compile(r"(?im)^\s*@?echo\s+off\b"),
        re.compile(r"(?im)^\s*(?:set|setlocal|goto|call)\b"),
        re.compile(r"%~?[A-Za-z0-9_]+%|%~d?p?0"),
        re.compile(r"(?im)^\s*(?:rem\b|::)"),
        re.compile(r"(?im)^\s*if\s+(?:not\s+)?(?:exist|defined|errorlevel)\b"),
    ),
    "shell": (
        re.compile(r"\A#!\s*/(?:usr/)?bin/(?:env\s+)?(?:ba|z|da|k)?sh\b"),
        re.compile(r"(?m)^\s*(?:export\s+\w+=|if\s+\[|fi\b|then\b|esac\b)"),
        re.compile(r"\bchmod\s+\+?[0-7x]+\b"),
        re.compile(r"\$\{?\w+\}?"),
    ),
}

_CRADLE_VERBS = r"(?:DownloadString|DownloadData|Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b)"
_INVOKE = r"(?:\bIEX\b|Invoke-Expression)"


def _p(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


#: Dropper shapes: the only thing here at the gate. Each is a name and a
#: chain of parts, every part a pattern with no gap inside it, and each gap
#: between parts a bound in characters and whether it may cross a line.
#:
#: A chain rather than one regex with `[^\n]{0,200}?` between the parts:
#: that form retries the whole gap at every occurrence of the first part,
#: and 4 MiB of `IEX ` took 33 s. Each part is found once, in one linear
#: pass, and parts are paired by position, so the cost is linear in the
#: file whatever the file repeats.
SHAPES: tuple[tuple[str, tuple[tuple[re.Pattern, int, bool], ...]], ...] = (
    ("PowerShell download cradle", ((_p(_INVOKE), 0, False), (_p(_CRADLE_VERBS), 200, False))),
    ("PowerShell download cradle", ((_p(_CRADLE_VERBS), 0, False), (_p(r"\|\s*" + _INVOKE), 200, False))),
    ("encoded PowerShell launch", (
        (_p(r"\b(?:powershell|pwsh)(?:\.exe)?\b"), 0, False),
        (_p(r"\s[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+[\"']?"
            r"[A-Za-z0-9+/]{24,}"), 160, False))),
    # One line, as the one-liners are written. Across lines it matched a
    # Microsoft test that decodes EICAR and, two lines later, invokes an
    # `echo` of it.
    ("base64 decoded and invoked", ((_p(r"FromBase64String"), 0, False), (_p(_INVOKE), 300, False))),
    ("base64 decoded and invoked", ((_p(_INVOKE), 0, False), (_p(r"FromBase64String"), 300, False))),
    ("certutil fetching a URL", (
        (_p(r"\bcertutil(?:\.exe)?\b"), 0, False), (_p(r"-urlcache\b"), 120, False),
        (_p(r"https?://"), 200, False))),
    ("bitsadmin fetching a URL", (
        (_p(r"\bbitsadmin(?:\.exe)?\b"), 0, False), (_p(r"/transfer\b"), 60, False),
        (_p(r"https?://"), 240, False))),
    ("mshta running remote script", (
        (_p(r"\bmshta(?:\.exe)?[\"']?\s+[\"']?(?:https?://|vbscript:|javascript:)"), 0, False),)),
    ("regsvr32 loading a remote scriptlet", (
        (_p(r"\bregsvr32(?:\.exe)?\b"), 0, False), (_p(r"/i:\s*[\"']?https?://"), 120, False))),
    ("rundll32 running script", (
        (_p(r"\brundll32(?:\.exe)?\b"), 0, False), (_p(r"javascript:"), 120, False))),
    ("msiexec installing from a URL", (
        (_p(r"\bmsiexec(?:\.exe)?\b"), 0, False), (_p(r"/(?:i|package)\s+[\"']?https?://"), 60, False))),
    ("download piped to a shell", (
        (_p(r"\b(?:curl|wget)\b"), 0, False), (_p(r"\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"), 240, False))),
    ("download piped to a shell", (
        (_p(r"\bbase64\s+(?:-d|--decode)\b"), 0, False), (_p(r"\|\s*(?:ba|z|da)?sh\b"), 80, False))),
    # Process substitution runs a download the way a pipe does.
    ("download piped to a shell", (
        (_p(r"\b(?:ba|z|da)?sh\s+<\(\s*(?:curl|wget)\b"), 0, False),)),
)

#: What each shape needs present, as groups of lowercase literals: every
#: group must have one of its literals in the case-folded text, or the
#: shape is not looked for. Each part of a chain is a pattern with a fixed
#: word in it, so a file without the word cannot match it, and most files
#: have none of them: ordinary text was 1.2 s a MiB before these and is a
#: tenth of that after. Case-folded rather than lowered because the patterns
#: ignore case the way `re` does, which matches `\u017f` to `s`; a
#: test checks every shape gives the same answer with and without these.
_SHAPE_HINTS: tuple[tuple[tuple[str, ...], ...], ...] = (
    (("iex", "invoke-expression"),
     ("downloadstring", "downloaddata", "invoke-webrequest", "iwr", "invoke-restmethod", "irm")),
    (("iex", "invoke-expression"),
     ("downloadstring", "downloaddata", "invoke-webrequest", "iwr", "invoke-restmethod", "irm")),
    (("powershell", "pwsh"),),
    (("frombase64string",), ("iex", "invoke-expression")),
    (("frombase64string",), ("iex", "invoke-expression")),
    (("certutil",), ("-urlcache",), ("http",)),
    (("bitsadmin",), ("/transfer",), ("http",)),
    (("mshta",),),
    (("regsvr32",), ("/i:",)),
    (("rundll32",), ("javascript:",)),
    (("msiexec",), ("http",)),
    (("curl", "wget"), ("sh",)),
    (("base64",), ("sh",)),
    (("<(",), ("curl", "wget")),
)


def _present(folded: str, groups) -> bool:
    return all(any(word in folded for word in group) for group in groups)


#: The write-and-run shape needs all three parts somewhere in the script,
#: which one pattern cannot say.
_WSH_FETCH = re.compile(r"(?i)\b(?:MSXML2\.(?:Server)?XMLHTTP|Microsoft\.XMLHTTP|WinHttp\.WinHttpRequest|URLDownloadToFile)")
_WSH_WRITE = re.compile(r"(?i)\bADODB\.Stream\b|\.SaveToFile\b|\.CreateTextFile\b")
_WSH_RUN = re.compile(r"(?i)\.(?:Run|Exec|ShellExecute)\s*\(?")
_WSH_HINTS = (("xmlhttp", "winhttp.winhttprequest", "urldownloadtofile"),
              ("adodb.stream", ".savetofile", ".createtextfile"),
              (".run", ".exec", ".shellexecute"))
#: `re` matches these two to `i` when ignoring case, and case folding does
#: not turn either into a bare `i`, so `\u0131ex` would match the pattern and
#: miss its hint. Every other character `re` matches to an ASCII letter
#: case-folds to it; a test walks all of Unicode to keep that true.
_FOLD = {0x130: "i", 0x131: "i"}
#: Off only in the test that checks the hints change no answer.
_USE_HINTS = True


def _chain(text: str, newlines: list[int], parts) -> bool:
    """Whether the parts occur in order, each within its gap of the last.

    Every part is matched once over the whole text; then for each start of
    the first part, the next part is found by binary search among the next
    part's starts. A gap that may not cross a line is checked against the
    newline positions, also by binary search.
    """
    found = [[(m.start(), m.end()) for m in pattern.finditer(text)] for pattern, _, _ in parts]
    if any(not spans for spans in found):
        return False
    starts = [[span[0] for span in spans] for spans in found]
    frontier = found[0]
    for index in range(1, len(parts)):
        _, gap, crosses = parts[index]
        reached = []
        for _, end in frontier:
            at = bisect_left(starts[index], end)
            if at == len(starts[index]):
                continue
            start, stop = found[index][at]
            if start - end > gap:
                continue
            if not crosses:
                line_break = bisect_left(newlines, end)
                if line_break < len(newlines) and newlines[line_break] < start:
                    continue
            reached.append((start, stop))
        if not reached:
            return False
        frontier = sorted(set(reached))
    return True


#: Calls that start something. Reported as capability, at `low`. Each with
#: the literals it cannot match without, as the shapes have.
EXECUTION = (
    ("powershell", re.compile(r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b"), ("powershell", "pwsh")),
    ("cmd /c", re.compile(r"(?i)\bcmd(?:\.exe)?[\"']?\s+/[ck]\b"), ("cmd",)),
    ("WScript.Shell", re.compile(r"(?i)WScript\.Shell"), ("wscript.shell",)),
    ("Shell.Application", re.compile(r"(?i)Shell\.Application"), ("shell.application",)),
    ("ShellExecute", re.compile(r"(?i)\bShellExecute"), ("shellexecute",)),
    ("Start-Process", re.compile(r"(?i)\bStart-Process\b|\bsaps\b"), ("start-process", "saps")),
    ("Invoke-Expression", re.compile(rf"(?i){_INVOKE}"), ("iex", "invoke-expression")),
    ("mshta", re.compile(r"(?i)\bmshta(?:\.exe)?\b"), ("mshta",)),
    ("rundll32", re.compile(r"(?i)\brundll32(?:\.exe)?\b"), ("rundll32",)),
    ("regsvr32", re.compile(r"(?i)\bregsvr32(?:\.exe)?\b"), ("regsvr32",)),
    ("wscript or cscript", re.compile(r"(?i)\b[wc]script(?:\.exe)?\s"), ("script",)),
    ("Win32_Process", re.compile(r"(?i)Win32_Process"), ("win32_process",)),
    ("schtasks", re.compile(r"(?i)\bschtasks(?:\.exe)?\b"), ("schtasks",)),
)

#: Calls that fetch from a network. Reported as capability, at `info`.
DOWNLOAD = (
    ("Net.WebClient", re.compile(r"(?i)Net\.WebClient"), ("net.webclient",)),
    ("DownloadString or DownloadFile", re.compile(r"(?i)\.Download(?:String|File|Data)\b"),
     (".download",)),
    ("Invoke-WebRequest", re.compile(r"(?i)\bInvoke-WebRequest\b|\biwr\b"),
     ("invoke-webrequest", "iwr")),
    ("Invoke-RestMethod", re.compile(r"(?i)\bInvoke-RestMethod\b|\birm\b"),
     ("invoke-restmethod", "irm")),
    ("Start-BitsTransfer", re.compile(r"(?i)\bStart-BitsTransfer\b"), ("start-bitstransfer",)),
    ("XMLHTTP", re.compile(r"(?i)XMLHTTP"), ("xmlhttp",)),
    ("WinHttpRequest", re.compile(r"(?i)WinHttpRequest"), ("winhttprequest",)),
    ("URLDownloadToFile", re.compile(r"(?i)URLDownloadToFile"), ("urldownloadtofile",)),
    ("curl or wget", re.compile(r"(?i)\b(?:curl|wget)(?:\.exe)?\s"), ("curl", "wget")),
)

#: Asking for no window, the way a script hides from the person who ran it:
#: PowerShell's `-WindowStyle Hidden` in any of the prefixes it accepts, and
#: .NET's `CreateNoWindow`. WSH's `.Run(command, 0)` is a chain, below.
HIDDEN = re.compile(
    r"(?i)\s-w(?:i(?:n(?:d(?:o(?:w(?:s(?:t(?:y(?:le?)?)?)?)?)?)?)?)?)?\s+h(?:i(?:d(?:d(?:en?)?)?)?)?\b"
    r"|CreateNoWindow\s*=\s*\$?true")
_HIDDEN_RUN = ((_p(r"\.Run\b"), 0, False), (_p(r",\s*0\b"), 400, False))


def decode(raw: bytes) -> str | None:
    """The bytes as text, or `None` if they do not read as text.

    PowerShell scripts are often UTF-16 with a byte order mark, and a script
    with no mark that is half NUL bytes is UTF-16 too. Anything else is read
    as UTF-8 with replacement, which leaves every ASCII keyword intact.
    """
    if raw[:2] == b"\xff\xfe":
        text = raw[2:].decode("utf-16-le", "replace")
    elif raw[:2] == b"\xfe\xff":
        text = raw[2:].decode("utf-16-be", "replace")
    elif raw[:3] == b"\xef\xbb\xbf":
        text = raw[3:].decode("utf-8", "replace")
    elif len(raw) >= 16 and raw[1:_SAMPLE:2].count(0) > 0.9 * len(raw[1:_SAMPLE:2]):
        text = raw.decode("utf-16-le", "replace")
    else:
        text = raw.decode("utf-8", "replace")
    sample = text[:_SAMPLE]
    if not sample:
        return None
    # Text is overwhelmingly printable, with line breaks and tabs. A binary
    # that happened to have no magic number is not.
    bad = sum(1 for ch in sample if ch < " " and ch not in "\t\r\n\f" or ch == "\ufffd")
    return text if bad <= 0.02 * len(sample) else None


_LANGUAGE_SAMPLE = 262144


def language(text: str) -> str | None:
    """The language with the most distinct features, if it has two.

    From the first 256 KiB: a script says what it is near its top, and
    thirty patterns over every byte of a long file buy nothing.
    """
    text = text[:_LANGUAGE_SAMPLE]
    best, best_score = None, 1
    for name, features in LANGUAGES.items():
        score = sum(1 for feature in features if feature.search(text))
        if score > best_score:
            best, best_score = name, score
    return best


#: Whole-line comments, per language. Only whole lines: a comment marker in
#: the middle of a line may be inside a string, and stripping from it would
#: let `$a = "#"; IEX (iwr ...)` hide everything after the quote. A line
#: that starts as a comment cannot run, so ignoring it is exact. Measured on
#: 923 real scripts, two of four dropper matches were the official install
#: one-liner quoted in help text.
_LINE_COMMENTS = {
    "powershell": re.compile(r"(?m)^[ \t]*#.*$"),
    "shell": re.compile(r"(?m)^[ \t]*#.*$"),
    "batch": re.compile(r"(?im)^[ \t]*@?(?:rem\b|::).*$"),
    "vbscript": re.compile(r"(?im)^[ \t]*(?:'|rem\b).*$"),
    "jscript": re.compile(r"(?m)^[ \t]*//.*$"),
}
#: A PowerShell block comment that opens at the start of a line, which is
#: where help text lives, up to the first close.
_PS_BLOCK = re.compile(r"(?ms)^[ \t]*<#.*?#>")


def uncommented(text: str, language_name: str | None) -> str:
    """The text with the comments that cannot run blanked out.

    Blanked rather than removed, so positions and line numbers still hold.
    """
    def blank(match: re.Match) -> str:
        return re.sub(r"[^\n]", " ", match.group())
    if language_name == "powershell":
        text = _PS_BLOCK.sub(blank, text)
    pattern = _LINE_COMMENTS.get(language_name or "")
    return pattern.sub(blank, text) if pattern else text


def scan(text: str) -> dict[str, Any]:
    """Names from this module's lists, never the text they were found in."""
    language_name = language(text)
    text = uncommented(text, language_name)
    newlines = [m.start() for m in re.finditer("\n", text)]
    folded = text.translate(_FOLD).casefold() if _USE_HINTS else None

    def worth(groups) -> bool:
        return folded is None or _present(folded, groups)

    shapes: list[str] = []
    for (name, parts), hints in zip(SHAPES, _SHAPE_HINTS):
        if name not in shapes and worth(hints) and _chain(text, newlines, parts):
            shapes.append(name)
    if (worth(_WSH_HINTS) and _WSH_FETCH.search(text) and _WSH_WRITE.search(text)
            and _WSH_RUN.search(text)):
        shapes.append("WSH download written to disk and run")
    return {
        "language": language_name,
        "shapes": shapes,
        "execution": [name for name, pattern, hints in EXECUTION
                      if worth((hints,)) and pattern.search(text)],
        "download": [name for name, pattern, hints in DOWNLOAD
                     if worth((hints,)) and pattern.search(text)],
        "hidden": ((worth((("-w", "createnowindow"),)) and bool(HIDDEN.search(text)))
                   or (worth(((".run",),)) and _chain(text, newlines, _HIDDEN_RUN))),
    }


class ScriptExtractor(StreamExtractor):
    """Text that nothing else identified, read as a script.

    A stream extractor, so it takes its bytes from the one pass every other
    stream extractor shares rather than opening the file again: the first
    version opened it a second time, which the v0.1.2 invariant (one open,
    one read) caught. It keeps at most `script_max_bytes`, and decides on
    the first 4 KiB whether the file is text at all, so a binary costs one
    small check and no buffer: the first version decoded a megabyte of
    random bytes into a string before deciding, and the peak memory test
    caught that.
    """

    name = "script"

    def applies_to(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> bool:
        return ctx.get("family") in ("unknown", "script")

    def begin(self, path: Path, ctx: dict[str, Any], config: dict[str, Any]) -> None:
        self._cap = config_int(config, "script_max_bytes", 1048576)
        self._buffer = bytearray()
        self._seen = 0
        self._text: bool | None = None

    def feed(self, chunk: bytes) -> None:
        self._seen += len(chunk)
        if self._text is False:
            return
        room = self._cap + 1 - len(self._buffer)
        if room > 0:
            self._buffer += chunk[:room]
        if self._text is None and len(self._buffer) >= _DECIDE:
            self._decide()

    def _decide(self) -> None:
        self._text = decode(bytes(self._buffer[:_DECIDE])) is not None
        if not self._text:
            self._buffer = bytearray()

    def finish(self, path: Path, ctx: dict[str, Any],
               config: dict[str, Any]) -> dict[str, Any]:
        if self._text is None:
            self._decide()
        text = decode(bytes(self._buffer[:self._cap])) if self._text else None
        self._buffer = bytearray()
        if text is None:
            return {"text": False}
        data: dict[str, Any] = {"text": True, **scan(text),
                                "bytes_read": min(self._seen, self._cap)}
        if self._seen > self._cap:
            data["parse_errors"] = [
                f"script: read the first {self._cap} bytes of a longer file; "
                "anything after that was not examined"]
        return data

    def findings(self, data: dict[str, Any], config: dict[str, Any]) -> list[dict[str, Any]]:
        if not data.get("text"):
            return []
        out = []
        language_name = data.get("language")
        reads_as = f"a {language_name} script" if language_name else "text"
        shapes = data.get("shapes") or []
        if shapes:
            # At the gate. Each shape is a dropper's, specific enough that an
            # ordinary script does not take it by accident: an installer that
            # downloads and starts a process does it with neither an
            # expression invoked on the download nor a Windows binary pressed
            # into fetching a URL.
            out.append(mk_finding(
                self.name, "script_dropper",
                f"{reads_as} with the shape of a dropper: {', '.join(shapes)}", "medium",
                evidence=[{"name": "shapes", "value": shapes},
                          {"name": "language", "value": language_name}]))
        execution = data.get("execution") or []
        if execution:
            out.append(mk_finding(
                self.name, "script_execution",
                f"{reads_as} that can start a process: {', '.join(execution)}", "low",
                evidence=[{"name": "execution", "value": execution}]))
        download = data.get("download") or []
        if download:
            out.append(mk_finding(
                self.name, "script_download",
                f"{reads_as} that can fetch from a network: {', '.join(download)}", "info",
                evidence=[{"name": "download", "value": download}]))
        if data.get("hidden"):
            out.append(mk_finding(
                self.name, "script_hidden_window",
                f"{reads_as} that asks for no window, so whoever ran it sees nothing", "low"))
        return out
