"""
Shared MITRE ATT&CK technique registry.

Ids, the names that go with them, and the rule for when maltriage is allowed
to attach one to a finding.

This is a registry, not a mapping. It says what `T1036.008` is called and
which tactic it belongs to; it does not say which findings earn it. That
decision is made where the finding is constructed, by naming a constant from
here, because the same technique must mean the same thing in maltriage,
claude-recon-agent and Shadowfax -- and three repositories each writing their
own id strings is the drift that a shared component exists to prevent.
`mk_finding` validates against this table, so an id that is not in it cannot
reach a report at all.


## The rule, and why it disqualifies nearly everything

**`mitre` is absent unless the finding is near-unambiguous.**

maltriage does not claim a file is malicious. It ranks a queue. A technique id
is a claim about adversary behaviour, and it is the field a consumer is most
likely to aggregate without reading the finding underneath it -- so an
inflated one does more damage than an absent one. A dashboard counting
"T1055: Process Injection, 400 hits" that turns out to mean "400 installers
had a writable executable section" is worse than a dashboard with no ATT&CK
column.

Applied honestly to maltriage's thirty-eight finding keys, exactly one earns a
technique on its own. That is the correct outcome rather than a thin one, and
the ones refused are worth recording because each is a case somebody will
reflexively want to map:

- **`writable_executable_section`, `virtual_size_mismatch`, `no_imports`** are
  the shape of a packer, and packing is the normal state of most installers.
  `T1027.002` describes software packing accurately, which is exactly the
  problem: the technique is right and the inference is not.
- **`known_packer_section`** is stronger -- a section named `UPX0` is packing
  and not a guess -- and is still refused, for the same reason. UPX is a
  legitimate tool used legitimately far more often than not.
- **`registry_persistence_path`** looks like `T1547.001`, and an installer
  writing a Run key is an installer. It is held at `low` in the extractor for
  this reason, and a technique id would undo that restraint.
- **`implausible_timestamp`** is not `T1070.006`. Timestomping is about
  filesystem timestamps, and a zero PE compile timestamp is what a
  reproducible build produces on purpose.
- **`api_capability`** is refused despite `apis.py` carrying a technique per
  capability as reference data. A capability inferred from names present in a
  binary is not evidence the binary used it.

What qualifies is `extension_mismatch`, and it qualifies for the reason it is
this project's only `high`: content under a lying extension is near-unambiguous
deception. There is no benign reason for a PE to be called `invoice.pdf`.

The other source is a YARA rule that declares its own technique in `meta`.
That is deliberate -- a rule is a much narrower statement than a finding key,
so a rule author can be specific where this table cannot, and the mapping
becomes extensible in exactly the way the rules already are.
"""

from __future__ import annotations

from typing import Any, Iterable

#: Masquerading: Masquerade File Type. The one technique maltriage attaches on
#: its own account.
MASQUERADE_FILE_TYPE = "T1036.008"

#: Techniques this project knows. Name and tactic are carried so a consumer
#: never has to resolve an id against an external source to render it, and so
#: a typo in a rule's `meta` is caught here rather than published.
#:
#: Entries exist for techniques maltriage references anywhere, including the
#: ones `apis.py` records as reference data and does not emit. A registry that
#: only held what is currently emitted would have to grow every time somebody
#: wanted to write an id down.
TECHNIQUES: dict[str, dict[str, str]] = {
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "defense-evasion"},
    "T1027.002": {"name": "Software Packing", "tactic": "defense-evasion"},
    "T1027.007": {"name": "Dynamic API Resolution", "tactic": "defense-evasion"},
    "T1027.013": {"name": "Encrypted/Encoded File", "tactic": "defense-evasion"},
    "T1036.008": {"name": "Masquerade File Type", "tactic": "defense-evasion"},
    "T1055": {"name": "Process Injection", "tactic": "defense-evasion"},
    "T1056": {"name": "Input Capture", "tactic": "collection"},
    "T1057": {"name": "Process Discovery", "tactic": "discovery"},
    "T1059.005": {"name": "Visual Basic", "tactic": "execution"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "command-and-control"},
    "T1106": {"name": "Native API", "tactic": "execution"},
    "T1134": {"name": "Access Token Manipulation", "tactic": "privilege-escalation"},
    "T1204.002": {"name": "Malicious File", "tactic": "execution"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "persistence"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "credential-access"},
    "T1622": {"name": "Debugger Evasion", "tactic": "defense-evasion"},
}


def is_known(technique: Any) -> bool:
    return isinstance(technique, str) and technique in TECHNIQUES


def validate(techniques: Iterable[Any]) -> list[str]:
    """The recognised ids in `techniques`, in order, without duplicates.

    Unknown ids are dropped rather than raising, because one caller is a YARA
    rule's `meta` and a rule set is somebody else's input. The caller is
    expected to report what was dropped -- silently discarding it would be the
    failure this project guards against everywhere else -- and
    `unknown` below is what it reports.
    """
    out: list[str] = []
    for technique in techniques or ():
        if is_known(technique) and technique not in out:
            out.append(technique)
    return out


def unknown(techniques: Iterable[Any]) -> list[str]:
    """The ids in `techniques` this registry does not recognise.

    Returned as text so a caller can put them in `parse_errors`. A rule
    declaring `T1055.012` when the registry only has `T1055` is a rule whose
    author should be told, not a rule to quietly ignore.
    """
    return [str(t) for t in (techniques or ()) if not is_known(t)]


def describe(technique: str) -> dict[str, str]:
    """Id, name and tactic, for a renderer that should not have to look it up."""
    entry = TECHNIQUES[technique]
    return {"id": technique, "name": entry["name"], "tactic": entry["tactic"]}
