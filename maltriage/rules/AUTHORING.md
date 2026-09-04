# Writing rules for maltriage

Rules in this directory are compiled at startup and run against every sample.
`yara_rule_paths` in the config adds further files or directories; it does not
replace this one.

## What belongs here

Structure, not signatures. A rule here describes the *shape* of a file: a
header where one does not belong, an executable encoded as text, a container
feature that exists to make something run.

Family signatures do not belong here. This project has no corpus to keep them
honest, ships no samples, and a signature list nobody can measure rots into
false confidence. That measurement arrives at v0.7; until then a rule has to
justify itself by reasoning rather than by a hit rate.

Nor does anything the extractors already report. Packed section names,
writable executable sections, overlays and import counts are the PE
extractor's findings, and a rule restating one produces two findings about a
single fact.

## The severity rule

Declare `severity` in `meta`, as one of `info`, `low`, `medium` or `high`. A
rule that declares nothing scores `yara_default_severity`, which is `info`,
because a rule that forgot to say how much it matters should not be able to
fail somebody's build by forgetting.

`GATE_SEVERITY` is medium. Every `medium` rule is a reason for this tool to
exit non-zero in somebody's CI, so a rule earns medium only if a human should
look at the file because of that rule alone.

Nothing here reaches `high`. In this project `high` means content that lies
about what it is — a PE wearing a `.pdf` extension — and a rule matching a
byte pattern is not in a position to establish deception.

## What a rule may not do

**A finding never carries the bytes that matched.** The extractor records the
rule, its tags and meta, the string identifier, the offset and the length,
and never reads `matched_data`. A report is stored, piped and shared, and a
rule that matched a credential pattern would otherwise put the credential in
it. There is no configuration switch for this, deliberately: the person most
likely to turn one on is the person debugging a rule that matches secrets.

Write rules whose *identity* is the finding. If an analyst needs the bytes,
they have the offset and the file.

## Meta fields this project reads

| Field | Effect |
|---|---|
| `severity` | The finding's severity, validated against the four levels |
| `description` | The finding's detail text |

Everything else in `meta` is carried into `report.data["yara"]` untouched.
`rationale` and `false_negative` are conventions in the bundled set rather
than fields the code knows about: a rule that cannot state why it fires and
what it misses is a rule nobody can tune later.

## A rule set is an input, and this tool treats it as one

Rules you did not write are code you are running. YARA is not a sandbox, and
three of its behaviours are bounded here rather than trusted:

**`include` is disabled** (`yara_allow_includes`). An include is resolved
relative to the rule file and confined to nothing, so `include "/etc/passwd"`
is opened and parsed, and YARA quotes offending tokens back in its syntax
errors. Turn it on only for a set you wrote.

**The `console` module is captured, not printed.** A rule can call
`console.hex(uint8(i))` in a loop, and libyara writes to the process's own
stdout when nothing catches it — which put sample bytes on an analyst's
terminal, under `--quiet`, without a byte of it appearing in the report. The
output is routed to the debug log instead.

**Sample size is capped** (`yara_max_scan_bytes`, 64 MiB). This is the one
bound the extractor genuinely controls, and it exists because two costs are
not bounded by anything else:

- Fast matching (`yara_fast_matching`) records the first occurrence of each
  string rather than every one, which stops a short string against a large
  sample from producing libyara's cap of a million match objects. **libyara
  ignores fast mode for any string whose condition reads that string's count,
  offset or length** — `#a`, `@a`, `!a`, `$a in (...)` — so a rule as ordinary
  as `condition: #a > 5` opts itself back into full enumeration.
- A rule using `console` can allocate until the scan deadline fires.

So: **prefer strings of six bytes or more, and avoid `#a`, `@a` and `!a` on
short strings.** A four-byte string is a match every 4 GB of random data, and
this tool is pointed at packed and encrypted files by definition.

## Practical notes

**One file per theme.** Each file compiles separately and its stem becomes the
match's namespace, so a syntax error in a rule you are halfway through writing
disables that file and nothing else. Compile failures are reported in
`report.data["yara"]["parse_errors"]` and printed by the CLI under
`incomplete:`.

**Anchor on structure where you can.** `uint16(0) != 0x5A4D` costs nothing and
removes a whole class of false positive that a string alone invites.

**Assume random data.** A two-byte string matches roughly once every 64 KB of
random content, and this tool is pointed at packed and encrypted files by
definition. `embedded_pe_header` requires the DOS stub for exactly this
reason, and says so in its `false_negative` field.

**Rules run under a timeout** (`yara_timeout_seconds`, 10 by default). A rule
set that does not finish is reported as a failure rather than as no matches,
because those are different facts. Unbounded regular expressions are the usual
cause.

**Test against a synthetic fixture.** Every fixture in this project is built
in-process and no malicious sample is committed. If a rule cannot be
demonstrated against something `sample_data.py` can build, that is a reason to
question the rule.


## Declaring an ATT&CK technique

A rule may name techniques in its `meta`, comma separated:

```
meta:
    severity = "medium"
    mitre = "T1204.002, T1059.005"
```

They reach the finding and the findings envelope. An id this build does not
recognise is **not** attached and is reported in `parse_errors` against the
rule name, so a typo tells you rather than silently producing a rule that
looks mapped and is not. `maltriage/attack.py` holds the ids this build knows.

**The bar is near-unambiguous, and it is higher than it sounds.** A technique
id is a claim about adversary behaviour, and it is the field a consumer is
most likely to aggregate without reading the finding underneath it. A
dashboard reporting four hundred hits on a technique that turns out to mean
four hundred installers is worse than one with no ATT&CK column at all.

**None of the bundled rules declares a technique**, and that is deliberate
rather than an oversight. Every rule here describes the *shape* of a file, and
ATT&CK describes *behaviour*, so the mapping does not survive contact with the
benign cases:

- `embedded_pe_header` fires on any ZIP, CAB or MSI carrying an executable,
  which is what those formats are for.
- `base64_encoded_pe_header` fires on a MIME email attachment, because that is
  what MIME does to attachments.
- `pdf_with_automatic_action` and `ole_document_with_vba_project` fire on
  ordinary forms and ordinary macros, which is why both are already `low`.

A rule you write may well be narrower than any of these -- a rule matching one
family's configuration block is a much more specific statement than "there is
a PE header in here" -- and narrow is exactly where a technique id is earned.
