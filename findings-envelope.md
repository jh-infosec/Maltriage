# Findings Envelope 0.1

A wire format for one tool's findings about one subject, meant to be read by a
tool that did not produce them.

This document is a **draft written from the constraints recorded in
`ROADMAP.md`**, not a recovered original. The Findings Envelope 1.0 notes that
this project's roadmap has referred to since v0.4 were pasted into a
conversation and never written to a file, so the reference pointed at nothing.
What follows keeps every constraint the roadmap records, settles the questions
it left open, and adds one field it did not mention. maltriage is the first
emitter, so this shape is a proposal that claude-recon-agent and Shadowfax
should argue with rather than a contract they are bound by.

`envelope_version` is `0.1` and moves independently of maltriage's
`SCHEMA_VERSION`. Two different things change for two different reasons: the
schema version tracks what a maltriage report looks like, the envelope version
tracks what three tools have agreed to say to each other.


## Why it exists

Three tools produce findings about things — maltriage about files,
claude-recon-agent about hosts and web applications, Shadowfax about actors and
sessions. Each has its own report format and should keep it. What they need in
common is a way to hand a finding to something that did not produce it, so that
Shadowfax can ingest a maltriage result without knowing what a PE section is.

The envelope is that handoff. It is deliberately smaller than any of the three
native formats, and converting to it is lossy on purpose.


## Shape

```json
{
  "envelope_version": "0.1",
  "emitter": {"name": "maltriage", "version": "0.4.0"},
  "subject": {
    "id": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "kind": "file",
    "size_bytes": 40960,
    "media_type": "pe"
  },
  "observed_at": "2026-09-04T11:04:12+00:00",
  "severity": "medium",
  "findings": [
    {
      "key": "section_entropy_high",
      "source": "pe",
      "severity": "medium",
      "validated": true,
      "discriminator": ".text",
      "summary": "section .text has entropy 7.98, 0.99 of what random data of that length reaches",
      "evidence": [
        {"name": "section", "value": ".text"},
        {"name": "entropy", "value": 7.98},
        {"name": "expected_random_entropy", "value": 8.0},
        {"name": "scored_bytes", "value": 16384}
      ]
    }
  ],
  "incomplete": [
    {"source": "yara", "reason": "yara-python is not installed, so no rules ran"}
  ]
}
```


## Fields

### `envelope_version` (required, string)

The version of this document that the emitter wrote to. Consumers reject what
they do not recognise rather than guessing.

### `emitter` (required, object)

`name` and `version`. A finding is a claim, and a claim has an author. An
ingesting tool needs this to apply per-source trust, to reproduce a result and
to know which emitter to blame.

### `subject` (required, object)

What the findings are about.

- `id` (required) — a content address, `"<algorithm>:<hex>"`. The algorithm is
  in the string rather than in a sibling field so that the id is a single
  comparable token.
- `kind` (required) — `"file"`, and later `"host"`, `"endpoint"`, `"actor"`.
  The consumer needs this before it can decide what an id means.
- `size_bytes`, `media_type` (optional) — descriptive, never authoritative.
  maltriage's `media_type` is its own family string (`pe`, `elf`, `pdf`),
  which is a claim from magic bytes and not a MIME type.

**There is no path field, and adding one is a change to this document rather
than a convenience.** maltriage's own `Report.path` is a resolved absolute
path, and the safety checklist records that as carrying the directory layout
and the username of the machine that produced it. The envelope is the artefact
most likely to be handed to somebody else, so it is the one that must not carry
that. A filename alone is little better: `Q3-payroll-hendricks.xlsx` is a leak.

The cost is real and accepted: a directory scan produces envelopes that only a
hash distinguishes. Correlating an envelope back to a file on disk is the
caller's job, and the caller is the party entitled to know the path.

### `observed_at` (required, string)

ISO 8601, timezone-aware. When the emitter looked, not when the subject was
created or when the envelope was ingested.

### `severity` (required, string)

The highest severity among `findings`, repeated at the top so a consumer can
triage a stream without walking every finding. One of `info`, `low`, `medium`,
`high`.

An empty `findings` array with `severity: "info"` is a meaningful message —
"this was examined and nothing was found" — and is not the same as no envelope
at all.

### `findings` (required, array)

May be empty. Each entry:

- **`key`** (required) — a stable, bounded identifier for the kind of finding.
  Bounded is the load-bearing word: a consumer must be able to enumerate the
  keys an emitter can produce. This is why maltriage files every YARA match
  under `yara_match` and every capability under `api_capability` rather than
  promoting the rule or category into the key — a key set that grows when
  somebody adds a rules file is not one a dashboard can count on.

- **`source`** (required) — which component of the emitter produced it. In
  maltriage this is the extractor name. It lets a consumer suppress a noisy
  source without suppressing a whole tool.

- **`severity`** (required) — `info`, `low`, `medium` or `high`. **Severity is
  the emitter's opinion and the consumer is entitled to override it.** It is
  calibrated against the emitter's own gate, not against a shared scale: what
  maltriage calls medium means "a human should look at this file", which is
  not what Shadowfax's medium means about an actor.

- **`validated`** (required, boolean) — see below.

- **`discriminator`** (optional, string) — which instance of the key. The YARA
  rule name, the capability category, the section name. Present when the key
  alone does not identify what was found, absent when it does. This is what
  makes a bounded key set survivable: the detail that would otherwise want its
  own key goes here, where a consumer can group by it without needing to know
  it in advance.

- **`summary`** (required, string) — one sentence a person can read. Prose, and
  the only prose in the finding.

- **`evidence`** (required, array) — the observations the finding rests on, as
  `{"name": ..., "value": ...}`. May be empty.

- **`mitre`** (optional, array of strings) — ATT&CK technique ids.

### `incomplete` (required, array)

What the emitter could not do, as `{"source", "reason"}`. May be empty.

**This field is the one addition to the constraints the roadmap recorded, and
it is not optional to the design.** maltriage's oldest rule is that a report
must never look clean while quietly omitting the analysis nobody ran: an
absent YARA engine, a parser that raised, a file above `max_parse_bytes`. An
envelope carrying only findings would convert "I could not look" into "I
looked and found nothing", which is the exact failure the tool spends its
`report.errors` channel preventing. A consumer that ignores `incomplete` is
free to; one that does not have it cannot tell the difference.


## `validated`

**`validated` is true when the emitter did work that could have falsified the
claim.**

The obvious reading — "did the emitter compute this rather than assume it" —
is useless, because nearly every finding reads a field, and a boolean that is
true twelve times in thirteen carries no information. The test above
discriminates, because it asks about the counterfactual: was there a version of
this file for which the same work would have produced no finding?

In practice it separates two kinds of finding cleanly:

**A string copied out of the subject is `false`.** Nothing was tested. The
emitter transcribed what the file said about itself, and a file can say
anything.

**The outcome of a comparison, computation or structural walk is `true`.** The
entropy could have come back low. The timestamp could have been after the
floor. The rule could have failed to match.

It is not a confidence score and not a quality rating. A `false` finding is
often the more interesting one — a PDB path naming a build machine is
`validated: false` and worth more to an analyst than most `true` findings. It
tells a consumer what kind of claim it is holding, so that a consumer choosing
to trust a subset can choose on something principled.

### maltriage's classification

`false` — the finding's substance is a string the subject supplied:

`signature_present` (signer names transcribed out of a certificate blob, and
nothing verifies a chain), `build_id_present`, `runpath_set`, `rpath_set`,
`urls_present`, `emails_present`, `mutexes_present`, `windows_paths_present`,
`unix_paths_present`, `registry_path_present`.

`true` — everything else, because something was compared, counted, walked or
computed. Three worth naming because they look like transcription and are not:

- `ipv4_present` passes every candidate through an octet-range check that
  rejects, so `999.1.1.1` never becomes a finding.
- `registry_persistence_path` quotes paths, but its claim is that they survive
  a reboot, which is a membership test against a marker list.
- `api_capability` matches names against a fixed vocabulary and counts them
  against a threshold. Two ways to have come back empty.

`extension_mismatch` is the one finding whose value depends on how it was
reached: `true` when `report.data["pe"]` exists, because pefile parsed the
file, and `false` when only the magic bytes matched. Header-only
identification is a claim the file makes about itself; a successful parse is
not.

### A name collision to be aware of

A maltriage report already contains a field called `validated`, on the
certificate, meaning "was this Authenticode signature verified against a
chain". It is always `false`, because nothing in this project verifies chains.

That field and this one mean entirely unrelated things and both appear in the
same pipeline. This document keeps the name because `validated` is the right
word for what it describes and the certificate field is inside
`report.data`, which does not cross the envelope — so the two never appear in
the same document. **A future emitter that does put certificate data into
`evidence` must not name that value `validated`.**


## `evidence`

Evidence is what was observed. It is not the reasoning, not the conclusion and
not a second copy of the summary.

```json
"evidence": [
  {"name": "entropy", "value": 7.98},
  {"name": "scored_bytes", "value": 16384}
]
```

The rule that decides what belongs: **an observation is something the subject
would have to change for the value to change.** "entropy 7.98" is an
observation. "consistent with packing" is an inference and belongs in
`summary`, if anywhere.

`{name, value}` pairs rather than a free-form object, because a consumer that
does not know the emitter can still render, group and filter them. Values are
JSON scalars.

### Evidence never carries the thing it found

An offset, a length, an entropy, a count, a name from the emitter's own
vocabulary. **Never the matched bytes, never the extracted string, never the
credential, never the secret.**

An envelope is stored, piped, shared and ingested, and putting a recovered
credential into one turns a detection into a leak. maltriage already holds this
rule in two places — YARA match context is offsets and never bytes, with no
configuration switch, and the secret engine at v0.4 is specified to return the
offset, the length and the rule name and not the string. The envelope inherits
it, and inherits the part that matters most: **there is no configuration option
to turn it off.** The person most likely to enable one is the person debugging
a rule that matches secrets.

The consequence is that some findings have thin evidence, and thin evidence is
correct. A URL finding's evidence is a count, not the URLs.

### `report.data` does not cross

The envelope carries findings, not extraction output. A consumer wanting the
section table should ask the emitter for its native report.

This does not forbid an evidence value that also appears in `report.data` —
naming an observation is what evidence is. It forbids the shortcut of attaching
the data wholesale and calling it evidence.

### An empty evidence array

Means the emitter has not been taught to supply evidence for that key yet.

It does not mean there was none, and a consumer must not treat it as a weaker
finding. In maltriage at v0.4 most findings emit `[]`, because evidence is
supplied at the site where a finding is constructed and only some sites have
been migrated. Filling the rest in is mechanical work, not a design question.


## `mitre`

Omitted unless the finding is near-unambiguous.

A technique id is a claim about adversary behaviour. Attaching one to a finding
that is merely unusual inflates it, and inflated attribution is worse than
none, because it is the field a consumer is most likely to aggregate without
reading the finding underneath it. A writable executable section is consistent
with packing; packing is the normal state of most installers; `T1055` on that
finding would be a lie told at scale.

**maltriage at v0.4 emits `mitre` on nothing.** The capability registry in
`apis.py` records a technique per category as reference data and does not emit
it. That is the correct state for a tool that ranks a queue and does not claim
a file is malicious.


## What a consumer may assume

- `envelope_version` is present and is the first thing to check.
- `subject.id` is stable for identical content and is the only correlation key.
- `key` comes from a set the emitter can enumerate on request.
- Absence of a finding means the emitter did not produce one, **unless
  `incomplete` names its source**, in which case it means nothing at all.
- `severity` is the emitter's opinion, calibrated to the emitter's own gate.
- No field carries a secret, a credential, a matched byte or a filesystem path.


## Open questions

Recorded rather than decided, because they need a second emitter to answer.

1. **Is `key` namespaced?** `no_imports` is unambiguous within maltriage.
   Across three tools it may not be. `maltriage/no_imports` is the obvious
   answer and is not adopted yet, because it should be settled when the second
   emitter arrives and can say whether it collides.

2. **Should findings be able to reference each other?** `no_imports` and
   `high_file_entropy` on the same subject are one observation, not two, and
   an ingesting tool re-derives that relationship today.

3. **Does the envelope need a signature?** It is a claim about a possibly
   hostile artefact, travelling between tools. Nothing signs it. That is
   acceptable while all three emitters are the same person's.

4. **Batch envelopes.** One subject per envelope today. A directory scan of
   four hundred files produces four hundred, which JSON Lines handles and a
   consumer may not want.
