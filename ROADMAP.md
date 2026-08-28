# maltriage Roadmap

## Version 0.1

- [x] Extraction engine
- [x] Hashing
- [x] Format identification
- [x] Entropy analysis
- [x] Report schema
- [x] Command line interface
- [x] Synthetic samples
- [x] Test suite

---

## Version 0.1.1

- [x] Windowed entropy on small files
- [x] Size-aware entropy thresholds
- [x] Config validation with reported fallbacks
- [x] Consistent JSON array output
- [x] Distinct exit codes for findings and failures
- [x] Regression test per defect

---

## Version 0.1.2

- [x] Single open, single pass over the sample
- [x] Streaming entropy accumulator
- [x] Header and stream extractor phases
- [x] Error isolation at begin, feed and finish
- [x] Optional numpy accelerator for byte counting
- [x] Optional fuzzy hashing via ssdeep

This list said "incremental fuzzy hashing" until v0.2. It was never true:
ssdeep's API takes a path and hashes the file itself, so it read the sample a
second time rather than consuming the shared pass. It was the only false
claim in the repository, and v0.2 both corrects it here and moves ssdeep into
the phase where reading the file for yourself is the declared contract.

---

## Version 0.2

Executable structure. The first extractor to gate on the header phase, and
the milestone that produces the fields the classifier will eventually consume.

- [x] A third extractor kind for structure no forward pass can reach
- [x] Synthetic PE builder, verified against a real parser
- [x] PE parsing, behind an optional dependency whose absence is reported
- [x] Import table and imphash
- [x] Section characteristics and per-section entropy
- [x] Compile timestamp
- [x] Exports, TLS callbacks and the debug directory with its PDB path
- [x] Overlay detection, kept distinct from the certificate table
- [x] Authenticode presence and signer, never validity
- [x] Fuzzy hashing moved into the random-access phase
- [x] ELF parsing (shipped in v0.3.1)

ELF landed after v0.3 rather than with the rest of v0.2, and is ticked here
because it is v0.2's design rather than v0.3's. It takes no dependency: the
header, program header table and section header table are fixed-layout
records that `struct` reads, and there is no equivalent of pefile's
accumulated knowledge of malformed real-world files to buy. Pay a dependency
where the format is genuinely hostile, not where it is merely binary.

Authenticode said "validity" here until v0.2. Presence and the embedded
signer name are free from the directory; validation is not, because it needs
a certificate chain, a trust store and a clock. The report says
`"validated": false` for the same reason this line now says what it does.

---

## Version 0.3

Pattern matching, and the release where the extractor set stops being fixed
by the code: a rules directory is an extension point anybody can add to.

- [x] YARA integration
- [x] Bundled rule set
- [x] Rule authoring notes
- [x] Match context in findings, as offsets and never bytes
- [x] Per-rule-file compile isolation
- [x] Extractors built once per directory scan rather than once per file

Every match files under the single finding key `yara_match`, with the rule
name in the detail and the data rather than promoted to a key. Rules are
user-extensible, and a key set that grows with somebody's rules directory is
not one a dashboard can count on — nor one the findings envelope at v0.4 can
describe as bounded. The rule name is the envelope's `discriminator`, which
makes this the first release with a real use for that field.

Match context carries the rule, its tags and meta, the string identifier, the
offset and the length. It never carries the matched bytes, and there is no
configuration switch to make it: the person most likely to turn one on is the
person debugging a rule that matches secrets. This is the v0.4 secret engine's
rule, arriving a release early because YARA is the first thing that can break
it.

---

## Version 0.4

Content, and the release where maltriage stops being a single tool. Three of
the items below are shared with claude-recon-agent and Shadowfax rather than
owned here, and one of them is the package layout that makes sharing possible
at all.

Reputation enrichment lives here rather than owning a version. It is an API
call and a cache, and it makes the tool depend on a network and a key, so it
stays optional and off by default.

- [x] ASCII and Unicode string extraction
- [x] URL and IP extraction
- [x] Registry path and mutex extraction
- [ ] Suspicious API name detection
- [x] Package layout, so a shared module has one home
- [ ] Secret engine: patterns, entropy and context (shared)
- [ ] ATT&CK technique mapping from the shared registry (shared)
- [ ] Findings envelope emit, provisional (shared)
- [ ] Optional reputation enrichment by hash, cached and rate limited
- [ ] Offline mode

**The package layout comes first, and it is not the packaged distribution at
v1.0.** Four components are now planned as shared — the secret engine, the
ATT&CK registry, the archive path-locking primitive at v0.5, and the HTML
renderer at v1.0 — and `architecture.md` records under "Flat module layout"
that modules import each other by bare name and the project is not suitable
for installation as a library. Sharing a component with three repositories
that cannot import it produces three copies that drift, which is the problem
the sharing was meant to solve. What is needed here is importability, not a
published artefact; distribution stays at v1.0.

**The secret engine.** Pattern matching plus entropy plus context. Known
patterns catch what a rule exists for; entropy catches what no rule exists
for, which is the case that matters, because a company's own API key format
has no public matcher and never will. maltriage runs it over extracted
strings, claude-recon-agent over JavaScript and configuration files, and
ShadowClip's hand-maintained `SECRET_FILTER` becomes a caller rather than a
fourth list.

It lives in `findings()`, never in `parse()`. Extracting strings is data;
deciding a string looks like a credential is a heuristic, and the
data-and-findings split already governs which side that falls on.

Severity, decided now rather than during implementation. Nothing reaches
`high`: `extension_mismatch` earns high because content under a lying
extension is near-unambiguous deception, and a credential in a file is not
deception. A confirmed match against a known format is `medium`, because a
human should look at that file on its own. A high-entropy string with no
matching rule is `low` — it is a candidate, and `GATE_SEVERITY` is medium, so
anything higher makes every minified bundle a CI failure.

**The engine never returns the secret.** Findings carry the offset, the
length, the entropy and the matched rule name, and not the string. A report
is stored, piped and shared, and putting a recovered credential in one turns
a detection into a leak.

**ATT&CK mapping leaves `mitre` absent unless the finding is
near-unambiguous.** maltriage does not claim a file is malicious; it ranks a
queue. A technique id is a claim about adversary behaviour, and attaching one
to a finding that is merely unusual inflates it. A writable executable
section is consistent with packing, and packing is the normal state of most
installers.

**The findings envelope emits here rather than at v1.0.** See
`findings-envelope.md`. Both that document and this roadmap want maltriage to
be the first emitter, so the shape is proven before claude-recon-agent and
Shadowfax commit to it — and v1.0 is the worst possible time to discover the
shape is wrong, because Shadowfax will have an ingest path by then. The emit
is a serialiser over a findings model that already exists; its whole value is
being early. v0.4 rather than v0.3 because the string, secret and ATT&CK
findings arriving here are what exercise `evidence`, `validated` and `mitre`;
v0.2's thirteen keys would prove the shape thinly. Move it to v0.3 if the
recon agent needs it sooner.

Three things the emit has to settle, recorded here so they are not decided by
accident during implementation:

- `report.data` does not cross the envelope, and `SCHEMA_VERSION` moves
  independently of `envelope_version`.
- `validated` needs a sharper test than "did the emitter compute it", because
  nearly every PE finding reads a header field and a field that is false
  twelve times out of thirteen carries no information. The test that works is
  **whether the emitter did work that could have falsified the claim**.
  Entropy could have come back low, so `true`. A timestamp compared against a
  floor, `true`. Certificate common names transcribed out of a blob, `false`.
  A PDB path transcribed, `false`. And `extension_mismatch` is `true` when
  `report.data["pe"]` exists because pefile actually parsed the file, `false`
  when only two magic bytes matched: header-only identification is a claim
  the file makes about itself, and a successful parse is not.
- The envelope carries `subject.id` as a content hash and has no path field,
  while `Report.path` is the resolved absolute path. The safety checklist
  records that as leaking directory layout and username, so the envelope is
  safer to share than maltriage's own JSON. Do not add a path to it.

---

## Version 0.5

Archive recursion. The safety work is the point: a triage tool that unpacks
untrusted containers has an attack surface of its own, and decompression
bombs, path traversal in entry names and symlink entries all have to be
handled before the feature is safe to run.

- [ ] Recurse into ZIP, GZIP, TAR and RAR
- [ ] Depth, entry-count and total expansion ratio caps
- [ ] Path locking that refuses any member escaping the extraction root (shared)
- [ ] Password-protected archive detection
- [ ] Nested reports linked to their parent
- [ ] Known-good hash filtering, which reports what it suppressed
- [ ] Bounded parse time

**Path locking is the third use of a primitive that already exists twice**, in
`loganalysis._safe_path` and in the wordlist roots landing in
claude-recon-agent v0.3.1. Third use is where it should be shared rather than
written again, which is why the package layout is a v0.4 item.

**Known-good hash filtering moves here from v0.7.** It was placed with the
corpus harness, but it needs a hash list rather than a labelled corpus, and
recursion is what makes it necessary: unpacking an installer of four hundred
files and reporting on all of them is unusable output. v0.7 keeps measuring
what the filter costs in false negatives, which is the corpus harness's job
and not the filter's.

A suppressed finding must say so in the report. Silently dropping one
produces a report that looks clean for a reason the reader cannot see, which
is the failure the config accessors already guard against.

**Bounded parse time is closed here, not recorded again.** `architecture.md`
carries it as a known gap: isolation covers a parser that raises, not one
that hangs, and `max_parse_bytes` bounds size while nothing bounds time. A
nested archive is an unbounded-time construct by design — quines, deep
nesting, an entry that decompresses forever — so v0.5 is the version where
that gap stops being theoretical. It needs a mechanism the pipeline does not
have: a subprocess, a watchdog or an alarm.

---

## Version 0.6

Document containers, which follow archive recursion rather than joining it.
An OOXML file *is* a ZIP, so part extraction consumes v0.5's recursion and
its guards; merging the two would put a second large feature into the release
where the safety work lives. Both formats wrap structure no forward pass
reaches, so both are random-access extractors gating on the header phase,
which is the third kind doing what it was added for.

- [ ] OLE2 structured storage parsing
- [ ] OOXML part extraction
- [ ] VBA macro extraction and stream listing
- [ ] Auto-execute trigger detection
- [ ] DDE and external relationship detection

---

## Version 0.7

The measurement release. Everything after this depends on being able to state
precision and recall, so it comes before the classifier rather than after.

- [ ] Corpus harness with labelled directories
- [ ] Precision, recall and per-finding false positive rates
- [ ] False negatives introduced by known-good filtering
- [ ] Report diff between two runs
- [ ] Throughput benchmarking

---

## Version 0.8

- [ ] Feature vector construction from the report schema
- [ ] Gradient boosting classifier
- [ ] Probability calibration
- [ ] False positive analysis against the corpus harness
- [ ] Per-sample feature attribution, so a score comes with its reasons

The model explains findings and does not produce them. It reads
`report.findings` and writes prose about why a combination of observations
warrants attention. It never adds a finding, never changes a severity, and
never sees a byte of the sample. This is the rule Shadowfax states as
"detection is deterministic and policy-driven", and it holds here for the
same reason.

---

## Version 0.9

The adversarial release. Attack the classifier from v0.8, measure what the
attacks cost it, harden it, and measure the recovery.

- [ ] Feature-space evasion
- [ ] Appended bytes and padding attacks
- [ ] Section and import perturbation
- [ ] Adversarial retraining
- [ ] Before and after evaluation written up with the numbers

---

## Version 1.0

- [ ] HTML report rendering via the shared renderer
- [ ] Findings envelope 1.0, stable
- [ ] Batch corpus analysis
- [ ] Packaged distribution
- [ ] Continuous integration

The HTML renderer comes from claude-recon-agent's `report.py`, which already
produces self-contained HTML with severity badges and escapes all
subject-derived content. That escaping is the reason to share it rather than
write a fourth one: a sample's embedded strings are attacker-controlled text
and a report is a document somebody opens in a browser. Whatever it renders
must also drop the absolute paths that `Report.path` carries, for the reason
recorded at v0.4 — an HTML report is more likely to be shared than a JSON
one, not less.

The envelope is emitted from v0.4. What lands here is the commitment that its
shape has stopped moving, which is a different promise and can only be made
after two other tools have consumed it.
