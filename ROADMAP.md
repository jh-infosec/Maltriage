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
- [ ] ELF parsing

Authenticode said "validity" here until v0.2. Presence and the embedded
signer name are free from the directory; validation is not, because it needs
a certificate chain, a trust store and a clock. The report says
`"validated": false` for the same reason this line now says what it does.

---

## Version 0.3

- [ ] YARA integration
- [ ] Bundled rule set
- [ ] Rule authoring notes
- [ ] Match context in findings

---

## Version 0.4

Reputation enrichment lives here rather than owning a version. It is an API
call and a cache, and it makes the tool depend on a network and a key, so it
stays optional and off by default.

- [ ] ASCII and Unicode string extraction
- [ ] URL and IP extraction
- [ ] Registry path and mutex extraction
- [ ] Suspicious API name detection
- [ ] ATT&CK technique mapping on findings
- [ ] Optional reputation enrichment by hash, cached and rate limited
- [ ] Offline mode

---

## Version 0.5

Archive recursion. The safety work is the point: a triage tool that unpacks
untrusted containers has an attack surface of its own, and decompression
bombs, path traversal in entry names and symlink entries all have to be
handled before the feature is safe to run.

- [ ] Recurse into ZIP, GZIP, TAR and RAR
- [ ] Depth limit and total expansion ratio cap
- [ ] Entry name and symlink handling
- [ ] Password-protected archive detection
- [ ] Nested reports linked to their parent

---

## Version 0.6

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
- [ ] Known-good hash filtering
- [ ] Report diff between two runs
- [ ] Throughput benchmarking

---

## Version 0.8

- [ ] Feature vector construction from the report schema
- [ ] Gradient boosting classifier
- [ ] Probability calibration
- [ ] False positive analysis against the corpus harness
- [ ] Per-sample feature attribution, so a score comes with its reasons

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

- [ ] HTML report rendering
- [ ] Batch corpus analysis
- [ ] Packaged distribution
- [ ] Continuous integration
