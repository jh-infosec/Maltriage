# Changelog

## Version 0.5.2 - what one real archive taught the signature table

Four defects, all read off a single run of v0.5.1 against an ordinary DOCX
from a Downloads folder. None of them would have shown up on a fixture,
because a fixture has three members and they are all files somebody chose.

**25 of the 29 members came back `unrecognised_format`.** The signature table
had no entry for PNG, JPEG, GIF, BMP, XML or RTF: the formats a document is
actually made of. The same gap explains 53.1% on a System32 sample, which had
been read as a corpus full of mysteries rather than as a table too thin for
the platform. `<?xml` is a magic number in every way that matters here.

**The PNGs scored `high_file_entropy`**, which is the argument v0.5.1 made
about ZIPs arriving one release late. A PNG is deflate output, so the figure
measures the codec and the finding says only that the file was compressed,
which its own magic number already said. The rule now keys on a
`compressed_families` list rather than on two literals, and the list is in
config with the argument written beside it.

TAR stays off that list, because a TAR is not compressed. So does a packed
PE, which is the case the finding exists for. And the *windowed* findings are
untouched: a hot region inside an otherwise quiet file still means something,
and an appended payload in a PNG is exactly that shape.

**`(incomplete)` fired on all 29 members.** One missing optional parser,
reported once in the container's errors block and then again on every line
below it. A marker that fires on everything marks nothing. A member is now
incomplete *relative to the run*: the marker means "this one came back short
for a reason the others did not".

**And the suite went from 37 seconds to 216 on Windows.** The same archive
cases cost 0.86 seconds here. Members are unpacked into the system temporary
directory and an endpoint scanner inspects every executable-shaped file
written there, which is the scanner working rather than failing - the same
conclusion v0.4.4 reached about the pytest fixtures it quarantined.

`archive_staging_dir` moves the unpacking somewhere the machine's policy
already understands. It is a choice about where to write, not an antivirus
exclusion, and this project's position on those is unchanged. Empty means the
system temporary directory, which stays the default.

### Also

- Two mutation survivors, both tests rather than code, which is now the
  pattern rather than the exception. One was a `-k` filter that did not select
  the test meant to catch it. The other could not tell a staging directory
  that was used and cleaned up from one that was never used at all, since both
  end up empty; it watches the call now instead of the directory afterwards.
- `config_str`, with the same strictness as the rest: a path written as a
  number falls back rather than being coerced, because a staging directory the
  caller did not mean is worse than the default one.
- **473 passed**, or 362 passed and 111 skipped with neither pefile nor
  yara-python.

### Still standing from that output

`word/document.xml` scored `ipv4_present`, and in a Word document that is
almost certainly a version string: `14.0.0.0` is a valid dotted quad. Left
alone deliberately, because the fix is a measurement rather than a guess at a
pattern, and this release was already four fixes long.

---

## Version 0.5.1 - the report says what it found

v0.5.0 recursed into a real archive on the first try: a DOCX inside a ZIP,
twenty-eight OOXML parts, depth two, exactly as designed. Then it printed the
container's own findings and stopped. Thirty files analysed and none of them
mentioned.

That is a report thinner than the work behind it, which is the failure this
project guards against everywhere else, and it took running the tool on
something real to see it. A fixture has three members and reads fine with no
tree at all.

```
exam-report-template.zip  (84,265 bytes)
  type     ZIP archive (or OOXML/JAR/APK)
  entropy  7.997 overall, measuring the compression rather than the contents

  no findings

  inside (30 file(s), worst medium):
     ! setup/payload.exe                   1,536B  no_imports
       report.docx                           292B
         word/document.xml                 1,200B  unrecognised_format
         word/media/image1.png             2,008B  unrecognised_format
     ~ alerts.csv                             29B  high_file_entropy
```

One line per member rather than a report per member: thirty reports is not a
summary, and `--json` carries everything. A member whose own analysis came
back short is marked `(incomplete)`, because the errors block belongs to the
container and the absence would otherwise be invisible. The list caps at
twenty-four and says where the rest is.

**The findings header now scores the file rather than the tree.** `severity`
includes everything inside, which is right for the exit code and wrong as a
label above a list of this file's own findings: a ZIP with one low finding and
a medium member was announcing `findings (medium max)` above a single low
line.

### A compressed container is no longer scored on its own entropy

Deflate output is incompressible by construction, so every ZIP and every GZIP
scores about 8.0 and `high_file_entropy` on one carries no information. It
mattered less when a container was a single opaque file; now the members are
scored individually and the container's figure is noise sitting above them.

Withheld, not silent: the numbers stay in the report, `entropy` carries
`whole_file_finding_withheld`, and the rendered line says "measuring the
compression rather than the contents". TAR is deliberately not on the list,
because a TAR is not compressed and its entropy still describes its contents.

### One warning per run, not one per member

A missing optional parser logged an identical line for every file in the tree:
thirty on a small archive, four hundred on an installer, each naming a staging
path a release after those were taken out of the report. `scan` now quiets the
package logger unless `-v`, which is what `corpus` already did. What could not
run is still in the report's errors block, which is where a consumer reads it.

### The System32 prediction, and why it is not a verdict

v0.4.4 predicted the gate would land between 10.0% and 15.8% after the
certificate exclusion. Measured: **9.6%**, which is 0.4 points below the floor.

It is also not the controlled comparison that prediction assumed, and the
harness is what said so. The v0.4.4 run sampled 291 files from a population of
23,907; this one sampled 292 from 23,949. System32 gained 42 files in the
intervening week, so the seed drew from a different pool: a seed fixes which
files are picked from a list, not what is on the list. `signature_present`
moved from 12.0% to 9.2% and `section_entropy_high` appears for the first
time, which is a different file mix rather than a different tool.

So the direction and rough magnitude held - the gate fell from 15.8% and
`entropy_hotspot` halved from 12.4% to 6.2% - and the band is neither
confirmed nor refuted. Recorded that way rather than claimed as a success.

The `sampled_from` line, added in v0.4.3 so a sampled result could not be
mistaken for a complete one, is what made the population change visible. It
was written for honesty about sampling and paid for itself as a diagnostic.

### Also

- Two mutation survivors were tests checking the wrong thing again. The header
  test used a ZIP carrying a PE, which has no findings of its own, so the
  header was absent whatever the renderer did; the cap test read the `+16
  more` message, which printed whether or not the list was capped. The first
  is now built by hand, because it is a question about the renderer and two
  attempts to produce it from real containers failed for reasons about
  entropy. The second counts the lines.
- A TAR fixture of 40 KB tested nothing: tar pads to a 10 KB block, which
  pulled the whole-file ratio to 0.874 and under the threshold, so the test
  read a too-small fixture as the rule working.
- **461 passed**, or 350 passed and 111 skipped with neither pefile nor
  yara-python.

---

## Version 0.5.0 - opening containers, and the attack surface that comes with it

Every extractor before this one read bytes and reported what it saw. This one
is handed a structure whose author chose the entry names, the declared sizes,
the nesting depth and the compression ratio, and acts on them. The feature is
three hundred lines; the safety is most of them.

`maltriage scan installer.zip` unpacks members into a directory the tool
deletes when the scan ends, analyses each one, and attaches the result as a
child report. ZIP, GZIP and TAR. RAR and 7z are recognised and not opened.

### Four rules, stated before the code rather than after it

**Nothing an archive says about itself is believed.** A ZIP entry declares an
uncompressed size. That number is a claim by the sample and a bomb is exactly
the case where it is a lie, so every member is read through a cap and the cap
is what ends the read. The declared size is recorded and never used as a
bound, and the expansion ratio is computed from bytes actually written. A test
forges a 50 MB declared size onto a 64-byte member and asserts no bomb finding
appears.

**No member lands outside the staging directory.** Entry names are
attacker-controlled text. `safe_member_path` refuses absolute paths in either
POSIX or Windows spelling, drive letters, UNC paths, any `..` segment, and
anything whose *resolved* location is not under the root. The last check is
the one that matters: a tar can write a symlink entry and then an
ordinary-looking entry through it, and that name contains no `..` and is not
absolute. A refusal is a finding at `high`, not a skipped line in a log.

**The budget belongs to the tree, not to each archive.** A thousand archives
of a thousand small entries is the same attack as one enormous member, and a
per-container limit does not see it. Depth, entry count, bytes written and
wall-clock time live in one `Budget` passed down the recursion, and the first
to run out stops the walk and says so in the report.

**The pipeline recurses, not the extractor.** An extractor calling `analyse`
would import the module that imports it, and would own a budget spanning files
it cannot see. The extractor stages members into a directory the pipeline
created and will delete; the walk belongs to whoever owns the tree.

### Severity propagates out of a container

`Report.severity` is now the worst of a file's own findings and everything
inside it, which is the case recursion exists for: a gate scoring the wrapper
rather than its contents exits clean on an installer carrying a dropper. The
propagation is in the model rather than in the CLI because the exit code, the
corpus harness and the envelope all ask the same property the same question.

Schema 1.7 adds `children`, and `to_dict` recurses into them. `asdict` copies
fields, and `severity` is a property, so each child's own worst score would
have been missing from its dictionary while the parent's was present.

### `archive_path_traversal` is the second finding in this project to earn high

The first is `extension_mismatch`, and the argument is the same: content that
lies about what it is deserves a human on that alone. An entry naming a path
outside its own container has no benign reading, and a build script that
produces one is broken in a way worth knowing about too.

### What the report does not carry

`staged` is plumbing between the extractor and the pipeline. It names a
directory on the scanning machine, which is the leak `Report.path` already is
and the envelope exists to strip, so the pipeline removes it once the walk has
used it. A child's `path` is rewritten to `container.zip!/member.exe`: the
real path names a file deleted moments later, and the fake one says something
useful.

Caught by a test written for it, which failed on the first implementation.

**And the name in it comes from the container, after Windows said otherwise.**
The first version derived it from the staging path with `relative_to`, so the
separator was whichever one the scanning machine's filesystem uses: the same
ZIP described itself as `lib/thing.bin` on Linux and `lib\thing.bin` on
Windows. Every format here uses forward slashes internally and the ZIP
specification requires them, so the name is read from the entry rather than
from the host, and `staging_root` is gone with it.

This could not have failed on Linux, which is the fourth defect this project
has found by running the suite on Windows and the reason that machine is the
verification environment rather than this one.

### Two lessons from the mutation runs, neither about archives

**A mutation run on a tree that is not green proves nothing, and this is the
second release to learn it.** Thirteen mutations all reported "caught", every
one of them by a test that was already failing. Fixed, re-run, and this time
the harness restores the file on SIGTERM - because the previous run timed out
mid-mutation and left the mutation in the tree, which then explained two
failures that were mine rather than the code's.

**Three survivors were test gaps rather than safe code.** The `..` check and
the resolve check overlap, so removing either left the other catching every
case the suite had. The cases that separate them are now pinned: a name that
normalises back inside the root is still refused, and a symlinked directory
inside the root is caught only by the resolve. A fourth survivor was an
equivalent mutant, and is left alone and recorded.

### Also

- TAR is identified by its magic at offset 257, which is why it was absent
  from the signature table while ZIP and GZIP were there.
- `archive_max_ratio` is an integer and deliberately does not use
  `config_ratio`, which is bounded at 2.0 because it exists for entropy.
  Borrowing it would have silently clamped 200 to 2.
- The encoding guard from v0.4.4 cannot tell `zipfile.ZipFile.open` from
  `Path.open`: both are a call named `open`, and the first takes no encoding.
  Rather than loosen the rule into guesswork about receivers, a call can be
  marked `# binary API` on its own line, which keeps the exception visible in
  the source instead of hidden in the test.
- **451 passed**, or 342 passed and 109 skipped with neither pefile nor
  yara-python. 37 new tests, 14 mutations, all caught.

### What is not here

- **RAR and 7z** need a third-party decompressor. A dependency that parses
  hostile input is one thing; one that unpacks it is a larger decision,
  because the unpacker becomes the thing handling attacker-controlled
  structure and the caps here do not reach inside it.
- **Known-good hash filtering**, which is what makes a four-hundred-file
  installer readable rather than merely safe to open.
- **The hung parser.** The recursion checks a deadline between members, so a
  nesting bomb ends with a report that says it ran out of time. A single call
  into zlib that never returns is still unbounded: nothing in the pipeline can
  interrupt a C extension mid-call, and closing that needs the subprocess the
  roadmap has always said it needs.

---

## Version 0.4.5 - one module per format

`extractors.py` was 3,091 lines: a quarter of the project, eight extractors
for six formats, in one file. It is now eight modules, and `extractors.py` is
the extractor set plus the names everything imports.

| module | lines | what it holds |
|---|---|---|
| `base.py` | 225 | the three extractor kinds, `ParserUnavailable`, and the helpers more than one format needs |
| `filetype.py` | 99 | format identification from magic bytes |
| `hashes.py` | 85 | cryptographic and optional fuzzy hashing |
| `entropy_scan.py` | 188 | the windowed scan |
| `strings.py` | 543 | ASCII and UTF-16 extraction, IOCs, the run scanner |
| `pe.py` | 923 | PE structure, and `certificate_range` for phase 1 |
| `elf.py` | 703 | ELF structure |
| `rules.py` | 407 | YARA compilation and matching |

**Timed rather than prompted.** v0.5 adds an archive parser and v0.6 adds two
document parsers. Each would have made this same work larger, and a file that
grows by a format per release is not a file anybody chose - it is one nobody
got around to dividing.

### Nothing changed behaviour, and that was checked three ways

- The suite passed **412 on both sides** of the move.
- A report-level diff over the bundled samples: every field of every report,
  **byte-identical** before and after.
- A check that no name the package imports went missing from
  `maltriage.extractors`.

Line ranges were moved rather than retyped, so the concatenation of the new
modules differs from the original only in the module headers.

`extractors.py` re-exports every name the project and its suite import, for
the reason `entropy.py` did when the secret engine took its arithmetic: a
refactor that forces every caller to learn a new layout has spent its own
benefit. What it does not re-export is the format constants - `SHT_NOBITS`,
`SCN_MEM_EXECUTE`, `DIRECTORY_DEBUG` and the rest - which were only reachable
because they shared a file with everything else, and now live with their
format.

### The split found two defects, which is the argument for doing it

**Four tests were patching a name nothing read.** A monkeypatch on
`extractors_module.compile_rules` rebinds a name in the facade; the code that
calls it looks up its own module global and never sees the patch. Those tests
would have passed while testing nothing. They now patch the module that owns
the name - `rules_module`, `pe_module`, `elf_module` - and one of them
caught itself immediately: the compile-once test reported "compiled 0 times
for 8 files" the moment the patch stopped landing.

**One test had never run.** `test_per_section_entropy_separates_a_packed_section_from_a_padded_one`
was defined twice, once for PE and once for ELF. Python keeps the second, so
the PE one had been silently replaced since the ELF extractor landed in v0.3.1
-- and the suite's pass count had been counting the pair once. The ELF one is
renamed, the PE one runs for the first time and passes, and
`test_no_two_tests_share_a_name` parses the suite with `ast` and fails on any
future pair. Found by `pyflakes`, which is worth running on a file nobody has
read end to end lately.

The key-coverage test needed the same attention: it reads the source for
`mk_finding(self.name, "...")` calls, and after the split it would have read
`extractors.py`, found no keys at all, and passed vacuously. It now walks
every module in the package and asserts it found more than twenty - the
failure mode a test that greps for its own subject always has.

### Also

- **414 passed**, or 305 passed and 109 skipped with neither pefile nor
  yara-python. Two more than v0.4.4: the test that had never run, and the one
  that stops it happening again.

---

## Version 0.4.4 - a signature is not the file's content

v0.4.3 left `entropy_hotspot` as the largest remaining contributor to the
gate: 12.4% of ordinary Windows files, sole cause of flagging on 28 of the 46
the gate still caught. This release establishes what it was firing on and
stops it.

### The measurement came first, and it was not the obvious one

The first hypothesis was size: signed files are bigger, bigger files have more
windows, more windows mean more chances of a hot one. From the per-file record
of the same 291-file System32 sample, holding size constant:

| file size | signed, with hotspot | unsigned, with hotspot |
|---|---|---|
| under 32 KB | **6 of 6 (100%)** | 2 of 168 (1%) |
| 32-128 KB | 5 of 8 (62%) | 2 of 39 (5%) |
| 128-512 KB | 7 of 12 (58%) | 3 of 30 (10%) |
| over 512 KB | 7 of 9 (78%) | 4 of 19 (21%) |

Six to a hundred times the rate, in every bucket. It is not size. An
Authenticode certificate is DER-encoded hashes and signatures, so it cannot be
anything but high entropy; it is not part of the mapped image; and it is not
the sample's content in the sense the finding means. A signed 20 KB DLL is
mostly certificate by proportion, which is why the smallest bucket is 100%.
Scoring it was scoring the envelope rather than the letter.

### The phase problem, and why `ctx` was the answer

`EntropyExtractor` is a stream: one forward pass, no seeking, no idea where
anything is. The certificate range is parsed by the PE extractor, two phases
later. The obvious fix asked an earlier phase to know something only a later
one learns.

It does not, as it turns out. **The security directory is the one data
directory entry that holds a file offset rather than an RVA**, which is
exactly what makes it readable without the section table and therefore without
the random-access phase. `FileTypeExtractor` publishes the range into `ctx` in
phase 1 - the same channel it already uses for the format family, and the one
`architecture.md` has described since v0.1.2 as "each sees what the previous
one published" - and the entropy stream drops those bytes before they reach a
window or the histogram.

No new phase, and no cross-extractor findings pass. The alternative was the
correlation phase this project has declined twice, and it would have been the
wrong shape anyway: this is an observation travelling forward, not a
conclusion drawn from two extractors at once.

### Writing it opened an evasion

The first version trusted the range. A sample controls that field, so a PE
whose security directory was rewritten to say *offset 64, length everything*
made the entropy pass skip the whole file - a packed binary going completely
silent, which is worse than the false positive it was meant to fix.

The second version required the range to end at the end of the file, which
Authenticode requires. `offset 64, length size-64` satisfies that too. It
survived.

What works is structural: **a certificate that overlaps the mapped image is
not a certificate.** The section table sits in the header beside the directory
making the claim, so the last section's raw end is knowable in phase 1, and
the range must begin past it. Three checks now - past the image, ending at
the file's end, non-empty - and a range failing any of them excludes nothing,
so the failure direction is "score every byte". There is a test that builds
exactly that evasive PE and asserts the payload still scores.

### What it reports

- `entropy.excluded` names the reason, offset and size, or is `null`.
- `entropy.bytes_scanned` says how many bytes produced the figures.
- The human output appends `skipping a 6,144B signature` to the entropy line.
  A number computed over a different set of bytes than the file holds has to
  say so where it is reported, not three screens away in the JSON.

### Predicted, not yet confirmed

From the per-file data, the gate should land between **10.0% and 15.8%** on
the same seeded System32 sample - 10.0% if every hotspot on a signed file was
the signature, higher if some signed files carry a genuine hot region as well.
That run has not happened yet. It is recorded here as a prediction rather than
left out, for the same reason v0.4.3 recorded the `extension_mismatch` guess
that turned out to be wrong: a prediction nobody wrote down is not one that
can be checked.

What the suite does establish, independently of any corpus: a signed PE with a
quiet body scores no hot windows, the same random blob appended as an *overlay*
still does, a hot region inside a signed file still fires, and the evasive PE
above is scored in full.

### Also

- `FileTypeExtractor` reads the file size with `ctx.get` rather than
  `ctx[...]`. A caller handing it a bare context lost format identification
  entirely - a `KeyError` in the one extractor whose job is to say what the
  file is, because an optional key for somebody else's optimisation was
  absent. Caught by `test_family_detection`, which passes `{}`.
- That bug also made a whole mutation run meaningless: seven mutations all
  reported "caught", every one of them by my own broken test rather than by
  the test that was supposed to catch it. A mutation run on a tree that is not
  green proves nothing, and the run was repeated after the fix.
- 15 tests, mutation-verified. One mutation survives and is left alone: a
  missing size and a size of zero produce the same behaviour, which makes it
  an equivalent mutant rather than a gap.
- **412 passed**, or 304 passed and 108 skipped with neither pefile nor
  yara-python.

---

## Version 0.4.3 - the Windows corpus, and what it cost to find out

v0.4.2 could not answer four deferred decisions because it had no Windows
binaries to answer them with. This release points the harness at
`C:\Windows\System32` and answers them.

**The gate flagged 32.3% of ordinary Windows files.** Against 0.6% on Linux.
As a CI gate on Windows software this tool was unusable, and had been since
v0.2, with nobody in a position to say so. It now flags 15.8%, which is still
too high and is now a number with a list of causes attached rather than a
suspicion.

### Pointing the harness at a corpus you already have

`--benign DIR` and `--malicious DIR`, repeatable, taking the label as given
rather than reading it off a path. The `corpus/benign/` layout is right for a
corpus you are assembling and useless for one that already exists: copying two
gigabytes of Windows in order to rename its parent directory is a cost this
tool had no business imposing, and it is the reason this measurement did not
happen sooner.

`--limit N` scans at most N files of each label, drawn at random with a fixed
seed. Random rather than the first N: a sorted System32 opens with hundreds of
`api-ms-win-*` stubs, which are a coherent group and nothing like the rest.
Seeded, because a sample nobody can redraw is a measurement nobody can check --
and because it made the before-and-after below a controlled comparison on
identical files rather than two samples of the same directory.

A sampled result records what it was sampled from, in the output and in the
JSON. A rate over 291 of 23,907 files is a different claim from a rate over
23,907, and the difference has to survive into the artefact.

Symbolic links are skipped, which matters more here than on Linux: a Windows
system directory is full of hard links and reparse points, and a denominator
that counts one file twice is the one thing a false positive rate must not do.

### `api_capability` is settled, after three releases of deferral

It fires on **23.7%** of ordinary Windows binaries - 69 of 291. Promoting it
to medium would newly flag 44 files nothing else flags and take the gate from
15.8% to **30.9%**.

v0.4 wrote "when v0.7's corpus harness can state the cost, that is the release
that may change it", and that sentence has been carried, rephrased, through
three releases. The cost is stated. The severity does not move, and the reason
is now arithmetic rather than argument.

Worth keeping both numbers: **0% over 6,688 Linux files and 23.7% over 291
Windows ones.** That contrast is the clearest statement this project has of
why a corpus must match the claim being made about it.

### `no_imports` at medium was the largest single defect in the tool

52 of 291 files, and the sole cause of flagging on 48 of the 94 the gate
caught. The cause is a population that does not exist on Linux: Windows ships
thousands of **resource-only modules** - every `en-US\*.mui`, and a large
share of the DLLs beside them - with no entry point, no executable section
and no imports.

The finding's own argument excludes them. It says a binary with no imports
"must resolve them at runtime, the usual mark of a packed stub", and resolving
imports at runtime takes instructions. A module with no code has none.

So a PE with no entry point and no executable section now reports
`resource_only_module` at `info` instead. Not silence: a PE with no code is a
fact an analyst wants, and without it the absence of every import-derived
finding has no visible explanation. A stub with code and no imports still
scores medium, and a non-zero entry point defeats the exclusion, so it cannot
be used to carry code past the gate.

Measured on `C:\Windows\System32\en-US`, which is resource modules and almost
nothing else: 98.0% `resource_only_module`, and the gate at 1.0%.

### The counterfactual predicted the outcome exactly

Before the change, over the same 291 files, `counterfactual` reported that
demoting `no_imports` below the gate would take the false positive rate to
**15.8%**.

After the change, measured on the same seeded sample: **15.8%**.

That is what the marginal calculation was for. A gross count would have
predicted 32.3% - 17.9% = 14.4% and been wrong, because four of the 52 files
were flagged by something else as well. This is the first time this project
has been able to state the cost of a change before making it, and have the
number hold.

`no_imports` went from 52 files to 1. Fifty-one were resource-only; the
remaining one is a genuine no-imports binary with code, which is exactly what
the finding is for.

### What is still wrong, in order of what it costs

Over the same sample, now at 15.8%:

- `entropy_hotspot`, 12.4%, sole cause on 28. Demoting it would reach 6.2%.
  On Linux it cost 0.6%. Twenty times the rate on Windows is a fact about
  Windows binaries - compressed resources, embedded media, Authenticode
  blobs - and not yet a fact about the finding. Unmeasured: whether those
  hotspots land inside the certificate the file is signed with, which would
  be a mechanical exclusion rather than a severity change. `signature_present`
  fires on 12.0%, which is close enough to 12.4% to be worth checking and far
  from proof.
- `virtual_size_mismatch`, 5.5%, sole cause on 9.
- `known_packer_section` and `no_imports`, one file each.

### What was measured and did not settle anything

- `registry_persistence_path` costs 0.3% here - two files, promoting newly
  flags two. That reads as affordable and is the wrong corpus to read it from:
  Run keys live in installers, not in System32. It stays at low until a
  `Program Files` corpus says otherwise.
- **YARA did not run at all.** `incomplete: yara on 291 file(s)`: yara-python
  has no wheel for Python 3.14 and building it needs MSVC. So 15.8% is the
  rate *without* rules, and rules can only add to it. Whether a rule may
  declare its own severity, the question `AUTHORING.md` defers, remains
  unmeasured on Windows.
- `unrecognised_format` fires on 52.6%. That is the magic table meeting
  `.nls`, `.cat`, `.mun`, `.winmd` and the rest of the Windows data-file
  vocabulary. It is `info` and costs nothing, and it says the format table is
  thin for the platform.
- `implausible_timestamp`, 30.6%, and it is Microsoft's doing rather than the
  finding's: a `/Brepro` build writes a hash into the timestamp field instead
  of a date. The finding is correct and useless as a signal here. It stays at
  low; promoting it would reach 39.9%.

### Also

- 9 of 300 files were unreadable and counted as `incomplete` rather than
  quietly leaving the denominator, which is what that counter was added for.
- Throughput on Windows: 5.0 MB/s and 11 files/s, against 5.6 MB/s and 81
  files/s on Linux. The per-file rate differs because the files are larger,
  not because the tool is slower.
- Predictions recorded before the run, for the record: `extension_mismatch`
  would light up on `.mui` and `.cpl`. It fired **zero** times.
- 26 tests, each mutation-verified, including one that pins that a DLL with
  code and no `DllMain` - entry point zero, which is ordinary - is not
  treated as a resource module. **399 passed.**

---

## Version 0.4.2 - the corpus harness, three releases early

The harness was v0.7's headline feature. It is here instead, because six
decisions in this repository were recorded as *deferred until something can
measure them*, and all six were deferred to the same release - one that sits
behind two feature releases. A decision deferred to a release that has not
started is not deferred, it is abandoned with a citation.

`maltriage corpus <root>` runs the tool over directories named for what is in
them and reports what fired on what.

**It is built for a corpus with no malicious files in it, rather than
tolerating one.** This repository must never contain a sample, and a harness
that waits for one would have waited forever. Precision and recall need both
labels; false positive rates need only the benign half, and the benign half is
what every open severity decision here actually turns on. Where a rate cannot
be computed from what was supplied, the result carries `None` rather than a
number: a precision of zero over an empty malicious set is a lie with a
decimal point in it.

**The counterfactual is the part that answers a question rather than reporting
a number.** For every key below the gate: how many ordinary files would be
newly flagged if it were promoted. For every key at or above it: how many
would stop being flagged if it were demoted. Both are *marginal* - they count
only files where nothing else already decides the outcome. The first draft
counted gross, and gross is worse than useless here: a key that fires on two
hundred benign files but never on one that isn't already flagged is free to
promote, and the gross count named it the most expensive key in the set.

### Measured, over 6,688 ordinary files

1,020 system binaries, 1,039 shared objects, 3,000 Python standard library
source files and 1,629 documentation files. 461 MB, 82.9s, **5.6 MB/s and 81
files/s** single-threaded - the throughput baseline this project has never
had.

**The gate flags 0.6% of them.** Forty files. Two keys produce all forty:

- `entropy_hotspot`, 38 files, and it is the sole cause on all 38. Demoting it
  takes the gate to 0.0%. The population is specific and worth writing down:
  Go binaries (`runc`, `containerd-shim`, `ctr`, `git-lfs`, `age`), character
  set conversion tables (`IBM930`, `SJIS`, `BIG5`, `libJIS`), and crypto
  libraries carrying embedded key material (`openssl`, `libsoftokn3`,
  `libnssckbi`, `libfreeblpriv3`). Dense tables and compressed sections, which
  is what the finding says it detects. It stays at medium: the finding is
  correct, the rate is 1 file in 167, and the fix is a demotion rule for a
  hotspot inside an ELF data section, not a lower severity.
- `yara_match`, 2 files: `gdb` and `libbfd`. Binutils embeds header magic for
  every format it parses, so a structural rule about a header where one does
  not belong is right to fire. 0.03%.

### What it settled

- **`secret_candidate` stays at `low`.** It fires on 1.2% of ordinary files,
  and promoting it would take the gate from 0.6% to **1.6%** - nearly tripling
  it, on 69 files nothing else flags. The v0.4 argument was that anything
  higher makes every minified bundle a CI failure; the number now says so.
- **Nothing the strings extractor reports may reach medium.** `urls_present`
  fires on 35.7% of ordinary files, `unix_paths_present` on 34.7%,
  `emails_present` on 26.3%. Promoting any one of them makes the gate useless
  in a single step. This was reasoned in v0.4 and is now arithmetic.
- **`high_file_entropy` stays at `low`**: 11.0%, and all 734 marginal.

### What it cannot settle, which is the sharper finding

`api_capability` fired **zero times** over all 6,688 files - as it did over
the 6,725 in v0.4. That is not the answer to whether a capability category may
reach medium. This corpus has no Windows binaries in it, so it measures that a
Win32 vocabulary does not fire on things that are not Win32 programs, which is
the smaller claim v0.4 already made. `registry_persistence_path` never fired
either, for the same reason.

So the blocker on those decisions was never the harness. It is a corpus of
ordinary Windows binaries, and that is now a named, obtainable item rather
than a release number. The four decisions still open are open for a reason
that can be acted on.

### Also

- `--max-false-positive-rate` exits non-zero when the gate flags more than a
  stated share of benign files, so a measured rate can be pinned in CI. It
  rejects a value outside 0 to 1 before the scan rather than after it, because
  `--max-false-positive-rate 5` meaning five percent is the mistake somebody
  will make, and it would otherwise pass silently forever.
- Otherwise a corpus run exits clean. A measurement that fails a build because
  it came back with a number nobody asked a question about is a measurement
  people stop running.
- The result carries counts and rates and no paths. `--per-file` adds one
  record per file, keyed by SHA-256 and never by name, and is off unless asked
  for: a corpus report is an artefact that gets kept and compared, and a corpus
  directory is by construction a description of somebody's sample collection.
- The raw result of the run above is **not committed**. It describes a machine
  nobody else has, and a baseline file implying two runs are comparable when
  the corpora differ is worse than no baseline. The numbers live here, where
  they are read.

### The README tests were broken on Windows, and had been for a release

Found on the first Windows run of v0.4.2, in code v0.4.1 shipped:

```
UnicodeDecodeError: 'charmap' codec can't decode byte 0x90 in position 3570
```

`Path.read_text()` with no encoding uses the *locale's* encoding - UTF-8 on
Linux, cp1252 on a default Windows install. The README draws its architecture
diagram with box characters, `┐` is `e2 94 90`, and `0x90` is one of the five
bytes cp1252 leaves undefined. So two tests raised there and nowhere else.

v0.4.1 said those tests were "verified from the public clone", and they were
-- on Linux, which is exactly the point. A test that reads a file is also a
test of the environment's idea of what a file is, and this project had been
verifying one environment and shipping to two.

- Every text read and write in the package and the suite now states
  `encoding="utf-8"`. That is 18 call sites, not the 2 that failed: patching
  only the failures would have left the rest waiting for the next person on
  Windows to find them one at a time.
- A test walks every source file with `ast` and fails on a `read_text`,
  `write_text` or `open` in text mode that does not name an encoding. Binary
  mode is exempt, which is how a sample is read and why no extractor was
  affected.
- A second test pins the reproduction itself: the README must still contain a
  byte cp1252 does not define, or the first test is guarding a defect that can
  no longer occur.
- `README.md` now documents `LANG=C LC_ALL=C python -X utf8=0 -m pytest -q`,
  which reproduces the whole class on Linux. Verified: it fails on the
  unpatched call and passes on the patched one.

### A third flaky test, found the way flaky tests are found

`test_a_token_inside_a_longer_string_is_not_a_candidate` ended with
`assert secrets_module.scan(f"prefix-{token}")` on a single token, and failed
about **one run in twenty**. Measured, not estimated: over 3,000 draws, 2,558
tokens were nominated on their own and 95.0% of those were still nominated
with `prefix-` glued to the front.

`_detected_token` guarantees the *bare* token is nominated. Gluing seven
low-entropy characters onto it makes a different string with a lower entropy
ratio, so about one in twenty falls under the bar. The guarantee did not
survive the concatenation and the test assumed it had - which is exactly the
defect the v0.4 pass fixed in two other tests, in a shape that pass did not
look for.

The claim is now split. The tokenisation - that a hyphen does not split the
token, so the string is one span of 47 characters - is a fact, asserted
against `_TOKEN` and independent of any draw, and verified by removing the
hyphen from the character class. What the entropy tier then does with that
token is a heuristic, and is measured over 200 draws against an 85% bar, six
standard deviations below the measured rate. Twenty-five consecutive runs of
the secret engine tests, and four of the full suite, all clean.

- 28 tests, each verified by reintroducing the defect it exists for: counting
  findings instead of files, the gross counterfactual on both sides, a
  precision of zero for an empty set, inferred labels, marginal counts polluted
  by malicious files, a filename in the per-file record, an unreadable file
  vanishing from the denominator, and four CLI exit paths. All fourteen
  mutations were caught. **374 passed**, or 278 passed and 96 skipped with
  neither pefile nor yara-python.

---

## Version 0.4.1 - the README is an interface

A close-out rather than a feature. `__version__` and `pyproject.toml` both say
0.4.1; v0.4 itself is not finished, because reputation enrichment and offline
mode are still open, and a tag saying otherwise would be a claim this project
does not make.

**Verified from the public clone**, which is the only test that matters for a
repository somebody else might use: `git clone`, a clean virtual environment,
`pip install -e '.[all]'`, every command the README documents, and the whole
suite. 343 passed.

**The README now has tests behind it.** It documented `python cli.py scan ...`
for two releases after the package layout moved `cli.py` inside `maltriage/`,
and every command in it was broken while the suite stayed green - because the
commands in a README are an interface with nothing behind them. Three tests
close that:

- every shell line in a `bash` block must be a form this tool offers, and its
  arguments must parse. This is what catches `python cli.py` and a renamed
  flag.
- every extra the README names in `pip install -e '.[...]'` must be declared
  in `pyproject.toml`.
- the walkthrough runs for real: generate the samples, scan them, write all
  three output formats, and check the envelope carries no path.

Each was checked by reintroducing the bug it exists for. The first fails on the
historical `python cli.py`, and on `--jsonlines` for `--json-lines`; the second
fails on `.[everything]`.

The counts in the README are corrected and re-measured: **343 passed** with
every optional dependency, **247 passed and 96 skipped** with neither pefile
nor yara-python.

---

## Version 0.4 - a package, and strings

Two things, and the first exists to make the rest of v0.4 possible. Three
components on the roadmap are shared with claude-recon-agent and Shadowfax,
and a project that cannot be imported cannot share anything: "shared" would
have meant three copies that drift, which is the problem sharing was meant to
solve.

### Added

- An installable package. `maltriage/` with `pyproject.toml`, a `maltriage`
  console script, `python -m maltriage`, and the bundled rules carried as
  package data so an installed copy finds them. Optional dependencies are
  declared as extras (`pe`, `yara`, `fuzzy`, `fast`, `test`, `all`) and the
  core still has none
- `config.py` and `fixtures.py`, split out of `sample_data.py`. Every
  extractor needs the config accessors and none of them needs a PE builder,
  so a module named for its fixtures was the wrong home - the docstrings had
  been apologising for it since v0.1.2
- `StringsExtractor`: printable ASCII and UTF-16LE strings taken off the
  shared pass, with URL, email, IPv4, registry path, mutex and absolute path
  indicators drawn from them
- `strings_include_text`, off by default. The indicators are the triage value
  and are always present; the raw list is two megabytes of somebody else's
  file in an artefact that gets stored, piped and shared, and a sample that
  harvests credentials has them among its strings
- `apis.py`: a registry of Windows API names grouped into eleven capability
  categories, and the matcher that recognises them. The first shared module,
  which is what the package layout was added for. It answers "which of these
  names did you see" and the extractors decide what to say about the answer
- Capability findings from two views. `PEExtractor` reports what the import
  table names outright; `StringsExtractor` reports what appears as literal
  text, which is the only evidence there is when a sample resolves its
  imports at runtime. Both file under the single key `api_capability` with
  the category in the detail, for the reason v0.3 gave for `yara_match`
- `api_names` and `api_capabilities` in the data for both extractors, listing
  what was seen whether or not it reached the threshold for a finding
- `api_min_names_per_capability` (2) and `api_max_token_scan_bytes` (128)
- `findings-envelope.md`, envelope version 0.1. The roadmap has pointed at
  this filename since v0.4 and no such file existed: the spec was written in
  conversation and never committed, so the reference was to nothing. It is a
  draft from the constraints the roadmap did record, and maltriage is the
  first emitter, so it is a proposal for claude-recon-agent and Shadowfax to
  argue with rather than a contract
- `envelope.py` and `maltriage scan --envelope PATH`, one JSON object per file
- `evidence` and `discriminator`, optional arguments to `mk_finding`, omitted
  from the result when not given. Supplied at six finding sites so far;
  everywhere else the envelope emits an empty evidence list, and the spec says
  what that means - the emitter has not been taught this key yet, not that
  there was nothing to say
- `attack.py`, the shared ATT&CK registry: technique ids with their names and
  tactics, and the rule for when one may be attached. A registry rather than a
  mapping - it says what `T1036.008` is called, not which findings earn it
- `mitre`, a third optional argument to `mk_finding`, validated against the
  registry so an id that does not exist cannot reach a report by way of a typo
- A `mitre` key in a YARA rule's `meta`, comma separated. An id this build does
  not recognise is not attached and is reported in `parse_errors` against the
  rule name

### Changed

- `EntropyExtractor` keeps a running maximum, total and count instead of one
  float per window
- `cli.VERSION` reads `maltriage.__version__` instead of being a second
  literal. They had already drifted: `--version` said 0.3.1 while the package
  metadata said 0.4.0
- Nothing the strings extractor reports reaches medium. An installer writing
  a Run key is an installer, and `GATE_SEVERITY` is medium. Turning a string
  into evidence is the secret engine's job and then the classifier's, once
  v0.7 can measure what it costs

### Measured

The capability vocabulary was run over 6725 real files - 1610 Linux system
binaries and shared objects, 2959 Python standard library source files, and
2156 documentation files - to find out what it fires on when nothing is
wrong. Twenty-one files produced a finding, and twenty of those came from
`gethostbyname` and `getaddrinfo`.

They were the only libc names in a Win32 vocabulary, and they were correct
matches: those binaries do resolve hostnames. Being correct is not the
standard a finding has to meet. They are gone, and they belong to the POSIX
vocabulary that arrives with ELF symbol parsing, where the caller is an
import table rather than a string table.

The twenty-first was a source file that mentioned two API names in prose,
which is what led to the rule that a run containing a space is not a symbol
reference. Nothing worth matching has a space in it: not a bare name, not a
stdcall decoration, not a mangled C++ signature, not a comma-delimited pair.
Prose does. After both changes the whole 6725 produced **no capability
findings at all**.

That rule is also, measured on a 100 MB sample with 2.8 million strings,
about a third of the cost of matching - the extractor goes from 5.28s to
7.21s with it and to 8.44s without. The cheaper path and the more accurate
one turned out to be the same path, which is not usually how that goes.

What this does not measure is the Windows false positive rate, because these
are not Windows binaries. It measures that the vocabulary does not fire on
things that are not Windows binaries, which is a smaller claim. The real
number is v0.7's job, and it is why nothing here reaches medium.

### The secret engine, and what the exclusions cost

`secrets.py`, the second shared module. Three detectors: known vendor formats,
assignment context, and entropy for the formats no rule exists for.

**The engine never returns the secret**, and the rule now covers `report.data`
as well as findings, because `--json` writes the data and a report is stored,
piped and shared. There is no configuration switch and a `Candidate` has no
field to put one in.

**Offsets meant teaching the string scanner to count.** The roadmap has
promised findings that carry an offset since it was written, and
`StringsExtractor` recorded what a string was and never where it was.
`_RunScanner` now tracks an absolute file position across chunks, and an
offset is pinned to be independent of `read_chunk_bytes` exactly as a string
already was.

**The detector runs on the shared pass and the policy runs in `findings()`.**
"Lives in `findings()`, never in `parse()`" cannot be done as written:
`strings_include_text` is off by default, so by then there are no strings.
Matching happens where the strings are and produces a candidate with an offset
and no text; which candidates become findings is decided in `findings()`.

**Nine tenths of this module is exclusions, and every one was measured.**
Unfiltered, the entropy tier fired on **84.7% of 1610 Linux system binaries**.
In order of what each removed:

- Tokens that are not the whole string. A credential in a string table is its
  own null-terminated run. 70.8% to 27.5% of binaries, and 12.3% to zero on
  2959 Python source files.
- Digests, GUIDs and mangled C++ symbols.
- Tokens with every character distinct. That is an enumeration, not a draw:
  forty characters taken at random from sixty-four repeat one with probability
  about 0.999999, so not repeating is evidence the token was written out. It
  is what a base64 alphabet table looks like.
- Tokens that read like words, judged by the longest run of same-case letters
  against `log2(n) + 2`. Scaled rather than fixed, for the reason
  `expected_random_entropy` exists: a fixed bar of six rejects 12% of random
  32-character tokens and 21% of 48-character ones, while the scaled bar holds
  near 5% at both.
- A minimum length of 32 rather than 24. Three quarters of what was left were
  tokens of 24 to 27 characters, and they were symbol names.
- **And finally the one that found the rest: a token with no digit in it is
  words.** `CERT_VerifySignedDataWithPublicKeyInfo` is thirty-eight characters
  of mixed case that scores as random and contains no number. A token drawn
  from base62 omits digits entirely with probability about 0.0007 at that
  length, so the rule costs almost nothing.

That leaves **3.3% of binaries, 0% of source files and 0.3% of documentation**,
at a cost of about 15% of genuinely random tokens - and the recall is steady
from 32 characters to 48, which is what the scaling was for.

Two known-tier corrections came out of the same measurement.
`aws_access_key_id` fired on `wget` and `xkbprint`, because `AKIA` plus
sixteen uppercase characters occurs inside longer uppercase runs; every known
pattern is now required to be a whole token. And `private_key_block` is `low`
rather than `medium`: the strings extractor splits on newlines, so the rule can
only ever see the PEM header, and every TLS library on a machine contains that
header as a parser literal.

**Two flaky tests were found and fixed rather than left.** Both assumed a
random token is always detected, and one in seven is not. A test that fails
sometimes is worse than one that does not exist: it teaches whoever sees it to
re-run rather than to read.

`entropy.py` was split out of `extractors.py` in the process - the engine
needed the same maths and could not import a module that imports it - and
`expected_random_entropy` now takes an alphabet size, because a base64 token
cannot reach eight bits per character however random it is.

### The ATT&CK mapping is mostly refusals

Applied honestly to thirty-eight finding keys, the near-unambiguous rule
disqualified thirty-seven of them. `extension_mismatch` carries `T1036.008`
and nothing else carries anything.

That is the feature rather than a shortfall, and the refusals are worth the
space because each is a case somebody will reflexively want to map:

- **`known_packer_section`, `writable_executable_section`,
  `virtual_size_mismatch`, `no_imports`** are the shape of a packer.
  `T1027.002` describes software packing accurately, which is exactly the
  problem - the technique is right and the inference is not, because packing
  is the normal state of most installers and UPX is a legitimate tool.
- **`registry_persistence_path`** looks like `T1547.001`, and an installer
  writing a Run key is an installer. It is already held at `low` for that
  reason and a technique id would undo the restraint.
- **`implausible_timestamp`** is not `T1070.006`. Timestomping is about
  filesystem timestamps, and a zero PE compile timestamp is what a
  reproducible build produces on purpose.
- **`api_capability`** is refused despite `apis.py` carrying a technique per
  capability. A capability inferred from names present in a binary is not
  evidence the binary used them.

`extension_mismatch` qualifies for the same reason it is this project's only
`high`: there is no benign reason for a PE to be called `invoice.pdf`.

**The extensible half is a rule declaring its own technique**, because a rule
is a much narrower statement than a finding key. **None of the bundled rules
declares one**, and a test enforces that rather than leaving it to drift: they
describe the *shape* of a file and ATT&CK describes *behaviour*, and shape does
not survive the benign case. `embedded_pe_header` fires on any ZIP, CAB or MSI
carrying an executable, which is what those formats are for.
`base64_encoded_pe_header` fires on a MIME email attachment, because that is
what MIME does to attachments.

### Decided in the envelope

**`validated` means the emitter did work that could have falsified the
claim.** The roadmap recorded that "did the emitter compute it" was too weak
without settling what replaces it. The test that discriminates asks the
counterfactual: was there a version of this file for which the same work would
have produced no finding? A string copied out of the subject is `false` --
nothing was tested, and a file can say anything. A comparison, a computation or
a structural walk is `true`. That lands at ten keys false and the rest true,
rather than the twelve-in-thirteen `true` the roadmap was worried about.

Three findings look like transcription and are not. `ipv4_present` rejects
out-of-range octets, so `999.1.1.1` never becomes a finding. `registry_
persistence_path` quotes paths but claims they survive a reboot, which is a
membership test. `api_capability` counts names against a threshold, which is
two ways to have come back empty.

**`incomplete` is new and is not optional to the design.** The roadmap listed
no such field. An envelope carrying only findings converts "I could not look"
into "I looked and found nothing", which is the exact failure `report.errors`,
`imports_parsed`, `entropy_skipped` and every `parse_errors` message exist to
prevent. It carries `report.errors` across as `{source, reason}`.

**The envelope carries no path and no filename.** `Report.path` is resolved
and absolute, and the safety checklist records it as carrying the directory
layout and the username of the machine that produced it. This is the output
most likely to be handed to somebody else, so it is the one that must not
carry it - and a filename is little better, because a document is often named
after the person it is about. The cost is accepted: a directory scan produces
envelopes that only a hash distinguishes, and correlating one back to a file is
the caller's job, the caller being the party entitled to know the path.

**A name collision worth knowing about.** A maltriage report already has a
field called `validated`, on the certificate, meaning "was this Authenticode
signature verified against a chain" - always false, because nothing here
verifies chains. It and the envelope's `validated` are unrelated. They never
meet, because the certificate field is inside `report.data` and `report.data`
does not cross, but an emitter that later puts certificate data into `evidence`
must not carry that name with it.

**Nothing emits `mitre`.** The capability registry records a technique per
category as reference data and does not emit it, because a technique id is a
claim about adversary behaviour and `mitre` is the field a consumer is most
likely to aggregate without reading the finding underneath it.

### Reviewed

Three independent adversarial passes over the API work found six defects that
the tests and the measurement had both missed.

**`display()` did not guarantee what its docstring claimed.** It was
`SPELLING.get(canonical, canonical)`, so an unrecognised key came back
verbatim - ANSI escapes and all. The claim that no sample-derived text can
reach a report through this module was therefore true of the two callers
rather than of the function, and one refactor away from being false. It now
raises on a key it did not write.

**A token had a length ceiling, and a ceiling on a token is a hidden substring
match.** `_TOKEN` capped a token at 64 characters, so `j` * 64 followed by
`VirtualAllocEx@16` matched while `j` * 63 followed by the same text did not:
the padding filled exactly one token and left the API name starting the next.
Whether a name was found depended on its offset modulo 64, and the case that
found it was the wrong one - it is `PreloadLibraryPath` arriving by a
different route. Tokens are now whole identifiers at any length.

**`DnsQuery` could never have fired.** It is a macro; a binary imports
`DnsQuery_A` or `DnsQuery_W`, and the suffix fallback only stripped a bare
trailing letter. The fallback now also strips `_A` and `_W`. Registering both
spellings instead would have been worse: two entries for one API, counting
twice towards a threshold that means "two APIs".

**U+212A KELVIN SIGN lowercases to `k`.** `Get\u212AeyState` canonicalised to
`getkeystate`. Unreachable today because both callers decode through
`ascii`/`replace` first, which makes it unreachable rather than harmless, and
the POSIX vocabulary is going to arrive by another path. `_canonical` is now
ASCII-only.

**`categorise(view="Import")` silently selected the string index**, dropping
every name the string view excludes. A wrong answer in the shape of a right
one. Unknown views now raise.

**Two tests were weaker than their docstrings.** `test_an_ordinal_import_
matches_nothing` asserted that `"#42"` matches nothing, which no plausible bug
could break - it now drives an ordinal-only import through the real path
instead. And the `CryptUnprotectData` test survived a reordering that tried
the stripped form first, because nothing in the real vocabulary collides with
`cryptunprotectdat`; it now pins the ordering against a vocabulary built to
collide. The `", and N more"` sentence in a capability detail was executed on
every run and asserted nowhere: an off-by-one in it passed the whole suite.

### The wide-string defect, fixed

`architecture.md` has carried this as a known constraint since the API work,
described as cosmetic. The secret engine made it a missed `medium`, and that
is what moved it.

Where an ASCII string's NUL terminator sits against a UTF-16 string, the wide
pattern reached one byte too far left: the last character of `config\x00` plus
that NUL is itself a valid `(printable, NUL)` pair, so a wide `AKIA...` behind
it came out as `gAKIA...`. Known-format secret patterns require whole-token
boundaries - without them `aws_access_key_id` fired on `wget` - so a stolen
leading character puts a letter in front of the token and the guard refuses the
match. The credential disappeared and the report looked clean.

    b"\x00config\x00" + "AKIAIOSFODNN7EXAMPLE".encode("utf-16-le")

reported nothing. The same bytes with one more NUL reported the key.

**Fixed with a lookbehind rather than by filtering matches**, because
`finditer` returns non-overlapping matches: rejecting the run that starts at
`g` afterwards would not then find the one that starts at `A`, since it lies
inside the rejected span.

**Every buffer now carries the byte that preceded it.** A lookbehind has
nothing to look at when a match starts at offset zero of a buffer, so the fix
on its own would have made the result depend on where the chunks fell - the
one thing this scanner exists to prevent. The guard byte cannot seed a match of
its own: it is only printable when the carry is non-empty, and a non-empty
carry always begins with a printable byte rather than the NUL a pair would
need. Verified over 3000 randomised chunk splits across five bodies, and by
tests at chunk sizes 1, 2 and 3, which land a boundary exactly on the stolen
byte.

What it gives up is a wide string that begins immediately after ASCII text
with no NUL between them. That is ambiguous in the bytes and rare in practice,
since strings in a string table are terminated.

**One line in this fix is defensive and says so.** The carry index is held
above the guard byte, and mutation testing showed no test fails without it: for
the walk to reach the guard, the guard must be printable, which needs an empty
carry, and the only branch producing both is the skipping path. I could not
build an input that reaches it. The comment records that rather than implying
a test covers it.

### Known and not fixed

Nothing outstanding from this release. The wide-string defect recorded here
when the API work shipped is fixed above.

### Hardened

The strings extractor is the first stream extractor added since v0.1.2, and
the chunk-boundary invariant is the one it broke.

**Results depended on `read_chunk_bytes`.** The carry kept a run only when the
regex had matched and the match reached the end of the buffer - but a
fragment shorter than the minimum length can never match `{6,}`, so it was
dropped and the next buffer restarted inside the run. `MZAPPDATAROAM` split at
a 4096-byte boundary was reported as `PPDATAROAM`. A UTF-16 continuation that
resumed one byte late was emitted as a fresh run, so `wide_count` on 100 MB of
`A\x00` was literally the number of chunks. And the skip state that discards
the tail of an over-length run was never cleared by a buffer containing no
match, so an unrelated later string was thrown away as though it were a tail.
Fifty-two of sixty structured samples produced different results at different
chunk sizes.

The rule that makes it correct: **carry the trailing bytes that could still be
part of a run, not the trailing bytes that already matched one.** That covers
the matched case and the too-short case with the same code. UTF-16 parity is
carried across the skip as well, because an odd chunk size leaves the next
buffer starting on the NUL half of a pair.

**The entropy extractor had been linear in sample size since v0.1.2.** It kept
one float per window to compute a maximum, a mean and a count, all three of
which are computable in constant space. It went unnoticed because a float is
small - 2441 of them for a 20 MB sample is 80 KB, invisible beside a 1 MB
read chunk - and because the test that should have caught it compared a
200 KB sample with a 20 MB one. The stream phase has no size ceiling, so the
same list is 400 MB at 100 GB.

The rest:

- The retained-strings cap was enforced per kind, so it was a ceiling of twice
  what the config asked for, and the comment beside the default claimed the
  product as the worst case
- The fallback default in the extractor was 4096 while `DEFAULT_CONFIG` said
  2048, so an absent value silently doubled the ceiling
- A capped indicator list stated its length as a total: "128 URL(s)" when
  there were 400. It now says "at least", and every cap reaches `parse_errors`
  and the CLI, including the one that matters most - that when the retained
  list is full the indicators were drawn from a subset
- `architecture.md` still described the flat layout it had just stopped having

### Notes

Three of the tests written alongside this release did not test what they
claimed, and one of them could not have failed for any input:

- The chunk-size test's body was 1380 bytes against a 4096-byte header read,
  so the pipeline fed one chunk whatever `read_chunk_bytes` said. All four
  parametrisations ran the same code
- The terminal-escape test asserted `"\u001b" not in json.dumps(...)`. In
  Python source that literal *is* the ESC character, and `json.dumps` always
  escapes it to six characters, so the raw character can never appear.
  Adding ESC to the printable range left the whole suite green
- The over-length test asserted `>= 1`, which passes at 489 as happily as at 1

Ten further mutations survived the suite, including deleting the entire
cross-boundary carry and replacing the entropy maximum with a minimum. The
`EntropyExtractor` change under review had no coverage at all.

Both memory tests were also measuring the wrong thing. They compared a small
sample with a large one, which conflates "grows with the sample" with "reaches
its ceiling": a bounded retained list is a fixed cost a small file never pays.
They now compare two sizes that have both saturated every ceiling, warm each
path before measuring, and subtract the memory already live - because
`get_traced_memory` reports the whole process and these tests run after two
hundred others that hold their own fixtures.


## Version 0.3.1 - ELF

The last unshipped piece of v0.2's design, arriving after v0.3 because that is
when it was built rather than because it belongs there.

No dependency. The header, program header table and section header table are
fixed-layout records that `struct` reads, and there is no equivalent of
pefile's accumulated knowledge of malformed real-world files to buy. The rule
`architecture.md` states is to pay a dependency where the format is genuinely
hostile, not where it is merely binary. So there is no optional import, no
missing-parser error, and it works on a bare checkout - and every bound is
this module's own.

### Added

- `ElfExtractor`: class, byte order, ABI, type, machine and entry point; the
  program header table with per-segment permissions; the section header table
  with per-section entropy; dynamic linkage with DT_NEEDED, DT_SONAME,
  DT_RPATH and DT_RUNPATH; the interpreter; the GNU build id; and trailing
  data past everything the headers account for
- Findings at medium: `writable_executable_segment`, `section_entropy_high`,
  `no_section_headers`, `entry_point_outside_segments`,
  `entry_point_not_executable`, `packer_section_name`. At low:
  `executable_stack`, `runpath_set`, `rpath_set`, `nonstandard_section_name`,
  `large_trailing_data`. At info: `trailing_data_present`, `stripped_symbols`,
  `statically_linked`, `build_id_present`
- `build_elf` in `sample_data.py`, building a structurally valid ELF for both
  classes and both byte orders, with segments, dynamic linkage, an
  interpreter, trailing data and an optionally absent section header table.
  Verified against pyelftools, which is a test-only dependency
- `safe_text`, applied to every string either extractor takes from a sample
- A `helper.elf` bundled sample that is a real ELF, replacing the eight
  plausible bytes it used to be
- An ELF summary block in the human CLI output

### Fixed

- `stripped` and `statically_linked` are `None` rather than `False` when the
  table that would answer them was never read

### Hardened

Eight defects from the fuzzing pass, each now with a regression test. Two are
worth reading even if the others are not.

**Section names were wrong on 3181 of 3185 real binaries.** GNU ld tail-merges
`.shstrtab`, so most names are interior offsets - `.rela.plt\0` also serves
`.plt` at +5. Resolving only the offsets that follow a NUL meant
`nonstandard_section_name` fired on essentially every ELF in existence, which
is a finding carrying no information, and a crafted `sh_name` pointing into
the middle of a string evaded `packer_section_name` entirely. Names are now
read from each offset to the next NUL. Measured after the fix: names match
pyelftools on 400 of 400 files, and the finding fires on 16 of 1201 rather
than on all of them.

**A string from the sample could unprint a finding.** DT_RUNPATH, DT_SONAME,
section names and the PE PDB path are attacker-chosen text that lands in a
terminal. A RUNPATH of `\x1b[6A\x1b[0J` plus a fake findings block moved the
cursor up six lines, cleared to the end of the screen, and replaced three
medium findings with a clean-looking one. `safe_text` now strips C0, DEL and
C1 control characters and caps length, and it covers the PE strings for the
same reason. C1 matters as much as C0: 0x9B is the single-byte CSI introducer
that `ESC [` spells in two, and it survived the one path that decodes to `str`
before sanitising.

The rest:

- `e_shentsize = 0` - one two-byte field - made the section table read as
  empty with nothing recorded. The file still runs, because the kernel never
  reads section headers, so the report said `stripped: true` about a binary
  with a full symbol table while the entropy and packer-name findings vanished
  without a word. A claimed table that cannot be read is now reported
- `writable_executable_segment` counted PT_GNU_STACK, which is a flags-only
  marker rather than a mapping and which `gcc -z execstack` sets on request.
  An ordinary build earned a medium whose text was untrue in both halves. The
  finding is now PT_LOAD only, and an executable stack is its own `low`
- `section_entropy_high` fired on 8.5% of real binaries, 548 of them from
  `.debug_*` alone because DWARF is dense, and the rest from read-only tables:
  a 256-byte byte-permutation table scores above 1.0 of random while being the
  most ordered data there is, since the reference is an estimate of what a
  random *sample* reaches. The finding now requires a section the loader maps
  writable or executable, because a payload has to be mapped to run
- Every cap truncated silently. `sections_truncated`, `segments_truncated`,
  `names_truncated`, `dynamic_truncated` and `needed_truncated` now exist and
  reach `parse_errors`
- Then `dynamic_truncated` fired on every ordinary binary, because stopping at
  DT_NULL and stopping at the cap were the same test. The first is the table
  ending and the second is the extractor giving up
- `build_elf` measured a segment's file size and memory size in the same
  space, so a file containing an SHT_NOBITS section got a `p_memsz` that
  stopped short of its own contents and an entry point outside every loadable
  segment - a false medium from a builder whose docstring calls its output
  structurally valid
- `e_shstrndx` pointing at a NOBITS section decoded names out of whatever sat
  at offset zero, which is the ELF header, and reported `\x7fELF\x02\x01\x01`
  as a section name
- SHN_XINDEX - the legal way to have more sections than `e_shnum` can express
  - was read literally as no section table at all, which is a medium

### Notes

Before this release no ELF test fed the extractor a malformed file, and
fourteen of its seventeen bounds could be deleted with the suite still green.
There is now a hostile-input section modelled on the PE one.

The finding set was measured against 1201 real binaries from `/usr/bin`,
`/usr/sbin` and `/usr/lib`: **zero mediums**, `runpath_set` on 50 and
`nonstandard_section_name` on 16. `GATE_SEVERITY` is medium, so a false
medium is a false CI failure, and a finding set nobody has pointed at real
software is a finding set nobody has tested.


## Version 0.3 - pattern matching

YARA. The release where the extractor set stops being fixed by the code: a
rules directory is an extension point anybody can add to, and an extension
point is an input.

### Added

- `YaraExtractor`, a random-access extractor. yara maps the file itself, which
  is the third kind's contract exactly; `match(data=...)` needs the sample
  whole and is therefore not available to this project
- A bundled structural rule set under `rules/`: an executable header where one
  does not belong, an executable encoded as base64 or hex, a PDF that runs
  something when opened, a PDF or RTF carrying an embedded object, an OLE2
  document with a VBA project. No family signatures, because this project has
  no corpus to keep them honest until v0.7, and nothing that restates a
  finding an extractor already produces
- `rules/AUTHORING.md`, the rule authoring notes
- Per-rule-file compile isolation. One `yara.compile` over the directory loses
  every rule to a syntax error anywhere in it; a rule somebody is halfway
  through writing should disable that file and nothing else
- `carrier.pdf` among the bundled samples: a real PDF with a real executable
  in its body. No extractor sees it, because the file is what it says it is
  and the payload is just bytes inside it
- `config_bool`, strict in the same way `config_int` is

### Changed

- `analyse_directory` builds its extractor set once and reuses it, which the
  `StreamExtractor` contract has always described and no previous release had
  a reason to exercise. Compiling a rule set is the first setup worth keeping
- `SCHEMA_VERSION` to 1.4
- The CLI renders `errors` and `incomplete` as two blocks. One heading that
  changed wording depending on which was present made the more serious of the
  two disappear into the other whenever both occurred

### Match context

Findings carry the rule, its tags and meta, the string identifier, the offset
and the length. They never carry the matched bytes, and there is no
configuration switch to add them: the person most likely to turn one on is the
person debugging a rule that matches secrets. This is the v0.4 secret engine's
rule, arriving a release early because YARA is the first thing that could
break it.

Every match files under the single finding key `yara_match`. Rules are
user-extensible and the key set is not; the rule name is data.

### Hardened

Ten defects from the first fuzzing pass and six more from the second, all
found after the code was written and each now with a regression test. The
theme is that a rule set is an input, and half of these are about the rules
rather than the sample.

- A rule could write the sample to the terminal. YARA's `console` module goes
  to the process's own stdout when nothing captures it, so a rule could dump
  the file as hex under `--quiet` without a byte of it reaching the report --
  the one channel that defeated "the extractor never reads `matched_data`".
  A `console_callback` now takes it to the debug log
- A four-byte string against a crafted sample produced libyara's cap of a
  million match objects: 220 MB from a 4 MB file. Fast matching records the
  first occurrence of each string instead. libyara ignores fast mode for any
  string whose condition reads that string's count, offset or length - `#a`
  is one of the commonest idioms in public rule sets - so `yara_max_scan_bytes`
  bounds the one thing the extractor genuinely controls
- Under fast matching a string reported `count: 1` and `truncated: false` for
  seven hundred thousand hits. `truncated` is the field whose whole job is to
  say nothing was left out. Strings now carry `complete`
- `include` reached the whole filesystem. `include "/etc/passwd"` was opened
  and parsed, and YARA quotes offending tokens back in its syntax errors.
  Now off unless `yara_allow_includes` says otherwise
- The compile cache was keyed on nothing, so a reused extractor answered with
  whichever rule set it saw first while reporting the files it had been asked
  for - a stale result presented as a current one. It now keys on the rule
  files and on `yara_allow_includes`, because both are inputs to the compile
- An unusable `yara_rule_paths` entry vanished silently: a nonexistent path, a
  `Path` where a string was expected, a device file, an unreadable directory.
  The report claimed a full run while the configured rules never executed
- A dangling symlink or a directory named `sub.yar` inside a rules directory
  disappeared the same way
- Naming the bundled directory in `yara_rule_paths` - a natural thing to
  write, since configured paths add to the bundled set - emitted every match
  twice, including the medium the CI gate reads
- The timeout bounded each rule file, and the number of rule files is a
  directory listing rather than a bound. It is now a budget spent across the
  whole set
- `yara_default_severity` set to a list raised `TypeError` from a membership
  test against a dict, and the pipeline then discarded every match the
  extractor had already found
- Two broken rule files with the same basename rendered as one line
- `yara_fast_matching: "false"` and `: 0` were silently ignored while the
  report stated the setting the caller thought they had turned off
- `embedded_elf_header` matched four magic bytes, which occur once every 4 GB
  of random data. That is a spurious finding on packed samples and a test that
  fails about once in 3600 runs. EI_CLASS, EI_DATA and EI_VERSION are now
  constrained

Three of the tests written for the first round did not pin what they claimed.
The PDB-length test passed against the unfixed code because the value chosen
broke pefile's unpack for an unrelated reason; the scan-budget test could not
fail at four rule files; and the ELF test had a 0.1% chance of catching its
own regression. All three are rewritten, two of them driven by fakes or by
specific impossible values rather than by random data.

### Still open

A rule that reads its own match count, or that uses the `console` module, can
allocate until the scan deadline fires. Both are bounded by
`yara_max_scan_bytes` and `yara_timeout_seconds` rather than by a memory
limit, and neither is reachable from the bundled set. The mitigation is rule
discipline, which is documentation, and it lives in `AUTHORING.md`.


## Version 0.2 - executable structure

PE parsing. The first release whose extractors gate on the header phase,
which is what that phase was built for, and the first that produces fields a
classifier will eventually consume.

Thirteen new finding keys, none of them `high`. `GATE_SEVERITY` is medium, so
each of the six mediums below is a new reason for this tool to exit non-zero
in somebody's CI, and each earns that only because a file deserves a human on
that finding alone. Packing is not deception: it is the normal state of most
commercial installers, and `high` stays reserved for content that lies about
what it is.

### Added

- `PEExtractor`, a random-access extractor gated on `family == "pe"`. It
  reports PE type, machine, subsystem, DLL and driver flags, compile
  timestamp, entry point and its section, the section table with per-section
  entropy and decoded characteristics, imports with imphash, exports, TLS
  callbacks, the debug directory with its PDB path, the overlay, and whether
  a certificate table is present
- Findings at medium: `section_entropy_high`, `writable_executable_section`,
  `virtual_size_mismatch`, `known_packer_section`, `no_imports` and
  `entry_point_in_writable_section`. At low: `nonstandard_section_name`,
  `few_imports`, `implausible_timestamp`, `large_overlay` and
  `tls_callbacks_present`. At info: `overlay_present` and `signature_present`
- `FuzzyHashExtractor`, which is where ssdeep now lives
- `certificate_common_names`, a bounded scan of the PKCS#7 blob for X.509
  commonName strings. It answers "whose name is written in here" and refuses
  "is this trustworthy": the report carries `"validated": false`, and the
  names include issuing CAs as well as the signer
- `region_entropy`, which scores a region of a mapped file in bounded pieces.
  The histogram of a region is the sum of the histograms of its parts, which
  is the same property the streaming entropy extractor is built on
- `tls_callbacks`, `pdb_path` and `certificate` arguments to `build_pe`, plus
  `build_certificate`. Those three directories are the only pointer
  arithmetic in the PE extractor that pefile does not do on its behalf, so
  they needed fixtures rather than trust
- An optional fourth element on a `build_pe` section entry, its virtual size.
  Everywhere else virtual and raw size are derived from the body and agree by
  construction, so this is the only way to build the unpacker shape
- `dropper.exe` among the bundled samples: a structurally valid PE carrying a
  packed writable-executable section, a section reserving far more memory
  than the file fills, a thin import table and an appended payload. It
  contains no code
- Sixteen config keys under `pe_`, all validated

### Changed

- ssdeep moved from `HashExtractor` to the random-access phase. It reads the
  sample a second time, which it always did, but it now does so from a phase
  whose contract permits it rather than from one whose promise was that
  nothing did. Its output moves from `report.data["hashes"]["ssdeep"]` to
  `report.data["fuzzy"]`, and its absence is reported as `available: false`
- `SCHEMA_VERSION` to 1.3. The new keys are additive, but the rule is that
  the version moves when the shape changes, and additive is a change
- `entropy_from_counts` no longer returns `-0.0` for a region with all its
  mass in one byte value. It compared equal to zero and then serialised into
  the report as `-0.0`, so a flat section read as though something had gone
  wrong with it
- The human CLI output carries a PE summary line, imphash, PDB path, overlay
  and signer when they are present

### Fixed

- `ROADMAP.md` claimed "incremental fuzzy hashing" under v0.1.2. ssdeep is
  not incremental and never was, and this was the only false claim in the
  repository
- `ROADMAP.md` promised Authenticode "validity" for v0.2. Presence and the
  embedded signer name are free from the directory; validation needs a chain,
  a trust store and a clock, and none of those are dependencies this tool has
  taken. The entry now says what the code does
- Version drift in comments: the corpus harness is v0.7, not v0.6, and
  reputation enrichment is v0.4, not v0.5
- `README.md` carried a second roadmap that contradicted `ROADMAP.md`,
  putting the classifier at v0.6 and reputation at v0.5 and stopping there.
  It now points at the file instead of restating it, and "Current Features"
  no longer omits the v0.1.2 single-pass work

### Hardened

Every item below is a single forged field in an otherwise valid PE, found by
fuzzing the extractor after it was written rather than by reading it. Each one
parsed cleanly and reported something false or expensive, and each now has a
regression test built from the same fixture.

- A CodeView record's `SizeOfData` sized pefile's read, so one DWORD turned a
  PDB path into a copy of the sample: a 40 MB file produced a 40 MB string, a
  200 MB peak and an 84 MB JSON report, with no error raised. The debug
  directory is now walked here and every read is given a length
- `pe_region_entropy_bytes` bounded one region while the number of regions is
  a field in the file. Two thousand sections each claiming the whole file took
  75 seconds against 0.3 for a normal sample of the same size. The budget is
  now shared across the table
- The budget was then spent in table order, which let a file starve a section
  by putting it last. Section order does not affect loading, so that was a
  free evasion of `section_entropy_high`. It is now allocated by size
- A section granted less than the entropy floor was still scored. Sixty-four
  bytes of a 16 MB section produced a ratio above 1.0 and a `medium` finding,
  because the reference model is out of range below about 128 bytes
- `AddressOfCallBacks` below `ImageBase` produced a negative RVA, which
  `pefile.get_data` resolved by slicing backwards from the header buffer and
  returning DOS-stub bytes as callback addresses. An RVA inside the declared
  image but in no section resolved as a raw file offset and returned
  sixty-four callbacks read out of the overlay. The address must now land in
  a section that has bytes behind it, because `SizeOfHeaders` and
  `SizeOfImage` are fields in the file and a guard built from them is a guard
  the file controls
- A security directory claiming to start at the headers and run to the end of
  the file deleted the overlay from the report, hiding a dropper's payload
  for the price of two DWORDs
- A forged import RVA made pefile record a warning and parse nothing, which
  was indistinguishable from a file with no imports and earned `no_imports`
  at medium. The warnings are now on the report and the finding is gated on
  whether the table was actually read
- Reading the CodeView record by RVA alone made a zeroed `AddressOfRawData` a
  one-DWORD eraser for the build path. The file pointer in the same entry is
  now the fallback
- `region_entropy` returned `0.0` for a region it could not read. Zero is the
  entropy of a flat region; a region that was never read is not a flat region
- `scored_bytes` was computed before the ceiling was applied, so a capped
  region recorded a byte count nobody had read
- The budget's water-filling then left the division's remainder with whichever
  equal-sized section came last, so two identical sections received 3510 and
  3511 bytes according to their position. One byte, but enough to move an
  entropy figure in its fourth decimal place and so to make the table order
  observable again. Equal claims are now settled as a group

### Notes

Three things the design did not anticipate, all found by building it:

The certificate table lives past the last section, because that is where the
format puts it. Subtracting section end from file size therefore reports
every signed binary as carrying an appended payload, so the certificate is
excluded from the overlay and the report says when it was.

A truncated sample keeps a section table describing the file it used to be.
Entropy is scored over the bytes actually present and the report records how
many that was, rather than reading past the end of the mapping.

A region larger than `pe_region_entropy_bytes` is sampled rather than
refused, and marked `entropy_sampled`. Declining outright throws away a
usable answer; reporting it unmarked lets a partial figure pass as a whole
one.

One gap is unchanged and worth restating: isolation covers a parser that
raises, not one that hangs. `max_parse_bytes` bounds the file, pefile's
`max_symbol_exports` and `max_repeated_symbol` are set well below their
defaults, and the TLS walk is capped because its terminator is a value the
file supplies. None of that bounds time.

## Version 0.2 groundwork

No new findings and no change to any severity. This is the foundation the PE
and ELF work sits on: a third extractor kind, for structure that cannot be
reached in one forward pass, and a synthetic executable to test a parser
against.

### Added

- `RandomAccessExtractor`, a third extractor kind. It implements `parse`,
  runs in a third phase after the stream phase closes, and may open the
  sample for itself. It exists because a PE import table lives at an RVA that
  resolves through the section table to an offset no forward pass can reach
- `build_pe` in `sample_data.py`, which constructs a structurally valid PE32
  byte by byte: DOS header, PE signature, COFF and optional headers, section
  table, section bodies, an import directory whose thunks are real RVAs, and
  an optional overlay. Variants come from its arguments, so a fixture that
  drifts from the format drifts for every test at once
- `max_parse_bytes`, a ceiling on the random-access phase. A parser decides
  for itself how much structure to walk, so its cost is the one thing not
  bounded by the configured read sizes. A sample above the ceiling is
  declined and the refusal recorded, because a report that silently skipped
  an analysis looks identical to one that found nothing

### Changed

- "One open, one read" is restated rather than quietly broken. The pipeline
  still performs exactly one sequential read; a random-access extractor may
  additionally map the file and touch bounded regions of it. Bounded memory
  was always the invariant that mattered, and reading once was its proxy
- The phase-1 dispatch no longer calls `extract()` on anything that is not a
  header or stream extractor. No class has ever defined that method, so the
  branch produced an `AttributeError` that read as though the extractor had
  failed at its job rather than as though it had no contract. An object of no
  known kind now raises a `TypeError` naming the three that exist

### Notes

`pefile` maps the sample with `mmap` and never reads it into the process,
which is why the random-access phase opens the file rather than being handed
a capped buffer. Any cap chosen in advance is wrong in one of two directions:
too small and imports past the cutoff vanish silently, too large and peak
memory is back in proportion to sample size.

Neither existing memory test would have caught the second open, and both
looked like they guarded it. `test_the_file_is_opened_once_and_read_once`
patches `Path.open` while pefile calls the builtin, and `tracemalloc` does
not account for mapped pages. The new contract is pinned by tests written for
it rather than inherited from tests that would have stayed green either way.

ssdeep is still the exception it always was. Under the new kind it is simply
the first member of a documented category, and it should move into the
random-access phase when the PE extractor lands.

## Version 0.1.2

Internal release. No new findings, no change to any severity. The extraction
engine now reads a sample once instead of twice and no longer holds it in
memory, which is what makes the corpus work planned for v0.6 possible.

### Changed

- The file is opened once and read once. v0.1.1 opened every sample three
  times and read it in full twice, once streamed for hashing and once whole
  for entropy
- Peak memory is governed by the read chunk size rather than the sample size.
  On a 200 MB sample, peak RSS falls from 220 MB to 23 MB
- Entropy is accumulated from a running 256-entry histogram instead of a
  whole-file buffer. The histogram of a file is the sum of the histograms of
  its parts, so the whole-file figure needs nothing held in memory
- Extractors are now either header or stream extractors. Header extractors
  implement `read_header` and are handed the bytes the pipeline already read.
  Stream extractors implement `begin`, `feed` and `finish` and are fed every
  chunk in order
- The header bytes are fed into the stream phase rather than re-read, so no
  byte is read twice and nothing seeks backwards
- `findings` failures are isolated from extraction failures and recorded
  under `<name>.findings`. A broken heuristic no longer costs the data that
  produced it
- `hash_chunk_bytes` is replaced by `read_chunk_bytes`, which now governs the
  whole pass rather than one extractor. `header_bytes` is new
- `SCHEMA_VERSION` is 1.2

### Added

- `byte_counts`, which uses numpy when it is installed and falls back to the
  standard library otherwise. Both paths are asserted to agree, because
  entropy silently changing with the environment would be worse than being
  slow
- `entropy_from_counts`, entropy from a histogram rather than from bytes
- Tests pinning the guarantees the refactor rests on: results independent of
  chunk size and header size, streamed entropy equal to the whole-buffer
  calculation, one open and no `read_bytes`, peak memory flat across a 100x
  size increase, mid-stream failure dropping only its own extractor, failure
  in `begin` never reaching `feed`, stream extractors gating on the header
  phase, and instances remaining reusable across files

### Notes

Runtime on a 200 MB sample falls from 14.4s to 7.5s on the standard library
alone, and to 2.2s with numpy installed. numpy is optional and listed
commented out in `requirements.txt`. Hashes and entropy are identical across
all three configurations.

`begin` must reset everything `feed` accumulates. Reusing one extractor
instance across a directory scan is the normal case, not the exception, and
there is a test for it.

A stream extractor must keep its own memory bounded. Buffering the chunks it
is handed would reintroduce exactly the problem this release removes.

ssdeep remains the one component that reads the file a second time, because
its API takes a path rather than bytes. This is stated rather than hidden,
and it is one reason ssdeep stays optional.
