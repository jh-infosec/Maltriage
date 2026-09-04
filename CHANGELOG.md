# Changelog

## Version 0.4 -- a package, and strings

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
  so a module named for its fixtures was the wrong home -- the docstrings had
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
  what that means -- the emitter has not been taught this key yet, not that
  there was nothing to say

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

The capability vocabulary was run over 6725 real files -- 1610 Linux system
binaries and shared objects, 2959 Python standard library source files, and
2156 documentation files -- to find out what it fires on when nothing is
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
about a third of the cost of matching -- the extractor goes from 5.28s to
7.21s with it and to 8.44s without. The cheaper path and the more accurate
one turned out to be the same path, which is not usually how that goes.

What this does not measure is the Windows false positive rate, because these
are not Windows binaries. It measures that the vocabulary does not fire on
things that are not Windows binaries, which is a smaller claim. The real
number is v0.7's job, and it is why nothing here reaches medium.

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
carry it -- and a filename is little better, because a document is often named
after the person it is about. The cost is accepted: a directory scan produces
envelopes that only a hash distinguishes, and correlating one back to a file is
the caller's job, the caller being the party entitled to know the path.

**A name collision worth knowing about.** A maltriage report already has a
field called `validated`, on the certificate, meaning "was this Authenticode
signature verified against a chain" -- always false, because nothing here
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
verbatim -- ANSI escapes and all. The claim that no sample-derived text can
reach a report through this module was therefore true of the two callers
rather than of the function, and one refactor away from being false. It now
raises on a key it did not write.

**A token had a length ceiling, and a ceiling on a token is a hidden substring
match.** `_TOKEN` capped a token at 64 characters, so `j` * 64 followed by
`VirtualAllocEx@16` matched while `j` * 63 followed by the same text did not:
the padding filled exactly one token and left the API name starting the next.
Whether a name was found depended on its offset modulo 64, and the case that
found it was the wrong one -- it is `PreloadLibraryPath` arriving by a
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
could break -- it now drives an ordinal-only import through the real path
instead. And the `CryptUnprotectData` test survived a reordering that tried
the stripped form first, because nothing in the real vocabulary collides with
`cryptunprotectdat`; it now pins the ordering against a vocabulary built to
collide. The `", and N more"` sentence in a capability detail was executed on
every run and asserted nowhere: an off-by-one in it passed the whole suite.

### Known and not fixed

**A wide string can steal the last byte of the string before it.** Where a
narrow string's terminator sits directly against a UTF-16 string, the wide
pattern reaches one byte too far left, because the last printable character of
the ASCII run plus its NUL is itself a valid pair:
`b"more\x00" + "LoadLibraryEx".encode("utf-16-le")` extracts as
`eLoadLibraryEx`. The API name inside it then matches nothing and no cap
fired, so the report looks complete.

It predates this release and belongs to the string scanner rather than to
anything reading from it -- widening the matcher to also try the run without
its first character would be exactly the substring matching the vocabulary
refuses, trading a silent miss for a silent false positive. Recorded in
`architecture.md` and scheduled at v0.5. It reproduces in a single chunk and is
identical at every chunk size, which is why the chunk-independence tests never
saw it.

### Hardened

The strings extractor is the first stream extractor added since v0.1.2, and
the chunk-boundary invariant is the one it broke.

**Results depended on `read_chunk_bytes`.** The carry kept a run only when the
regex had matched and the match reached the end of the buffer -- but a
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
small -- 2441 of them for a 20 MB sample is 80 KB, invisible beside a 1 MB
read chunk -- and because the test that should have caught it compared a
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
  and the CLI, including the one that matters most -- that when the retained
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
path before measuring, and subtract the memory already live -- because
`get_traced_memory` reports the whole process and these tests run after two
hundred others that hold their own fixtures.


## Version 0.3.1 -- ELF

The last unshipped piece of v0.2's design, arriving after v0.3 because that is
when it was built rather than because it belongs there.

No dependency. The header, program header table and section header table are
fixed-layout records that `struct` reads, and there is no equivalent of
pefile's accumulated knowledge of malformed real-world files to buy. The rule
`architecture.md` states is to pay a dependency where the format is genuinely
hostile, not where it is merely binary. So there is no optional import, no
missing-parser error, and it works on a bare checkout -- and every bound is
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
`.shstrtab`, so most names are interior offsets -- `.rela.plt\0` also serves
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

- `e_shentsize = 0` -- one two-byte field -- made the section table read as
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
  segment -- a false medium from a builder whose docstring calls its output
  structurally valid
- `e_shstrndx` pointing at a NOBITS section decoded names out of whatever sat
  at offset zero, which is the ELF header, and reported `\x7fELF\x02\x01\x01`
  as a section name
- SHN_XINDEX -- the legal way to have more sections than `e_shnum` can express
  -- was read literally as no section table at all, which is a medium

### Notes

Before this release no ELF test fed the extractor a malformed file, and
fourteen of its seventeen bounds could be deleted with the suite still green.
There is now a hostile-input section modelled on the PE one.

The finding set was measured against 1201 real binaries from `/usr/bin`,
`/usr/sbin` and `/usr/lib`: **zero mediums**, `runpath_set` on 50 and
`nonstandard_section_name` on 16. `GATE_SEVERITY` is medium, so a false
medium is a false CI failure, and a finding set nobody has pointed at real
software is a finding set nobody has tested.


## Version 0.3 -- pattern matching

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
  string whose condition reads that string's count, offset or length -- `#a`
  is one of the commonest idioms in public rule sets -- so `yara_max_scan_bytes`
  bounds the one thing the extractor genuinely controls
- Under fast matching a string reported `count: 1` and `truncated: false` for
  seven hundred thousand hits. `truncated` is the field whose whole job is to
  say nothing was left out. Strings now carry `complete`
- `include` reached the whole filesystem. `include "/etc/passwd"` was opened
  and parsed, and YARA quotes offending tokens back in its syntax errors.
  Now off unless `yara_allow_includes` says otherwise
- The compile cache was keyed on nothing, so a reused extractor answered with
  whichever rule set it saw first while reporting the files it had been asked
  for -- a stale result presented as a current one. It now keys on the rule
  files and on `yara_allow_includes`, because both are inputs to the compile
- An unusable `yara_rule_paths` entry vanished silently: a nonexistent path, a
  `Path` where a string was expected, a device file, an unreadable directory.
  The report claimed a full run while the configured rules never executed
- A dangling symlink or a directory named `sub.yar` inside a rules directory
  disappeared the same way
- Naming the bundled directory in `yara_rule_paths` -- a natural thing to
  write, since configured paths add to the bundled set -- emitted every match
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


## Version 0.2 -- executable structure

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
