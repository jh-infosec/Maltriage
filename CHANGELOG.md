# Changelog

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
