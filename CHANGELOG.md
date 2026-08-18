# Changelog

## Version 0.1.1

Defect release. No new capability, four fixes and one detection gap closed.

### Fixed

- Files smaller than the entropy window produced no windows at all, so a
  packed payload in a dropper-sized file scored `info`. The window now
  shrinks to fit, aiming for `entropy_target_windows` and never going below
  `entropy_min_window_bytes`
- `hash_chunk_bytes: 0` made every read return empty immediately, so all
  three digests reported the hash of an empty file with no error anywhere.
  Config is now validated and the substitution recorded on the report
- A malformed row in the signature table aborted format identification for
  the whole file. Bad rows are now skipped individually and reported
- `--json` wrote a bare object for one file and an array for several, so a
  consumer had to branch on the shape of its own input. It is always an array
- A missing scan target printed a traceback. It now prints one line and exits
  with a usage code

### Changed

- Entropy is scored as a ratio of what uniformly random data of the same
  length actually reaches, rather than against an absolute bits-per-byte
  figure. A fixed 7.5 threshold is unreachable in a 375-byte window, where
  random data averages 7.42, so shrinking the window alone would not have
  closed the gap
- `entropy_file_threshold` and `entropy_window_threshold` are replaced by
  `entropy_file_ratio` (0.90) and `entropy_window_ratio` (0.94). These
  reproduce the old absolute thresholds at the default 8192-byte window
- `entropy` data gains `overall_ratio`, `window_max_ratio` and
  `window_size_configured`. `window_size` is now the size actually used
- Config is read through validated accessors in `sample_data.py` instead of
  a bare `config.get`. A rejected value falls back to its default and the
  reason is recorded under `config` in `report.errors`
- Exit codes are distinct: 0 clean, 1 findings at or above `GATE_SEVERITY`,
  2 could not run. v0.1.0 conflated the last two
- An empty directory reports that it found nothing instead of printing
  nothing
- An empty file is described as empty rather than reported as having no
  signature match
- `SCHEMA_VERSION` is 1.1

### Added

- `small_dropper.bin` fixture, the packed-stub shape at 3 KB
- A regression test for each defect above
- Tests asserting the entropy reference tracks measured randomness within 3%
  from 128 bytes upward

### Notes

Entropy below roughly 128 bytes is not reported. A sample that short has too
few observations to say anything about 256 possible byte values, so
`window_count` is 0 and no hotspot finding is produced. Reporting nothing is
correct here; a score would be noise.

A ratio can slightly exceed 1.0, since the reference is a statistical
estimate rather than a hard ceiling. Thresholds accept values up to 2.0, and
anything above about 1.01 effectively disables its check.

On 400 real files between 128 bytes and 20 KB, the widened hotspot check
fired 4 times, all on PNGs. A PNG is deflate-compressed data inside a
low-entropy container, which is the shape the check looks for, so these are
correct observations rather than misfires.
