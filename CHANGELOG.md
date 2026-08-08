# Changelog

## Version 0.1.0

Initial release.

### Added

- Command line interface
- Extraction engine
- Cryptographic hashing with streaming reads
- Format identification from magic bytes
- Whole-file and windowed entropy analysis
- Extension mismatch detection
- Report schema with severity scoring
- Configuration-driven thresholds
- Synthetic sample generation
- Test suite

### Notes

This release performs static analysis only. Samples are never executed.

Format identification is header-based and uses no external dependencies.
Optional dependencies for PE parsing, YARA and classification are listed but
commented out in `requirements.txt` until the versions that need them.
