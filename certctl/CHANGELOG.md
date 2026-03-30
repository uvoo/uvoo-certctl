# Changelog

## v0.1.0 - 2026-03-30

Initial tagged release of `certctl`.

- Added immutable rotation for public and private leaf certificates with supersede lineage.
- Added private root and intermediate CA generations with separate lifecycle, trust, and issuing state.
- Switched SQLite storage to a pure-Go driver for simpler cross-platform builds.
- Added lifecycle and operations commands including `history`, `revoke`, `retire`, `promote`, `backup-db`, `restore-db`, `doctor`, `list-audit`, and `version`.
- Added JSON output for read, list, and main mutating commands to support automation.
- Added release scripts for Linux, macOS, and Windows artifacts with embedded version metadata.
