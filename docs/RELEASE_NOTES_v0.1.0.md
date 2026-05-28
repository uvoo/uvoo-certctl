# uvoocertctl v0.1.0

Initial public release of `uvoocertctl`.

## Highlights

- Immutable rotation for public and private leaf certificates so new issuance supersedes older rows instead of overwriting them.
- Private root and intermediate CA generations with separate lifecycle, trust, and issuing state.
- Pure-Go SQLite storage, which removes the cgo/toolchain requirement for normal builds.
- Operational commands for history, revoke, retire, promote, audit listing, backup, restore, and database health checks.
- JSON output on read, list, and main write paths for easier automation.
- Cross-platform release builds for Linux, macOS, and Windows with embedded version metadata.

## Operator-focused improvements

- One active public or private leaf certificate per common name.
- CA selection by policy and logical name instead of “latest row wins”.
- Password flags support raw values plus `env:` and `file:` references.
- SQLite defaults hardened with WAL mode, foreign keys, and a busy timeout.
- Release archives include checksums plus bundled README, changelog, and install guide files.

## Included artifacts

- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`
- `windows/arm64`

## Upgrade notes

- Public and private certificate rotation now preserves history instead of updating rows in place.
- `renew` now uses `--common-name`; the older `--common_name` form remains as a deprecated compatibility alias.
- Existing SQLite databases are migrated automatically on open.
