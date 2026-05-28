# Changelog

## v0.4.0 - 2026-04-01

- Added subject auto-approval rules for JWT/OIDC users, with issuer-scoped matching on email domain, upstream roles, and upstream groups plus local role/group assignment.
- Added local subject management improvements including `update-subject`, subject filters by local role/group, and richer auth debugging output for bearer tokens.
- Expanded built-in auth provider presets with `keycloak`, `microsoft-tenant`, and `aws-cognito`.
- Added dedicated optional Basic auth credentials for `/metrics` separate from the admin API credentials.
- Expanded auth observability with auth outcome counters, subject auto-approval match counters, pending-subject metrics, and richer `explain-authz` and `list-effective-authz` previews.
- Updated the Docker Keycloak smoke stack to exercise first-login auto-approval and improved manual debugging ergonomics with `--skip-cleanup` and `--only-cleanup`.

## v0.1.0 - 2026-03-30

Initial tagged release of `uvoocertctl`.

- Added immutable rotation for public and private leaf certificates with supersede lineage.
- Added private root and intermediate CA generations with separate lifecycle, trust, and issuing state.
- Switched SQLite storage to a pure-Go driver for simpler cross-platform builds.
- Added lifecycle and operations commands including `history`, `revoke`, `retire`, `promote`, `backup-db`, `restore-db`, `doctor`, `list-audit`, and `version`.
- Added JSON output for read, list, and main mutating commands to support automation.
- Added release scripts for Linux, macOS, and Windows artifacts with embedded version metadata.
