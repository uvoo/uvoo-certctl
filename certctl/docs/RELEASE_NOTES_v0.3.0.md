# certctl v0.3.0

Adds JWT/OIDC admin auth management, local subject approval controls, Docker-based integration smoke testing, and safer release/operator tooling.

## Highlights

- JWT/OIDC issuer trust and local authorization bindings for the built-in admin API.
- Auth operator commands for creating, updating, enabling, disabling, checking, explaining, and deleting trusted issuers and bindings.
- First-seen JWT subjects are now tracked locally and start in `pending` state until explicitly approved.
- Docker-based Keycloak plus `certctl` integration smoke testing for end-to-end bearer auth and CSR approval flows.
- Built-in issuer presets for Google and Microsoft to reduce first-time JWT/OIDC setup work.
- Expanded `doctor` coverage for auth configuration drift, including broken discovery or JWKS checks, unknown issuer references, unused issuers, unreachable issuer dependencies, and overly broad or duplicate authz bindings.
- New effective-permission reporting for principals or bearer tokens with `list-effective-authz`.
- Release automation hardening with a safe `draft-release.sh --dry-run` flow before creating a GitHub draft release.

## Operator-focused improvements

- Admin API bearer auth now uses standard OIDC discovery or JWKS endpoints with local allow-list authorization bindings, while keeping Basic auth as a break-glass path.
- Locally tracked JWT subjects can now be listed, approved, enabled, or disabled without changing the upstream identity provider.
- Subject records can carry local roles and groups, which are merged into the same principal-binding model used for upstream JWT roles and groups.
- `explain-authz` now shows matched issuer details, expected audiences, required claim constraints, derived roles and groups, and clear token verification failures.
- `check-auth-issuer` gives operators a simple read-only way to verify issuer discovery and JWKS connectivity before relying on a provider.
- Auth issuer configuration now supports exact-match required claims in `path=value` form in addition to allowed audiences, without introducing a larger policy language.
- Authz binding operations are easier to use operationally: list, update, and delete flows can now work from exact match fields instead of only opaque IDs.
- `/metrics` now includes low-cardinality counts for auth issuers, authz bindings, locally tracked subjects, pending CSR requests, and pickup-ready CSR requests.
- The Docker dev stack and manual GitHub Actions workflows make it easier to validate private auth flows routinely and public-provider checks only when intentionally requested.

## Included artifacts

- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`
- `windows/arm64`

## Upgrade notes

- Existing SQLite databases continue to migrate automatically on open, including the auth issuer schema for required-claim support.
- Existing SQLite databases now also migrate the local `subjects` registry used for JWT subject approval and local subject status.
- Existing Basic-auth admin flows continue to work; JWT/OIDC bearer auth remains optional and locally configured.
- New JWT subjects will be denied until approved, so first-time bearer-auth users now require an explicit local approval step.
- `doctor` is more opinionated in this release and may now report warnings for broad or stale authz state that older versions would not flag.
- `draft-release.sh --dry-run` is the recommended first step before creating and pushing a real release draft.
