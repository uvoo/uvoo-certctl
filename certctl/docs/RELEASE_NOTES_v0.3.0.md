# certctl v0.3.0

Adds JWT/OIDC admin auth management, stronger authorization diagnostics, and safer release/operator tooling.

## Highlights

- JWT/OIDC issuer trust and local authorization bindings for the built-in admin API.
- Auth operator commands for creating, updating, enabling, disabling, checking, explaining, and deleting trusted issuers and bindings.
- Expanded `doctor` coverage for auth configuration drift, including broken discovery or JWKS checks, unknown issuer references, unused issuers, unreachable issuer dependencies, and overly broad or duplicate authz bindings.
- New effective-permission reporting for principals or bearer tokens with `list-effective-authz`.
- Release automation hardening with a safe `draft-release.sh --dry-run` flow before creating a GitHub draft release.

## Operator-focused improvements

- Admin API bearer auth now uses standard OIDC discovery or JWKS endpoints with local allow-list authorization bindings, while keeping Basic auth as a break-glass path.
- `explain-authz` now shows matched issuer details, expected audiences, required claim constraints, derived roles and groups, and clear token verification failures.
- `check-auth-issuer` gives operators a simple read-only way to verify issuer discovery and JWKS connectivity before relying on a provider.
- Auth issuer configuration now supports exact-match required claims in `path=value` form in addition to allowed audiences, without introducing a larger policy language.
- Authz binding operations are easier to use operationally: list, update, and delete flows can now work from exact match fields instead of only opaque IDs.

## Included artifacts

- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`
- `windows/arm64`

## Upgrade notes

- Existing SQLite databases continue to migrate automatically on open, including the auth issuer schema for required-claim support.
- Existing Basic-auth admin flows continue to work; JWT/OIDC bearer auth remains optional and locally configured.
- `doctor` is more opinionated in this release and may now report warnings for broad or stale authz state that older versions would not flag.
- `draft-release.sh --dry-run` is the recommended first step before creating and pushing a real release draft.
