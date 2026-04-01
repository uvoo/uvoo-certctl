# Auth And Authz Design

This document defines a minimal authentication and authorization design for `certctl`'s built-in HTTP(S) server.

The goal is to support:

- local break-glass Basic auth
- standard OIDC/JWT bearer tokens
- multiple external identity providers without provider-specific code paths
- simple, explicit authorization checks

The design intentionally avoids:

- a large framework
- per-request remote lookups to cloud APIs
- policy languages
- deny rules, inheritance trees, or regex matching

## Principles

1. Keep authentication standard.
Use OIDC discovery and JWKS where possible. Avoid custom token formats.

2. Keep authorization local and explicit.
Map verified identities to local permissions in SQLite.

3. Stay close to RFC 7519.
Use registered claim names where they exist: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`.

4. Prefer exact-match rules.
Exact scopes are easier to audit than patterns.

5. Keep Basic auth as a bootstrap path.
Use it for initial setup and break-glass admin access, not as the long-term multi-user model.

## Recommendation

### Subject identity

Use the JWT `sub` claim as the canonical subject identifier.

That means:

- in tokens: use `sub`
- in Go structs: a field named `Subject` is fine, but it should come from `sub`
- in the database: a column named `subject` is fine, but it should represent the verified `sub`

Do not invent a custom JWT `subject` claim.

### Roles and groups

Do not invent a custom `subject_roles` claim either.

Instead:

- keep `sub` as the user or workload identity
- extract roles and groups from configurable claim paths
- convert them into local principals for authorization

Examples:

- Keycloak: `realm_access.roles`, `groups`
- Azure AD / Entra ID: often `roles` or `groups`
- Google: often only `sub` and profile claims unless extra group mapping is added externally
- Cognito / other providers: usually provider-specific role/group claims

This is why `certctl` should not hardcode a single roles claim name.

## Authentication Model

### 1. Basic auth

Keep the current Basic auth path as a bootstrap and break-glass superadmin.

Recommended behavior:

- existing `--admin-username` and `--admin-password` remain supported
- when Basic auth succeeds, the request is treated as local superadmin
- Basic auth can be disabled later if operators want JWT-only access

This keeps recovery simple and avoids locking out the instance when an IdP is misconfigured.

### 2. JWT bearer auth

Add optional bearer-token auth for the admin API.

Recommended validation:

- verify signature using cached JWKS keys
- verify `iss`
- verify `aud`
- verify `exp`
- verify `nbf` if present
- optionally allow small clock skew

Initial algorithm support should stay small:

- support RSA signing first, especially `RS256`

That covers Keycloak, Azure, Google, and Cognito in the common case without adding much code.

If a real provider later requires ECDSA, add it then.

## Trusted issuer configuration

Do not prepopulate a large provider catalog in SQLite.

Instead, store generic trusted issuer rows and let operators configure the providers they use.

Recommended table:

`auth_issuers`

Suggested columns:

- `id`
- `name`
- `enabled`
- `issuer`
- `audiences_json`
- `discovery_url`
- `jwks_url`
- `subject_claim`
- `username_claim`
- `email_claim`
- `roles_claims_json`
- `groups_claims_json`
- `created_at`
- `updated_at`

Recommended defaults:

- `subject_claim = "sub"`
- `username_claim = "preferred_username"`
- `email_claim = "email"`
- `roles_claims_json = ["roles", "realm_access.roles"]`
- `groups_claims_json = ["groups"]`

Notes:

- if `discovery_url` is present, fetch OpenID discovery and use its `jwks_uri`
- if `jwks_url` is set directly, use it without discovery
- store configuration in SQLite, but keep fetched keys only in memory
- refresh keys periodically and on unknown `kid`

This keeps provider support generic while avoiding code branches for Azure, AWS, Google, Keycloak, Auth0, and others.

### Why URL-based trust is better than preloaded cert blobs

Using discovery or JWKS URLs is the better default because signing keys rotate.

If `certctl` stored provider certs statically, operators would have to keep them current manually. That is more fragile and usually more code overall.

So the default should be:

- trust configured issuer metadata URLs
- cache fetched keys in memory
- allow enable/disable in SQLite

Pinned local certs can be added later only if a real offline/private-issuer case needs them.

## Authorization Model

Keep authz as a local allow-list.

Recommended concept:

- every authenticated request resolves to a set of principals
- principals are matched against local permission bindings
- if a binding matches, the action is allowed

### Principals

Derived principals:

- `sub:<issuer>:<sub>`
- `role:<issuer>:<role>`
- `group:<issuer>:<group>`

Using the issuer in the principal key prevents collisions across providers.

### Permissions

Keep permissions as short explicit strings.

Initial set:

- `doctor.read`
- `metrics.read`
- `csr.submit`
- `csr.read`
- `csr.approve`
- `csr.reject`

Future additions:

- `public_cert.issue`
- `private_cert.issue`
- `public_cert.read`
- `private_cert.read`
- `share.create`
- `ca.create`
- `ca.retire`
- `ca.promote`

### Scope

Start with optional exact-match scope, not patterns.

Recommended fields:

- `resource_kind`
- `resource_ref`

Examples:

- `resource_kind = "csr_request", resource_ref = "*"`
- `resource_kind = "intermediate_ca", resource_ref = "corp-issuing"`
- `resource_kind = "private_cert", resource_ref = "api.internal.example"`

For `certctl`, logical names and common names are usually more stable than row UUIDs, so they are the better first scope key.

Recommended table:

`authz_bindings`

Suggested columns:

- `id`
- `enabled`
- `issuer_id`
- `principal_type`
- `principal_value`
- `permission`
- `resource_kind`
- `resource_ref`
- `created_at`
- `updated_at`

No deny rules in v1.

No regex in v1.

No nested role expansion in v1.

## Route mapping

Initial built-in server mapping:

- `GET /admin/v1/doctor` -> `doctor.read`
- `GET /metrics` -> `metrics.read`
- `POST /admin/v1/csr-requests` -> `csr.submit`
- `GET /admin/v1/csr-requests` -> `csr.read`
- `GET /admin/v1/csr-requests/{id}` -> `csr.read`
- `POST /admin/v1/csr-requests/{id}/approve` -> `csr.approve`
- `POST /admin/v1/csr-requests/{id}/reject` -> `csr.reject`

For later routes, keep the same pattern: one explicit permission per action.

## Claims extraction

Claim handling should stay generic and small.

Recommended normalized identity:

- `Issuer`
- `Subject`
- `Username`
- `Email`
- `Roles []string`
- `Groups []string`
- `RawClaims`

Claim extraction rules:

- `Subject` comes from configured `subject_claim`, default `sub`
- `Username` comes from configured `username_claim`
- `Email` comes from configured `email_claim`
- `Roles` merges values from configured role claim paths
- `Groups` merges values from configured group claim paths

Support dotted claim paths like:

- `realm_access.roles`
- `resource_access.certctl.roles`

That adds flexibility without adding provider-specific code.

## What to reuse from the `go-crud` example

Keep:

- generic trusted issuer config
- OIDC discovery / JWKS verification
- claim normalization into a small internal struct

Do not copy directly:

- the transaction-oriented middleware shape
- storing raw request auth state in database session context
- provider-specific assumptions from the example app

`certctl` does not need SQL session auth context to make route-level decisions, so the simpler route middleware approach is a better fit here.

## Recommended implementation order

### Phase 1

- keep current Basic auth
- add bearer token verification for trusted issuers
- add in-memory principal resolution
- add exact-match permission checks in middleware
- store issuer config and authz bindings in SQLite

### Phase 2

- add CLI commands to manage `auth_issuers`
- add CLI commands to manage `authz_bindings`
- add `doctor` checks for disabled/misconfigured issuers

### Phase 3

- add optional multiple local Basic-auth users if there is a real need
- add more route permissions as the admin API grows

## Development and testing

For local testing, a small Docker Compose stack with Keycloak and `certctl` is worthwhile.

That should stay development-only and should not leak into the main runtime path.

Suggested dev stack:

- `certctl`
- Keycloak with realm import
- optional Prometheus scrape target later

This is useful for CI and local auth testing, but it should remain separate from the main server implementation so the production code stays small.

## Bottom line

The best minimal model is:

- `sub` as the canonical identity
- configurable role/group claim extraction
- generic OIDC discovery or JWKS URL trust
- local allow-list authz bindings
- Basic auth retained as a bootstrap superadmin path

That gives you Azure, AWS/Cognito, Google, Keycloak, and similar providers with one implementation path and without turning `certctl` into an auth framework.
