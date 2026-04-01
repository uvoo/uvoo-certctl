# certctl

A Cobra-based refactor of the original single-file ACME utility.

- Latest release notes: [`docs/RELEASE_NOTES_v0.3.0.md`](docs/RELEASE_NOTES_v0.3.0.md)
- Initial release notes: [`docs/RELEASE_NOTES_v0.1.0.md`](docs/RELEASE_NOTES_v0.1.0.md)
- Install guide: [`docs/INSTALL.md`](docs/INSTALL.md)
- CSR guide: [`docs/CSR_REQUESTS.md`](docs/CSR_REQUESTS.md)
- Admin runbook: [`docs/RUNBOOK.md`](docs/RUNBOOK.md)
- Auth/authz design: [`docs/AUTHZ_DESIGN.md`](docs/AUTHZ_DESIGN.md)
- Docker dev guide: [`docs/DOCKER_DEV.md`](docs/DOCKER_DEV.md)
- Prometheus watchdog guide: [`docs/PROMALERT.md`](docs/PROMALERT.md)
- Release process: [`docs/RELEASING.md`](docs/RELEASING.md)

## What changed

- Split the CLI into subcommands.
- Added `check-precursors` for provider auth, zone access, and public DNS checks.
- Added `create-record` and `delete-record` for explicit DNS record management.
- Preserved encrypted SQLite storage for certificates and keys.
- Switched SQLite access to a pure-Go driver, so builds no longer require cgo or a local C toolchain.
- Expanded stored metadata with issuer and validity timestamps.
- Public and private certificates now rotate immutably instead of being overwritten.
- Private root and intermediate CAs now keep logical generations with trust and issuing state split apart.

## Rotation model

- Public and private leaf certificates keep one active row per `common_name`; new issuance supersedes the previous active row.
- Private root and intermediate CAs keep immutable generations under the same logical `--name`.
- CAs use `status`, `is_trusted`, and `is_issuing` separately so rollover can keep older chains trusted without allowing new issuance from them.
- Active lookups resolve by policy instead of “latest updated row”.

## Commands

### Preflight checks

```bash
go run . check-precursors \
  --provider namecheap \
  --domain '*.example.com' \
  --api-user "$NAMECHEAP_API_USER" \
  --api-key "$NAMECHEAP_API_KEY" \
  --client-ip "$NAMECHEAP_CLIENT_IP" \
  --write-test
```

### Create a TXT record

```bash
go run . create-record \
  --provider godaddy \
  --domain example.com \
  --name _acme-challenge \
  --type TXT \
  --value hello \
  --ttl 60
```

### Delete a TXT record

```bash
go run . delete-record \
  --provider godaddy \
  --domain example.com \
  --name _acme-challenge \
  --type TXT \
  --value hello
```

### Obtain and store a certificate

```bash
go run . get \
  --common-name '*.example.com' \
  --sans '*.example.com,example.com' \
  --provider godaddy \
  --email admin@example.com \
  --storage-password 'change-me' \
  --api-user "$GODADDY_API_KEY" \
  --api-key "$GODADDY_API_SECRET"
```

### Read a stored certificate

```bash
go run . query \
  --san '*.example.com' \
  --password 'change-me' \
  --show-key
```

### Create or rotate a private root CA

```bash
go run . create-root-ca \
  --name internal-root \
  --common-name 'Internal Root CA' \
  --storage-password 'change-me'
```

### Create or rotate a private intermediate CA

```bash
go run . create-intermediate-ca \
  --root-name internal-root \
  --name internal-ica \
  --common-name 'Internal Issuing CA' \
  --parent-key-password 'change-me' \
  --key-password 'change-me-too'
```

### Issue a private leaf certificate from the active ICA generation

```bash
go run . issue-private-cert \
  --intermediate-name internal-ica \
  --common-name api.internal.example \
  --domain api.internal.example \
  --parent-key-password 'change-me-too' \
  --key-password 'leaf-password'
```

## Notes

- For GoDaddy, `--api-user` is the API key and `--api-key` is the API secret.
- For Namecheap, `--api-user` is the API username and `--api-key` is the API key.
- Namecheap requires the client IP to be whitelisted before API calls succeed.
- Namecheap record updates work by reading all DNS hosts and writing the full set back.
- `get` runs precursor checks by default. Use `--skip-checks` only when you are sure provider access and DNS are already correct.
- The ACME flow still uses lego for DNS-01 challenge presentation.
- Password-like flags accept raw values, `env:VARNAME`, or `file:/path/to/secret`.
- `--default-root-ca` and `--default-intermediate-ca` can be set once to avoid repeating issuer names on every command.
- `serve-certs` defaults its `--nacl` allowlist to private IPv4 and IPv6 client networks. Add loopback or public ranges explicitly when needed.

## Operations

Inspect lifecycle state:

```bash
go run . list-root-cas --all
go run . list-intermediate-cas --all
go run . history --kind private --name api.internal.example
```

Manage lifecycle:

```bash
go run . revoke --kind private --id <cert-id>
go run . retire --kind intermediate --id <ica-id>
go run . promote --kind intermediate --id <ica-id>
go run . list-audit --limit 50
```

Queue and approve CSRs:

```bash
go run . submit-csr --kind private --csr-file server.csr --requester-name 'Jane Doe'
go run . list-csr-requests
go run . approve-csr --id <request-id> --intermediate-name internal-ica --parent-key-password env:CERTCTL_PARENT_KEY_PASSWORD
go run . reject-csr --id <request-id> --reason "unable to verify requester"
```

Configure JWT/OIDC auth for the admin API:

```bash
go run . create-auth-issuer \
  --name keycloak-local \
  --issuer https://sso.example.com/realms/certctl \
  --audience certctl \
  --required-claim azp=certctl-cli \
  --discovery-url https://sso.example.com/realms/certctl/.well-known/openid-configuration \
  --roles-claim realm_access.roles

go run . create-authz-binding \
  --principal 'role:https://sso.example.com/realms/certctl:certctl_admin' \
  --permission doctor.read

go run . list-auth-provider-presets
go run . create-auth-issuer --preset google --name google-login --audience <client-id>
go run . create-auth-issuer --preset microsoft-tenant --name entra-login --issuer https://login.microsoftonline.com/<tenant>/v2.0 --audience <app-id>
go run . create-auth-issuer --preset keycloak --name keycloak-login --issuer https://sso.example.com/realms/certctl --audience certctl
go run . create-auth-issuer --preset aws-cognito --name cognito-login --issuer https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example --audience <app-client-id>
go run . list-auth-issuers
go run . check-auth-issuer --issuer https://sso.example.com/realms/certctl
go run . update-auth-issuer --issuer https://sso.example.com/realms/certctl --name keycloak-prod
go run . delete-auth-issuer --issuer https://sso.example.com/realms/certctl
go run . delete-auth-issuer --issuer https://sso.example.com/realms/certctl --force
go run . doctor --auth-only --json
go run . create-subject-auto-approval --name google-employees --issuer https://accounts.google.com --email-domain example.com --local-group employees
go run . list-subject-auto-approvals
go run . list-effective-authz --principal 'role:https://sso.example.com/realms/certctl:certctl_admin'
go run . list-authz-bindings
go run . list-authz-bindings --principal 'role:https://sso.example.com/realms/certctl:certctl_admin'
go run . list-subjects --all
go run . list-subjects --status pending
go run . list-subjects --local-group employees
go run . approve-subject --issuer https://accounts.google.com --subject user-123 --local-group viewers
go run . update-subject --issuer https://accounts.google.com --subject user-123 --status active --local-group employees
go run . disable-subject --issuer https://sso.example.com/realms/certctl --subject user-123
go run . enable-subject --issuer https://sso.example.com/realms/certctl --subject user-123
go run . update-authz-binding --id <binding-id> --permission csr.approve
go run . update-authz-binding --match-principal 'role:https://sso.example.com/realms/certctl:certctl_admin' --match-permission doctor.read --permission metrics.read
go run . delete-authz-binding --principal 'role:https://sso.example.com/realms/certctl:certctl_admin' --permission doctor.read
go run . delete-authz-binding --id <binding-id>
go run . explain-authz --bearer-token env:CERTCTL_BEARER_TOKEN
go run . disable-auth-issuer --issuer https://sso.example.com/realms/certctl
go run . enable-auth-issuer --issuer https://sso.example.com/realms/certctl
```

Serve certificate shares and CSR pickup/submission:

```bash
go run . serve-certs --listen :8080
go run . serve-certs --listen :8443 --tls-cert-file /etc/certctl/tls/server.crt --tls-key-file /etc/certctl/tls/server.key
go run . serve-certs --listen :8443 --tls-cert-file /etc/certctl/tls/server.crt --tls-key-file /etc/certctl/tls/server.key --nacl 127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7
go run . serve-certs --listen :8443 --tls-cert-file /etc/certctl/tls/server.crt --tls-key-file /etc/certctl/tls/server.key --admin-username admin --admin-password env:CERTCTL_ADMIN_PASSWORD --metrics
go run . serve-certs --listen :8443 --tls-cert-file /etc/certctl/tls/server.crt --tls-key-file /etc/certctl/tls/server.key --admin-username admin --admin-password env:CERTCTL_ADMIN_PASSWORD --metrics --metrics-username metrics --metrics-password env:CERTCTL_METRICS_PASSWORD
```

With `--admin-username` and `--admin-password`, the built-in server also exposes a small authenticated JSON admin API under `/admin/v1` for remote `doctor`, CSR queue, subject, subject auto-approval, and auth issuer actions. `--metrics` enables a Prometheus-style `/metrics` endpoint. If `--metrics-username` and `--metrics-password` are set, `/metrics` uses that dedicated Basic auth pair; otherwise it accepts the admin Basic auth or bearer auth. The metrics output includes certificate and CA status totals, CSR queue totals, pending and pickup-ready CSR counters, share totals, auth issuer/binding counts, auth issuer binding coverage, authz binding permission and principal-kind summaries, risky authz and subject-auto-approval counts, auth request outcomes, subject auto-approval rule matches, pending-subject counts, and locally tracked JWT subject counts.

Useful remote auth/admin paths include `/admin/v1/doctor/auth`, `/admin/v1/effective-authz`, `/admin/v1/auth-provider-presets`, `/admin/v1/auth-issuers`, and `/admin/v1/authz-bindings`. The metrics output also includes `certctl_auth_issuers_connectivity_status_total` from cached issuer probe results and `certctl_doctor_findings_total` for low-cardinality alerting by severity and check.

The admin API can also use bearer tokens from trusted JWT/OIDC issuers configured in the local database. The auth model and claim mapping are documented in [`docs/AUTHZ_DESIGN.md`](docs/AUTHZ_DESIGN.md).

New JWT subjects are tracked locally on first successful token verification and begin in `pending` state until an operator approves them, unless a matching subject auto-approval rule activates them and assigns local roles or groups.

`explain-authz` and `list-effective-authz --bearer-token ...` now also show local subject status, matching subject auto-approval rules, and the predicted local roles/groups that would apply to that token.

Remote admin examples:

```bash
curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  https://certctl.example.com:8443/admin/v1/subjects?status=pending

curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  -H 'Content-Type: application/json' \
  -X POST https://certctl.example.com:8443/admin/v1/subjects/approve \
  -d '{"issuer":"https://accounts.google.com","subject":"user-123","local_groups":["viewers"]}'

curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  https://certctl.example.com:8443/admin/v1/subjects/<subject-id>

curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  -H 'Content-Type: application/json' \
  -X PUT https://certctl.example.com:8443/admin/v1/subjects/<subject-id> \
  -d '{"status":"active","local_groups":["employees"]}'

curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  -X DELETE https://certctl.example.com:8443/admin/v1/subjects/<subject-id>

curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  -H 'Content-Type: application/json' \
  -X PUT https://certctl.example.com:8443/admin/v1/subject-auto-approvals/google-employees \
  -d '{"issuer":"https://accounts.google.com","email_domain":"example.com","local_groups":["employees"]}'

curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  https://certctl.example.com:8443/admin/v1/auth-provider-presets

curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  https://certctl.example.com:8443/admin/v1/auth-provider-presets/keycloak

curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  -H 'Content-Type: application/json' \
  -X POST https://certctl.example.com:8443/admin/v1/auth-issuers \
  -d '{"preset":"keycloak","name":"keycloak-dev","issuer":"https://sso.example.com/realms/certctl","audiences":["certctl"],"required_claims":{"azp":"certctl"},"discovery_url":"https://sso.example.com/realms/certctl/.well-known/openid-configuration"}'

curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  -H 'Content-Type: application/json' \
  -X PUT https://certctl.example.com:8443/admin/v1/auth-issuers/keycloak-dev \
  -d '{"name":"keycloak-prod","enabled":true}'

curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  -X DELETE 'https://certctl.example.com:8443/admin/v1/auth-issuers/keycloak-prod?force=true'

curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  -H 'Content-Type: application/json' \
  -X POST https://certctl.example.com:8443/admin/v1/authz-bindings \
  -d '{"principal":"role:https://sso.example.com/realms/certctl:certctl_admin","permission":"subject.read","resource_kind":"subject","resource_ref":"*"}'

curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  -H 'Content-Type: application/json' \
  -X PUT https://certctl.example.com:8443/admin/v1/authz-bindings/<binding-id> \
  -d '{"permission":"subject.update","enabled":true}'

curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  -X DELETE https://certctl.example.com:8443/admin/v1/authz-bindings/<binding-id>

curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  https://certctl.example.com:8443/admin/v1/effective-authz

curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  https://certctl.example.com:8443/admin/v1/doctor/auth

curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  https://certctl.example.com:8443/admin/v1/auth-issuers?probe=true
```

For local Docker-based Keycloak and `certctl` smoke testing, including private CSR approval and optional public provider checks, see [`docs/DOCKER_DEV.md`](docs/DOCKER_DEV.md).

Export safe metadata or a DB backup:

```bash
go run . export-metadata --out certctl-metadata.json
go run . backup-db --out certctl-backup.db
go run . restore-db --from certctl-backup.db --force
```

Mutating commands support `--json` for automation, for example:

```bash
go run . create-root-ca --name internal-root --common-name 'Internal Root CA' --json
go run . issue-private-cert --intermediate-name internal-ica --common-name api.internal.example --json
go run . share-cert --kind private --name api.internal.example --mode cert --share-password env:CERTCTL_SHARE_PASSWORD --json
```

Health and release information:

```bash
go run . doctor
go run . doctor --warn-days 14
go run . doctor --warn-days 0 --json
go run . version
go run . version --json
```

`doctor` also checks enabled JWT/OIDC issuers for broken discovery or JWKS connectivity, warns when disabled issuers are still referenced by enabled authz bindings, flags bindings that point at unknown issuers, warns on enabled issuers with no bindings or only risky subject auto-approval coverage, warns when bindings depend on an issuer that is currently unreachable, and warns on overly broad or duplicate/conflicting authz bindings and overly broad subject auto-approval rules.

Renew a stored public certificate:

```bash
go run . renew --common-name '*.example.com'
go run . renew --common-name '*.example.com' --force --json
```

## Build

Build a local binary for the current machine:

```bash
go build -o certctl .
```

If your Go executable is not the default `go` on `PATH`, set `GO_BIN`, for example:

```bash
GO_BIN=/snap/bin/go ./scripts/build-release.sh
```

If you are in a restricted environment, you can also point the Go build cache at a writable directory:

```bash
GOCACHE=/tmp/certctl-gocache ./scripts/build-release.sh
```

Install it into `/usr/local/bin`:

```bash
./scripts/build-and-cp-to-bin.sh
```

Build common release binaries for Linux, macOS, and Windows:

```bash
./scripts/build-release.sh
```

Build a versioned set of release archives:

```bash
VERSION=v0.2.0 ./scripts/build-release.sh
```

The release script stamps `version`, `commit`, and `date` into the binary, bundles the docs into each archive, and writes both per-archive checksums and a `checksums.txt` manifest.

Build only specific targets:

```bash
./scripts/build-release.sh linux/amd64 darwin/arm64 windows/amd64
```

For binary install and checksum verification steps, see [`docs/INSTALL.md`](docs/INSTALL.md).

For end-user CSR submission with `openssl` and `curl`, see [`docs/CSR_REQUESTS.md`](docs/CSR_REQUESTS.md).

For day-to-day operations, rotation, restore, and approval procedures, see [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

For tagging, signing, and GitHub draft release creation, see [`docs/RELEASING.md`](docs/RELEASING.md).

## Release checklist

- Run `go run . doctor` before shipping changes.
- Run `go test -mod=mod ./...` to cover storage and CLI smoke paths.
- Build stamped release artifacts with `VERSION=vX.Y.Z ./scripts/build-release.sh`.
- Optionally sign `dist/checksums.txt` with `./scripts/sign-release-checksums.sh`.
- Create the GitHub draft release with `./scripts/draft-release.sh vX.Y.Z --notes-file docs/RELEASE_NOTES_vX.Y.Z.md`.
- Keep the tag, release notes, and built artifact version aligned.
