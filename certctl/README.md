# certctl

A Cobra-based refactor of the original single-file ACME utility.

- Latest release notes: [`docs/RELEASE_NOTES_v0.2.0.md`](docs/RELEASE_NOTES_v0.2.0.md)
- Initial release notes: [`docs/RELEASE_NOTES_v0.1.0.md`](docs/RELEASE_NOTES_v0.1.0.md)
- Install guide: [`docs/INSTALL.md`](docs/INSTALL.md)
- CSR guide: [`docs/CSR_REQUESTS.md`](docs/CSR_REQUESTS.md)
- Admin runbook: [`docs/RUNBOOK.md`](docs/RUNBOOK.md)
- Auth/authz design: [`docs/AUTHZ_DESIGN.md`](docs/AUTHZ_DESIGN.md)
- Auth dev guide: [`docs/AUTH_DEV.md`](docs/AUTH_DEV.md)
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

go run . list-auth-issuers
go run . check-auth-issuer --issuer https://sso.example.com/realms/certctl
go run . update-auth-issuer --issuer https://sso.example.com/realms/certctl --name keycloak-prod
go run . delete-auth-issuer --issuer https://sso.example.com/realms/certctl
go run . delete-auth-issuer --issuer https://sso.example.com/realms/certctl --force
go run . list-authz-bindings
go run . list-authz-bindings --principal 'role:https://sso.example.com/realms/certctl:certctl_admin'
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
```

With `--admin-username` and `--admin-password`, the built-in server also exposes a small authenticated JSON admin API under `/admin/v1` for remote `doctor` and CSR queue actions. `--metrics` enables a Prometheus-style `/metrics` endpoint, using the same Basic auth when admin auth is enabled.

The admin API can also use bearer tokens from trusted JWT/OIDC issuers configured in the local database. The auth model and claim mapping are documented in [`docs/AUTHZ_DESIGN.md`](docs/AUTHZ_DESIGN.md).

For local Keycloak testing and a one-command bearer-auth smoke path, see [`docs/AUTH_DEV.md`](docs/AUTH_DEV.md).

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

`doctor` also checks enabled JWT/OIDC issuers for broken discovery or JWKS connectivity, warns when disabled issuers are still referenced by enabled authz bindings, flags bindings that point at unknown issuers, and warns on overly broad authz bindings such as wildcard permissions or unscoped mutation permissions.

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
