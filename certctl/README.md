# certctl

A Cobra-based refactor of the original single-file ACME utility.

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

Build a versioned set of release artifacts:

```bash
VERSION=v0.1.0 ./scripts/build-release.sh
```

Build only specific targets:

```bash
./scripts/build-release.sh linux/amd64 darwin/arm64 windows/amd64
```

## Suggested next improvements

- Add `list` and `renew` commands.
- Add structured JSON output.
- Add tests with mocked provider APIs.
- Add support for more DNS providers behind the same interface.
