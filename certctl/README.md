# certctl

A Cobra-based refactor of the original single-file ACME utility.

## What changed

- Split the CLI into subcommands.
- Added `check-precursors` for provider auth, zone access, and public DNS checks.
- Added `create-record` and `delete-record` for explicit DNS record management.
- Preserved encrypted SQLite storage for certificates and keys.
- Expanded stored metadata with issuer and validity timestamps.

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
  --provider godaddy \
  --domain '*.example.com' \
  --email admin@example.com \
  --password 'change-me' \
  --api-user "$GODADDY_API_KEY" \
  --api-key "$GODADDY_API_SECRET"
```

### Read a stored certificate

```bash
go run . query \
  --domain '*.example.com' \
  --password 'change-me' \
  --show-key
```

## Notes

- For GoDaddy, `--api-user` is the API key and `--api-key` is the API secret.
- For Namecheap, `--api-user` is the API username and `--api-key` is the API key.
- Namecheap requires the client IP to be whitelisted before API calls succeed.
- Namecheap record updates work by reading all DNS hosts and writing the full set back.
- `get` runs precursor checks by default. Use `--skip-checks` only when you are sure provider access and DNS are already correct.
- The ACME flow still uses lego for DNS-01 challenge presentation.

## Suggested next improvements

- Add `list` and `renew` commands.
- Add structured JSON output.
- Add tests with mocked provider APIs.
- Add support for more DNS providers behind the same interface.
