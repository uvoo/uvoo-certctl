# certctl v0.2.0

Adds queued CSR workflows and hardens the built-in certificate server.

## Highlights

- Queued CSR submission and approval for both public and private certificates.
- Native HTTPS support for `serve-certs` with `--tls-cert-file` and `--tls-key-file`.
- Built-in network ACLs for `serve-certs` with IPv4 and IPv6 CIDR support via `--nacl`.
- Server-side hardening with request size limits, client throttling, and explicit HTTP timeouts.

## Operator-focused improvements

- Requesters can generate keys and CSRs on their own hosts and keep private keys off the `certctl` server.
- CSR-backed private certificates are stored without private keys, which blocks accidental key export or `cert_key` sharing.
- CSR requests capture reviewer-friendly metadata such as requester name, email, phone number, organization, department, and notes.
- The built-in server now supports direct HTTPS deployment without requiring a reverse proxy in front.
- The default `serve-certs` network ACL allows private IPv4 ranges plus IPv6 ULA space, and can be overridden with explicit CIDRs when needed.

## Included artifacts

- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`
- `windows/arm64`

## Upgrade notes

- Existing SQLite databases continue to migrate automatically on open.
- `serve-certs` remains usable over plain HTTP by default, but HTTPS is enabled automatically when both `--tls-cert-file` and `--tls-key-file` are provided.
- The built-in network ACL checks the TCP client address directly and does not trust forwarded-for headers.
- For local testing with `serve-certs`, add loopback ranges explicitly if needed, for example `127.0.0.0/8` and `::1/128`.
