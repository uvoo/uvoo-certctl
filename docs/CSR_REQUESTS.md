# CSR Requests

`uvoo-certctl` can queue both public and private CSRs for later approval.

The key stays on the requester host. After approval, the issued certificate is stored in `uvoo-certctl`, but the private key is not.

## Generate a CSR with OpenSSL

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout server.key \
  -out server.csr \
  -subj "/CN=api.internal.example" \
  -addext "subjectAltName=DNS:api.internal.example,DNS:api"
```

## Submit with the CLI

```bash
uvoo-certctl submit-csr \
  --kind private \
  --csr-file server.csr \
  --requester-name "Jane Doe" \
  --requester-email jane@example.com \
  --phone-number "+1-555-0100" \
  --organization Uvoo \
  --department Platform \
  --requested-ca-name corp-issuing
```

## Serve submission

Start the built-in server with a submission password:

```bash
uvoo-certctl serve-certs \
  --listen :8080 \
  --csr-submit-password env:CERTCTL_CSR_SUBMIT_PASSWORD
```

Optional hardening flags:

```bash
uvoo-certctl serve-certs \
  --listen :8080 \
  --csr-submit-password env:CERTCTL_CSR_SUBMIT_PASSWORD \
  --csr-max-body-bytes 1048576 \
  --csr-min-submit-interval 2s
```

Enable HTTPS directly in the Go server:

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout server.key \
  -out server.crt \
  -subj "/CN=localhost"
```

```bash
uvoo-certctl serve-certs \
  --listen :8443 \
  --tls-cert-file server.crt \
  --tls-key-file server.key \
  --csr-submit-password env:CERTCTL_CSR_SUBMIT_PASSWORD
```

Restrict clients with a network ACL. `--nacl` accepts both IPv4 and IPv6 CIDRs. By default, `serve-certs` allows RFC1918 IPv4 space plus IPv6 ULA space (`fc00::/7`). To allow local loopback access for testing, override `--nacl` explicitly:

```bash
uvoo-certctl serve-certs \
  --listen :8443 \
  --tls-cert-file /etc/uvoo-certctl/tls/server.crt \
  --tls-key-file /etc/uvoo-certctl/tls/server.key \
  --csr-submit-password env:CERTCTL_CSR_SUBMIT_PASSWORD \
  --nacl 127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7
```

Submit from another host with `curl`:

```bash
curl -sS -X POST https://uvoo-certctl.example.com:8443/csr-requests \
  -F kind=private \
  -F submit_password="$CERTCTL_CSR_SUBMIT_PASSWORD" \
  -F requester_name="Jane Doe" \
  -F requester_email=jane@example.com \
  -F phone_number="+1-555-0100" \
  -F organization=Uvoo \
  -F department=Platform \
  -F requested_ca_name=corp-issuing \
  -F csr=@server.csr
```

The response includes:

- `id`: the queued request id
- `pickup_token`: a token the requester can use to poll for status and fetch the issued certificate

Poll for status:

```bash
curl -sS "https://uvoo-certctl.example.com:8443/csr-requests/<id>?pickup_token=<pickup-token>"
```

## Admin review and approval

List pending requests:

```bash
uvoo-certctl list-csr-requests
uvoo-certctl list-csr-requests --all
uvoo-certctl list-csr-requests --id <request-id> --json
```

Approve a private CSR:

```bash
uvoo-certctl approve-csr \
  --id <request-id> \
  --intermediate-name corp-issuing \
  --parent-key-password env:CERTCTL_PARENT_KEY_PASSWORD
```

Approve with JSON output for automation:

```bash
uvoo-certctl approve-csr \
  --id <request-id> \
  --intermediate-name corp-issuing \
  --parent-key-password env:CERTCTL_PARENT_KEY_PASSWORD \
  --json
```

Approve a public CSR:

```bash
uvoo-certctl approve-csr \
  --id <request-id> \
  --provider godaddy \
  --api-user "$GODADDY_API_KEY" \
  --api-key "$GODADDY_API_SECRET" \
  --email admin@example.com
```

Reject a CSR:

```bash
uvoo-certctl reject-csr --id <request-id> --reason "unable to verify requester"
```

Review the queue remotely over the built-in admin API:

```bash
curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  https://uvoo-certctl.example.com:8443/admin/v1/csr-requests
```

Approve a private CSR remotely:

```bash
curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  -H 'Content-Type: application/json' \
  -X POST https://uvoo-certctl.example.com:8443/admin/v1/csr-requests/<id>/approve \
  -d '{
    "intermediate_name": "corp-issuing",
    "parent_key_password": "'"$CERTCTL_PARENT_KEY_PASSWORD"'",
    "decision_note": "approved"
  }'
```

The broader operator flow for CSR review, backup, restore, and rotation is in [`RUNBOOK.md`](RUNBOOK.md).

## Notes

- Public CSR approval supports DNS-name CSRs only.
- Private CSR approval supports externally generated keys and leaves the private key on the requester host.
- CSR-backed certificates can be queried and shared as certificates, but `cert_key` sharing and private-key export are intentionally unavailable because the private key is not stored.
- HTTP CSR submission is capped in size and rate-limited per client IP by default.
- `serve-certs` can run over HTTPS when both `--tls-cert-file` and `--tls-key-file` are provided.
- `serve-certs` can expose a Basic-Auth-protected admin API under `/admin/v1` and Prometheus-style metrics at `/metrics`.
- The built-in network ACL accepts both IPv4 and IPv6 CIDRs, checks the TCP client address, and does not trust forwarded-for headers.
