# certctl Admin Runbook

This runbook is for operators managing `certctl` in day-to-day use.

Keep it simple:

- protect the SQLite database and backup files
- keep CA key passwords out of shell history when possible
- prefer `env:` or `file:` secret references
- run `certctl doctor` regularly
- back up before major lifecycle changes

## 1. First-time setup

Create the private PKI:

```bash
certctl create-root-ca \
  --name corp-root \
  --common-name "Corp Root CA" \
  --storage-password env:CERTCTL_STORAGE_PASSWORD

certctl create-intermediate-ca \
  --root-name corp-root \
  --name corp-issuing \
  --common-name "Corp Issuing CA" \
  --parent-key-password env:CERTCTL_STORAGE_PASSWORD \
  --key-password env:CERTCTL_ICA_PASSWORD
```

Use these defaults in later commands to keep operator workflows shorter:

```bash
certctl --default-root-ca corp-root --default-intermediate-ca corp-issuing doctor --warn-days 0
```

## 2. Routine health checks

Use `doctor` for structure and expiry checks:

```bash
certctl doctor
certctl doctor --warn-days 14
certctl doctor --warn-days 0 --json
```

`doctor` also checks enabled JWT/OIDC issuers for broken discovery or JWKS connectivity, flags disabled issuers that are still referenced by enabled authz bindings, warns on bindings that still point at unknown issuers, highlights unused or unreachable issuer relationships, and highlights overly broad or duplicate/conflicting authz bindings and subject auto-approval rules.

To review locally tracked JWT subjects:

```bash
certctl list-subjects --all
certctl list-subjects --status pending
certctl list-subjects --local-group employees
certctl create-subject-auto-approval --name google-employees --issuer https://accounts.google.com --email-domain example.com --local-group employees
certctl list-subject-auto-approvals
certctl approve-subject --issuer https://accounts.google.com --subject user-123 --local-group viewers
certctl update-subject --issuer https://accounts.google.com --subject user-123 --status active --local-group employees
certctl disable-subject --issuer https://sso.example.com/realms/certctl --subject user-123
certctl enable-subject --issuer https://sso.example.com/realms/certctl --subject user-123
```

For common public identity providers, start from a preset:

```bash
certctl list-auth-provider-presets
certctl create-auth-issuer --preset google --name google-login --audience <client-id>
certctl create-auth-issuer --preset microsoft-tenant --name microsoft-login --issuer https://login.microsoftonline.com/<tenant>/v2.0 --audience <app-id>
certctl create-auth-issuer --preset keycloak --name keycloak-login --issuer https://sso.example.com/realms/certctl --audience certctl
certctl create-auth-issuer --preset aws-cognito --name cognito-login --issuer https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example --audience <app-client-id>
```

Recommended routine:

- `--warn-days 30` for normal operations
- `--warn-days 14` before maintenance windows or releases
- `--warn-days 0` when you only want invariant checks

## 3. Issue a private certificate

```bash
certctl issue-private-cert \
  --intermediate-name corp-issuing \
  --common-name api.internal.example \
  --domain api.internal.example \
  --parent-key-password env:CERTCTL_ICA_PASSWORD \
  --key-password env:CERTCTL_LEAF_PASSWORD
```

Check the result:

```bash
certctl query-private-cert --common-name api.internal.example
certctl history --kind private --name api.internal.example
```

## 4. Submit and approve CSRs

Requester side:

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout server.key \
  -out server.csr \
  -subj "/CN=api.internal.example" \
  -addext "subjectAltName=DNS:api.internal.example,DNS:api"
```

```bash
certctl submit-csr \
  --kind private \
  --csr-file server.csr \
  --requester-name "Jane Doe" \
  --requester-email jane@example.com \
  --phone-number "+1-555-0100" \
  --organization Uvoo \
  --department Platform \
  --requested-ca-name corp-issuing
```

Admin side:

```bash
certctl list-csr-requests
certctl list-csr-requests --id <request-id> --json
```

Approve:

```bash
certctl approve-csr \
  --id <request-id> \
  --intermediate-name corp-issuing \
  --parent-key-password env:CERTCTL_ICA_PASSWORD
```

Reject:

```bash
certctl reject-csr --id <request-id> --reason "unable to verify requester"
```

## 5. Run the built-in HTTPS server

For local testing, generate a temporary cert:

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout server.key \
  -out server.crt \
  -subj "/CN=localhost"
```

Serve over HTTPS:

```bash
certctl serve-certs \
  --listen :8443 \
  --tls-cert-file server.crt \
  --tls-key-file server.key \
  --csr-submit-password env:CERTCTL_CSR_SUBMIT_PASSWORD
```

Allow local testing plus private networks:

```bash
certctl serve-certs \
  --listen :8443 \
  --tls-cert-file server.crt \
  --tls-key-file server.key \
  --csr-submit-password env:CERTCTL_CSR_SUBMIT_PASSWORD \
  --nacl 127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7
```

Enable the remote admin API and Prometheus metrics:

```bash
certctl serve-certs \
  --listen :8443 \
  --tls-cert-file server.crt \
  --tls-key-file server.key \
  --csr-submit-password env:CERTCTL_CSR_SUBMIT_PASSWORD \
  --admin-username admin \
  --admin-password env:CERTCTL_ADMIN_PASSWORD \
  --metrics

certctl serve-certs \
  --listen :8443 \
  --tls-cert-file server.crt \
  --tls-key-file server.key \
  --csr-submit-password env:CERTCTL_CSR_SUBMIT_PASSWORD \
  --admin-username admin \
  --admin-password env:CERTCTL_ADMIN_PASSWORD \
  --metrics \
  --metrics-username metrics \
  --metrics-password env:CERTCTL_METRICS_PASSWORD
```

Useful remote checks:

```bash
curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  https://certctl.example.com:8443/admin/v1/doctor

curl -sS -u admin:"$CERTCTL_ADMIN_PASSWORD" \
  https://certctl.example.com:8443/metrics

curl -sS -u metrics:"$CERTCTL_METRICS_PASSWORD" \
  https://certctl.example.com:8443/metrics
```

Notes:

- the default NACL allows private IPv4 ranges and IPv6 ULA space
- loopback is not included by default
- if you run behind a reverse proxy, allow the proxy source address
- the built-in NACL checks the TCP client address, not forwarded-for headers
- `/metrics` can use its own Basic auth credentials with `--metrics-username` and `--metrics-password`
- `/metrics` otherwise accepts the admin Basic auth or bearer auth
- `/metrics` includes low-cardinality counts for CSR backlog, pickup-ready requests, configured auth issuers and bindings, auth request outcomes, subject auto-approval rules and matches, and locally tracked JWT subjects
- for local end-to-end testing with Keycloak and the built-in server, use the Docker stack in [`DOCKER_DEV.md`](DOCKER_DEV.md)

## 6. Backup and restore

Create a backup before lifecycle changes:

```bash
certctl backup-db --out certctl-backup.db
```

Restore with guardrails:

```bash
certctl restore-db --from certctl-backup.db --force
```

Recommended practice:

- keep backups outside the working directory
- restrict backup file permissions
- test restore on a non-production copy before relying on it

## 7. Rotation and lifecycle

Rotate a root:

```bash
certctl create-root-ca \
  --name corp-root \
  --common-name "Corp Root CA" \
  --storage-password env:CERTCTL_STORAGE_PASSWORD
```

Rotate an intermediate:

```bash
certctl create-intermediate-ca \
  --root-name corp-root \
  --name corp-issuing \
  --common-name "Corp Issuing CA" \
  --parent-key-password env:CERTCTL_STORAGE_PASSWORD \
  --key-password env:CERTCTL_ICA_PASSWORD
```

Lifecycle commands:

```bash
certctl revoke --kind private --id <cert-id>
certctl retire --kind intermediate --id <ica-id>
certctl promote --kind intermediate --id <ica-id>
certctl history --kind intermediate --name corp-issuing
```

## 8. Public certificate workflow

Issue:

```bash
certctl get \
  --common-name "*.example.com" \
  --sans "*.example.com,example.com" \
  --provider godaddy \
  --email admin@example.com \
  --storage-password env:CERTCTL_STORAGE_PASSWORD \
  --api-user "$GODADDY_API_KEY" \
  --api-key "$GODADDY_API_SECRET"
```

Renew:

```bash
certctl renew --common-name "*.example.com"
```

## 9. Incident checklist

Certificate or CA expiring soon:

- run `certctl doctor --warn-days 14`
- rotate or renew before expiry
- confirm lineage with `history`

Need to recover:

- create a fresh backup of the current DB if possible
- restore from the last known-good backup
- rerun `certctl doctor`

Need to stop new issuance from a CA:

- retire the active CA or rotate to a new generation
- confirm `is_issuing` is no longer set on the old generation

Need to remove access to shared cert data:

- revoke the share
- rotate the share if continued access is still required
