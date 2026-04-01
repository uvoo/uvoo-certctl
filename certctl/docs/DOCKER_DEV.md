# Docker Dev Guide

`certctl` includes a small Docker-based development stack for exercising JWT bearer auth, the built-in server, private CSR approval, and optional public provider checks.

Files:

- `dev/docker/docker-compose.yml`
- `dev/docker/keycloak/certctl-realm.json`
- `scripts/smoke-docker-stack.sh`
- `scripts/smoke-jwt-auth.sh`

The stack runs:

- Keycloak on `http://127.0.0.1:18080` by default
- `certctl serve-certs` on `http://127.0.0.1:18081` by default

Realm defaults:

- realm: `certctl`
- public client: `certctl`
- test user: `alice`
- password: `alicepass`
- realm role: `certctl_admin`

## Start the stack

```bash
docker compose -f dev/docker/docker-compose.yml up -d --build
```

Stop it again with:

```bash
docker compose -f dev/docker/docker-compose.yml down -v
```

## Run the full smoke path

```bash
./scripts/smoke-docker-stack.sh
```

This smoke path:

- builds the `certctl` container image
- starts Keycloak and `certctl`
- configures the trusted issuer and local authz bindings inside the container
- fetches a Keycloak access token
- registers and approves the first pending JWT subject
- calls `/admin/v1/doctor`
- calls `/metrics`
- creates a private root and intermediate CA
- submits a private CSR over HTTP
- approves it over the admin API
- verifies certificate pickup with the requester token

To keep the stack running after the script exits:

```bash
KEEP_STACK=1 ./scripts/smoke-docker-stack.sh
```

If those local ports are already in use, override them:

```bash
KEYCLOAK_HOST_PORT=28080 CERTCTL_HOST_PORT=28081 ./scripts/smoke-docker-stack.sh
```

## Auth-only compatibility smoke

If you only want the earlier JWT/admin check without the private CA flow:

```bash
./scripts/smoke-jwt-auth.sh
```

## Optional public provider smoke

Public provider checks stay off by default so normal local and CI runs do not add avoidable third-party load.

To enable precursor checks for Namecheap:

```bash
SMOKE_PUBLIC_CERT=1 \
PUBLIC_DOMAIN='example.com' \
NAMECHEAP_API_USER="$NAMECHEAP_API_USER" \
NAMECHEAP_API_KEY="$NAMECHEAP_API_KEY" \
NAMECHEAP_CLIENT_IP="$NAMECHEAP_CLIENT_IP" \
./scripts/smoke-docker-stack.sh
```

To include the optional TXT write/delete check:

```bash
SMOKE_PUBLIC_CERT=1 \
PUBLIC_WRITE_TEST=1 \
PUBLIC_DOMAIN='example.com' \
NAMECHEAP_API_USER="$NAMECHEAP_API_USER" \
NAMECHEAP_API_KEY="$NAMECHEAP_API_KEY" \
NAMECHEAP_CLIENT_IP="$NAMECHEAP_CLIENT_IP" \
./scripts/smoke-docker-stack.sh
```

To go further and attempt real public issuance, explicitly opt in:

```bash
SMOKE_PUBLIC_CERT=1 \
SMOKE_PUBLIC_CERT_ISSUE=1 \
PUBLIC_DOMAIN='example.com' \
PUBLIC_CERT_COMMON_NAME='*.example.com' \
PUBLIC_CERT_EMAIL='admin@example.com' \
PUBLIC_STORAGE_PASSWORD='ChangeMe123!' \
NAMECHEAP_API_USER="$NAMECHEAP_API_USER" \
NAMECHEAP_API_KEY="$NAMECHEAP_API_KEY" \
NAMECHEAP_CLIENT_IP="$NAMECHEAP_CLIENT_IP" \
./scripts/smoke-docker-stack.sh
```

`SMOKE_PUBLIC_CERT_ISSUE=1` is intentionally separate so provider connectivity checks can be run much more frequently than real ACME issuance.

## Optional GitHub Actions workflow

The repo includes two manual GitHub Actions workflows:

- `.github/workflows/docker-integration.yml` for the normal private/auth integration path, with optional public smoke inputs
- `.github/workflows/docker-public-provider.yml` for explicitly public-provider-focused runs

They reuse `scripts/smoke-docker-stack.sh`. Public runs need the matching repository variables and secrets configured:

- `CERTCTL_PUBLIC_TEST_DOMAIN`
- `CERTCTL_PUBLIC_TEST_COMMON_NAME`
- `CERTCTL_PUBLIC_TEST_EMAIL`
- `CERTCTL_PUBLIC_STORAGE_PASSWORD`
- `NAMECHEAP_API_USER`
- `NAMECHEAP_API_KEY`
- `NAMECHEAP_CLIENT_IP`

## Useful environment variables

- `KEEP_STACK=1` leaves the containers up for manual debugging
- `KEYCLOAK_HOST_PORT` overrides the published Keycloak port
- `CERTCTL_HOST_PORT` overrides the published `certctl` port
- `INTERNAL_ISSUER_URL` overrides the OIDC discovery URL used from inside the `certctl` container
- `SMOKE_PRIVATE_CA=0` skips the private CSR flow
- `SMOKE_PUBLIC_CERT=1` enables public provider precursor checks
- `SMOKE_PUBLIC_CERT_ISSUE=1` attempts a real public certificate issuance
- `PUBLIC_WRITE_TEST=1` enables the provider TXT write/delete precursor check
- `CERTCTL_BASE_URL` overrides the local `certctl` server URL
- `ISSUER_URL` overrides the local Keycloak issuer URL

## Useful follow-up commands

```bash
docker compose -f dev/docker/docker-compose.yml logs -f certctl
docker compose -f dev/docker/docker-compose.yml logs -f keycloak
docker compose -f dev/docker/docker-compose.yml exec certctl certctl --db /data/certs.db list-auth-issuers --all
docker compose -f dev/docker/docker-compose.yml exec certctl certctl --db /data/certs.db list-authz-bindings --all
docker compose -f dev/docker/docker-compose.yml exec certctl certctl --db /data/certs.db doctor --warn-days 0
docker compose -f dev/docker/docker-compose.yml exec certctl certctl --db /data/certs.db list-csr-requests --all
```
