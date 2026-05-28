# Auth Dev Guide

`uvoocertctl` includes a small development-only Keycloak stack for exercising JWT bearer auth against the built-in admin API.

Files:

- `dev/docker/docker-compose.yml`
- `dev/docker/keycloak/uvoocertctl-realm.json`
- `scripts/smoke-jwt-auth.sh`
 
Note: the active local stack now lives under `dev/docker/`. `scripts/smoke-jwt-auth.sh` remains as a compatibility wrapper around the fuller Docker smoke.

## Start Keycloak

```bash
docker compose -f dev/docker/docker-compose.yml up -d
```

Keycloak will be available at:

- `http://127.0.0.1:18080`

Realm:

- `uvoocertctl`

Public client:

- `uvoocertctl`

Test user:

- username: `alice`
- password: `alicepass`

Realm role:

- `uvoocertctl_admin`

## Configure uvoocertctl

```bash
uvoocertctl create-auth-issuer \
  --preset keycloak \
  --name keycloak-dev \
  --issuer http://127.0.0.1:18080/realms/uvoocertctl \
  --audience uvoocertctl \
  --required-claim azp=uvoocertctl \
  --discovery-url http://127.0.0.1:18080/realms/uvoocertctl/.well-known/openid-configuration

uvoocertctl create-subject-auto-approval \
  --name keycloak-example-users \
  --issuer http://127.0.0.1:18080/realms/uvoocertctl \
  --email-domain example.com \
  --local-group employees

uvoocertctl create-authz-binding \
  --principal 'local_group:employees' \
  --permission doctor.read

uvoocertctl create-authz-binding \
  --principal 'local_group:employees' \
  --permission metrics.read

uvoocertctl list-auth-issuers --all
uvoocertctl list-authz-bindings --all
```

## Run the built-in server

```bash
uvoocertctl serve-certs \
  --listen 127.0.0.1:18081 \
  --nacl 127.0.0.0/8,::1/128 \
  --admin-warn-days 0 \
  --metrics
```

## Fetch a token

```bash
curl -sS -X POST \
  http://127.0.0.1:18080/realms/uvoocertctl/protocol/openid-connect/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode grant_type=password \
  --data-urlencode client_id=uvoocertctl \
  --data-urlencode username=alice \
  --data-urlencode password=alicepass
```

## Call the admin API

```bash
curl -sS http://127.0.0.1:18081/admin/v1/doctor \
  -H "Authorization: Bearer $ACCESS_TOKEN"

curl -sS http://127.0.0.1:18081/metrics \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

For a dedicated metrics Basic auth fallback:

```bash
uvoocertctl serve-certs \
  --listen 127.0.0.1:18081 \
  --nacl 127.0.0.0/8,::1/128 \
  --admin-warn-days 0 \
  --metrics \
  --metrics-username metrics \
  --metrics-password env:CERTCTL_METRICS_PASSWORD
```

## One-command smoke path

```bash
./scripts/smoke-jwt-auth.sh
```

The smoke script:

- starts Keycloak
- configures the trusted issuer and local bindings
- creates a subject auto-approval rule
- starts `uvoocertctl serve-certs`
- fetches a Keycloak access token
- calls `/admin/v1/doctor`
- calls `/metrics`

Useful follow-up commands:

```bash
uvoocertctl update-auth-issuer --issuer http://127.0.0.1:18080/realms/uvoocertctl --name keycloak-dev-local
uvoocertctl check-auth-issuer --issuer http://127.0.0.1:18080/realms/uvoocertctl
uvoocertctl update-authz-binding --id <binding-id> --permission csr.read
uvoocertctl list-authz-bindings --principal 'role:http://127.0.0.1:18080/realms/uvoocertctl:uvoocertctl_admin'
uvoocertctl disable-auth-issuer --issuer http://127.0.0.1:18080/realms/uvoocertctl
uvoocertctl enable-auth-issuer --issuer http://127.0.0.1:18080/realms/uvoocertctl
uvoocertctl delete-auth-issuer --issuer http://127.0.0.1:18080/realms/uvoocertctl --force
```

When you are done:

```bash
docker compose -f dev/docker/docker-compose.yml down -v
```
