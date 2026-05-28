# Auth Dev Guide

`certctl` includes a small development-only Keycloak stack for exercising JWT bearer auth against the built-in admin API.

Files:

- `dev/docker/docker-compose.yml`
- `dev/docker/keycloak/certctl-realm.json`
- `scripts/smoke-jwt-auth.sh`
 
Note: the active local stack now lives under `dev/docker/`. `scripts/smoke-jwt-auth.sh` remains as a compatibility wrapper around the fuller Docker smoke.

## Start Keycloak

```bash
docker compose -f dev/docker/docker-compose.yml up -d
```

Keycloak will be available at:

- `http://127.0.0.1:18080`

Realm:

- `certctl`

Public client:

- `certctl`

Test user:

- username: `alice`
- password: `alicepass`

Realm role:

- `certctl_admin`

## Configure certctl

```bash
certctl create-auth-issuer \
  --preset keycloak \
  --name keycloak-dev \
  --issuer http://127.0.0.1:18080/realms/certctl \
  --audience certctl \
  --required-claim azp=certctl \
  --discovery-url http://127.0.0.1:18080/realms/certctl/.well-known/openid-configuration

certctl create-subject-auto-approval \
  --name keycloak-example-users \
  --issuer http://127.0.0.1:18080/realms/certctl \
  --email-domain example.com \
  --local-group employees

certctl create-authz-binding \
  --principal 'local_group:employees' \
  --permission doctor.read

certctl create-authz-binding \
  --principal 'local_group:employees' \
  --permission metrics.read

certctl list-auth-issuers --all
certctl list-authz-bindings --all
```

## Run the built-in server

```bash
certctl serve-certs \
  --listen 127.0.0.1:18081 \
  --nacl 127.0.0.0/8,::1/128 \
  --admin-warn-days 0 \
  --metrics
```

## Fetch a token

```bash
curl -sS -X POST \
  http://127.0.0.1:18080/realms/certctl/protocol/openid-connect/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode grant_type=password \
  --data-urlencode client_id=certctl \
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
certctl serve-certs \
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
- starts `certctl serve-certs`
- fetches a Keycloak access token
- calls `/admin/v1/doctor`
- calls `/metrics`

Useful follow-up commands:

```bash
certctl update-auth-issuer --issuer http://127.0.0.1:18080/realms/certctl --name keycloak-dev-local
certctl check-auth-issuer --issuer http://127.0.0.1:18080/realms/certctl
certctl update-authz-binding --id <binding-id> --permission csr.read
certctl list-authz-bindings --principal 'role:http://127.0.0.1:18080/realms/certctl:certctl_admin'
certctl disable-auth-issuer --issuer http://127.0.0.1:18080/realms/certctl
certctl enable-auth-issuer --issuer http://127.0.0.1:18080/realms/certctl
certctl delete-auth-issuer --issuer http://127.0.0.1:18080/realms/certctl --force
```

When you are done:

```bash
docker compose -f dev/docker/docker-compose.yml down -v
```
