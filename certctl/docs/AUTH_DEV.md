# Auth Dev Guide

`certctl` includes a small development-only Keycloak stack for exercising JWT bearer auth against the built-in admin API.

Files:

- `dev/auth/docker-compose.yml`
- `dev/auth/keycloak/certctl-realm.json`
- `scripts/smoke-jwt-auth.sh`

## Start Keycloak

```bash
docker compose -f dev/auth/docker-compose.yml up -d
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
  --name keycloak-dev \
  --issuer http://127.0.0.1:18080/realms/certctl \
  --audience certctl \
  --discovery-url http://127.0.0.1:18080/realms/certctl/.well-known/openid-configuration \
  --roles-claim realm_access.roles

certctl create-authz-binding \
  --principal 'role:http://127.0.0.1:18080/realms/certctl:certctl_admin' \
  --permission doctor.read

certctl create-authz-binding \
  --principal 'role:http://127.0.0.1:18080/realms/certctl:certctl_admin' \
  --permission metrics.read
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

## One-command smoke path

```bash
./scripts/smoke-jwt-auth.sh
```

The smoke script:

- starts Keycloak
- configures the trusted issuer and local bindings
- starts `certctl serve-certs`
- fetches a Keycloak access token
- calls `/admin/v1/doctor`
- calls `/metrics`

When you are done:

```bash
docker compose -f dev/auth/docker-compose.yml down -v
```
