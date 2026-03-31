#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/dev/auth/docker-compose.yml"
WORK_DIR="${WORK_DIR:-$(mktemp -d /tmp/certctl-jwt-smoke.XXXXXX)}"
DB_PATH="${DB_PATH:-$WORK_DIR/certs.db}"
LISTEN_ADDR="${LISTEN_ADDR:-127.0.0.1:18081}"
ISSUER_URL="${ISSUER_URL:-http://127.0.0.1:18080/realms/certctl}"
CLIENT_ID="${CLIENT_ID:-certctl}"
USERNAME="${USERNAME:-alice}"
PASSWORD="${PASSWORD:-alicepass}"
CERTCTL_CMD="${CERTCTL_CMD:-go run .}"

SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$WORK_DIR"

echo "Starting Keycloak dev stack..."
docker compose -f "$COMPOSE_FILE" up -d

echo "Waiting for Keycloak token endpoint..."
for _ in $(seq 1 60); do
  if curl -fsS "$ISSUER_URL/.well-known/openid-configuration" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo "Configuring trusted issuer and local bindings..."
(cd "$ROOT_DIR" && $CERTCTL_CMD --db "$DB_PATH" create-auth-issuer \
  --name keycloak-dev \
  --issuer "$ISSUER_URL" \
  --audience "$CLIENT_ID" \
  --discovery-url "$ISSUER_URL/.well-known/openid-configuration" \
  --roles-claim realm_access.roles >/dev/null)

(cd "$ROOT_DIR" && $CERTCTL_CMD --db "$DB_PATH" create-authz-binding \
  --principal "role:$ISSUER_URL:certctl_admin" \
  --permission doctor.read >/dev/null)

(cd "$ROOT_DIR" && $CERTCTL_CMD --db "$DB_PATH" create-authz-binding \
  --principal "role:$ISSUER_URL:certctl_admin" \
  --permission metrics.read >/dev/null)

echo "Starting certctl server..."
(cd "$ROOT_DIR" && $CERTCTL_CMD --db "$DB_PATH" serve-certs \
  --listen "$LISTEN_ADDR" \
  --nacl 127.0.0.0/8,::1/128 \
  --admin-warn-days 0 \
  --metrics >/tmp/certctl-jwt-smoke.log 2>&1) &
SERVER_PID="$!"

for _ in $(seq 1 30); do
  if curl -fsS "http://$LISTEN_ADDR/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

echo "Requesting bearer token from Keycloak..."
TOKEN_JSON="$(curl -fsS -X POST "$ISSUER_URL/protocol/openid-connect/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "username=$USERNAME" \
  --data-urlencode "password=$PASSWORD")"

ACCESS_TOKEN="$(python3 - <<'PY' "$TOKEN_JSON"
import json
import sys
print(json.loads(sys.argv[1])["access_token"])
PY
)"

echo "Calling /admin/v1/doctor with bearer auth..."
DOCTOR_JSON="$(curl -fsS "http://$LISTEN_ADDR/admin/v1/doctor" \
  -H "Authorization: Bearer $ACCESS_TOKEN")"
python3 - <<'PY' "$DOCTOR_JSON"
import json
import sys
obj = json.loads(sys.argv[1])
assert obj["status"] == "ok", obj
print("doctor ok")
PY

echo "Calling /metrics with bearer auth..."
METRICS="$(curl -fsS "http://$LISTEN_ADDR/metrics" \
  -H "Authorization: Bearer $ACCESS_TOKEN")"
grep -q 'certctl_certificates_total' <<<"$METRICS"
grep -q 'certctl_csr_requests_total' <<<"$METRICS"

echo "JWT auth smoke test passed."
