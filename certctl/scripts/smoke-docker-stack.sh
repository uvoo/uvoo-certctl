#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/dev/docker/docker-compose.yml}"
PROJECT_NAME="${PROJECT_NAME:-certctl-smoke-$(date +%s)}"
WORK_DIR="${WORK_DIR:-$(mktemp -d /tmp/certctl-docker-smoke.XXXXXX)}"
CERTCTL_SERVICE="${CERTCTL_SERVICE:-certctl}"
KEYCLOAK_SERVICE="${KEYCLOAK_SERVICE:-keycloak}"
DB_PATH_IN_CONTAINER="${DB_PATH_IN_CONTAINER:-/data/certs.db}"
KEYCLOAK_HOST_PORT="${KEYCLOAK_HOST_PORT:-18080}"
CERTCTL_HOST_PORT="${CERTCTL_HOST_PORT:-18081}"
CERTCTL_BASE_URL="${CERTCTL_BASE_URL:-http://127.0.0.1:${CERTCTL_HOST_PORT}}"
ISSUER_URL="${ISSUER_URL:-http://127.0.0.1:${KEYCLOAK_HOST_PORT}/realms/certctl}"
INTERNAL_ISSUER_URL="${INTERNAL_ISSUER_URL:-http://${KEYCLOAK_SERVICE}:8080/realms/certctl}"
CLIENT_ID="${CLIENT_ID:-certctl}"
USERNAME="${USERNAME:-alice}"
PASSWORD="${PASSWORD:-alicepass}"
CSR_SUBMIT_PASSWORD="${CSR_SUBMIT_PASSWORD:-submit-secret}"
SMOKE_PRIVATE_CA="${SMOKE_PRIVATE_CA:-1}"
SMOKE_PUBLIC_CERT="${SMOKE_PUBLIC_CERT:-0}"
SMOKE_PUBLIC_CERT_ISSUE="${SMOKE_PUBLIC_CERT_ISSUE:-0}"
PUBLIC_PROVIDER="${PUBLIC_PROVIDER:-namecheap}"
PUBLIC_DNS_RESOLVER="${PUBLIC_DNS_RESOLVER:-8.8.8.8}"
PUBLIC_WRITE_TEST="${PUBLIC_WRITE_TEST:-0}"
PUBLIC_STAGING="${PUBLIC_STAGING:-1}"
KEEP_STACK="${KEEP_STACK:-0}"

ROOT_CA_NAME="${ROOT_CA_NAME:-corp-root}"
ROOT_CA_CN="${ROOT_CA_CN:-Corp Root CA}"
ROOT_CA_PASSWORD="${ROOT_CA_PASSWORD:-RootSecret123!}"
INTERMEDIATE_CA_NAME="${INTERMEDIATE_CA_NAME:-corp-issuing}"
INTERMEDIATE_CA_CN="${INTERMEDIATE_CA_CN:-Corp Issuing CA}"
INTERMEDIATE_CA_PASSWORD="${INTERMEDIATE_CA_PASSWORD:-IcaSecret123!}"

ACCESS_TOKEN=""

compose() {
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" "$@"
}

certctl_exec() {
  compose exec -T "$CERTCTL_SERVICE" certctl --db "$DB_PATH_IN_CONTAINER" "$@"
}

cleanup() {
  if [[ "$KEEP_STACK" != "1" ]]; then
    compose down -v >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

wait_for_url() {
  local url="$1"
  local name="$2"
  local attempts="${3:-60}"
  local delay="${4:-2}"
  for _ in $(seq 1 "$attempts"); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$delay"
  done
  echo "Timed out waiting for $name at $url" >&2
  return 1
}

json_field() {
  local payload="$1"
  local field="$2"
  python3 - <<'PY' "$payload" "$field"
import json
import sys

obj = json.loads(sys.argv[1])
value = obj
for part in sys.argv[2].split("."):
    value = value[part]
if isinstance(value, (dict, list)):
    print(json.dumps(value))
else:
    print(value)
PY
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "Required environment variable is missing: $name" >&2
    exit 1
  fi
}

configure_auth() {
  echo "Configuring trusted issuer and local bindings..."
  certctl_exec create-auth-issuer \
    --name keycloak-dev \
    --issuer "$ISSUER_URL" \
    --audience "$CLIENT_ID" \
    --required-claim "azp=$CLIENT_ID" \
    --discovery-url "$INTERNAL_ISSUER_URL/.well-known/openid-configuration" \
    --roles-claim realm_access.roles >/dev/null

  certctl_exec create-authz-binding \
    --principal "role:$ISSUER_URL:certctl_admin" \
    --permission doctor.read >/dev/null
  certctl_exec create-authz-binding \
    --principal "role:$ISSUER_URL:certctl_admin" \
    --permission metrics.read >/dev/null
}

configure_private_csr_auth() {
  certctl_exec create-authz-binding \
    --principal "role:$ISSUER_URL:certctl_admin" \
    --permission csr.read \
    --resource-kind csr_request \
    --resource-ref '*' >/dev/null
  certctl_exec create-authz-binding \
    --principal "role:$ISSUER_URL:certctl_admin" \
    --permission csr.approve \
    --resource-kind csr_request \
    --resource-ref '*' >/dev/null
}

fetch_access_token() {
  echo "Requesting bearer token from Keycloak..."
  local token_json
  token_json="$(curl -fsS -X POST "$ISSUER_URL/protocol/openid-connect/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode "grant_type=password" \
    --data-urlencode "client_id=$CLIENT_ID" \
    --data-urlencode "username=$USERNAME" \
    --data-urlencode "password=$PASSWORD")"
  ACCESS_TOKEN="$(json_field "$token_json" "access_token")"
}

verify_admin_endpoints() {
  echo "Calling /admin/v1/doctor with bearer auth..."
  local doctor_json
  doctor_json="$(curl -fsS "$CERTCTL_BASE_URL/admin/v1/doctor" \
    -H "Authorization: Bearer $ACCESS_TOKEN")"
  python3 - <<'PY' "$doctor_json"
import json
import sys

obj = json.loads(sys.argv[1])
assert obj["status"] == "ok", obj
print("doctor ok")
PY

  echo "Calling /metrics with bearer auth..."
  local metrics
  metrics="$(curl -fsS "$CERTCTL_BASE_URL/metrics" \
    -H "Authorization: Bearer $ACCESS_TOKEN")"
  grep -q 'certctl_certificates_total' <<<"$metrics"
  grep -q 'certctl_csr_requests_total' <<<"$metrics"
}

run_private_csr_smoke() {
  if [[ "$SMOKE_PRIVATE_CA" != "1" ]]; then
    echo "Skipping private CA smoke."
    return 0
  fi

  command -v openssl >/dev/null 2>&1 || {
    echo "openssl is required for private CSR smoke" >&2
    exit 1
  }

  echo "Configuring admin permissions for CSR review..."
  configure_private_csr_auth

  echo "Creating private root and intermediate CAs inside the container..."
  certctl_exec create-root-ca \
    --name "$ROOT_CA_NAME" \
    --common-name "$ROOT_CA_CN" \
    --key-password "$ROOT_CA_PASSWORD" >/dev/null

  certctl_exec create-intermediate-ca \
    --root-name "$ROOT_CA_NAME" \
    --name "$INTERMEDIATE_CA_NAME" \
    --common-name "$INTERMEDIATE_CA_CN" \
    --parent-key-password "$ROOT_CA_PASSWORD" \
    --key-password "$INTERMEDIATE_CA_PASSWORD" >/dev/null

  echo "Generating a private CSR locally..."
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$WORK_DIR/private.key" >/dev/null 2>&1
  openssl req -new \
    -key "$WORK_DIR/private.key" \
    -subj "/CN=svc.internal/O=Example/OU=Platform/C=US/ST=Utah/L=Salt Lake City" \
    -addext "subjectAltName=DNS:svc.internal,DNS:svc-alt.internal" \
    -out "$WORK_DIR/private.csr" >/dev/null 2>&1

  python3 - <<'PY' "$WORK_DIR/private.csr" "$WORK_DIR/private-submit.json" "$CSR_SUBMIT_PASSWORD" "$INTERMEDIATE_CA_NAME"
import json
import sys
from pathlib import Path

csr_path, out_path, submit_password, ca_name = sys.argv[1:]
payload = {
    "kind": "private",
    "submit_password": submit_password,
    "csr_pem": Path(csr_path).read_text(),
    "requester_name": "Alice Admin",
    "requester_email": "alice@example.com",
    "phone_number": "+1-801-555-0100",
    "organization": "Example Corp",
    "department": "Platform",
    "note": "docker smoke private csr",
    "requested_ca_name": ca_name,
    "cert_type": "server",
    "requested_days": 90,
}
Path(out_path).write_text(json.dumps(payload))
PY

  echo "Submitting the private CSR over HTTP..."
  local submit_json
  submit_json="$(curl -fsS -X POST "$CERTCTL_BASE_URL/csr-requests" \
    -H 'Content-Type: application/json' \
    --data-binary "@$WORK_DIR/private-submit.json")"
  local request_id pickup_token
  request_id="$(json_field "$submit_json" "id")"
  pickup_token="$(json_field "$submit_json" "pickup_token")"

  echo "Listing pending CSR requests over the admin API..."
  local list_json
  list_json="$(curl -fsS "$CERTCTL_BASE_URL/admin/v1/csr-requests" \
    -H "Authorization: Bearer $ACCESS_TOKEN")"
  python3 - <<'PY' "$list_json" "$request_id"
import json
import sys

payload = json.loads(sys.argv[1])
request_id = sys.argv[2]
assert any(item["id"] == request_id for item in payload["items"]), payload
print("csr list ok")
PY

  echo "Reading the individual CSR request over the admin API..."
  local item_json
  item_json="$(curl -fsS "$CERTCTL_BASE_URL/admin/v1/csr-requests/$request_id" \
    -H "Authorization: Bearer $ACCESS_TOKEN")"
  python3 - <<'PY' "$item_json" "$request_id"
import json
import sys

payload = json.loads(sys.argv[1])
assert payload["id"] == sys.argv[2], payload
assert payload["status"] == "pending", payload
print("csr get ok")
PY

  python3 - <<'PY' "$WORK_DIR/private-approve.json" "$INTERMEDIATE_CA_NAME" "$INTERMEDIATE_CA_PASSWORD"
import json
import sys
from pathlib import Path

out_path, ca_name, ca_password = sys.argv[1:]
payload = {
    "intermediate_name": ca_name,
    "parent_key_password": ca_password,
    "decision_note": "approved by docker smoke",
    "cert_type": "server",
    "days": 90,
}
Path(out_path).write_text(json.dumps(payload))
PY

  echo "Approving the private CSR over the admin API..."
  curl -fsS -X POST "$CERTCTL_BASE_URL/admin/v1/csr-requests/$request_id/approve" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H 'Content-Type: application/json' \
    --data-binary "@$WORK_DIR/private-approve.json" >/dev/null

  echo "Checking pickup flow for the issued private certificate..."
  local pickup_json
  pickup_json="$(curl -fsS "$CERTCTL_BASE_URL/csr-requests/$request_id" \
    -H "X-Pickup-Token: $pickup_token")"
  python3 - <<'PY' "$pickup_json"
import json
import sys

payload = json.loads(sys.argv[1])
assert payload["status"] == "issued", payload
assert "BEGIN CERTIFICATE" in payload["certificate_pem"], payload
print("private csr pickup ok")
PY
}

run_public_provider_smoke() {
  if [[ "$SMOKE_PUBLIC_CERT" != "1" ]]; then
    echo "Skipping public provider smoke."
    return 0
  fi

  require_env NAMECHEAP_API_USER
  require_env NAMECHEAP_API_KEY
  require_env NAMECHEAP_CLIENT_IP
  require_env PUBLIC_DOMAIN

  echo "Running public provider precursor checks..."
  local args=(
    check-precursors
    --domain "$PUBLIC_DOMAIN"
    --provider "$PUBLIC_PROVIDER"
    --api-user "$NAMECHEAP_API_USER"
    --api-key "$NAMECHEAP_API_KEY"
    --client-ip "$NAMECHEAP_CLIENT_IP"
    --dns-resolver "$PUBLIC_DNS_RESOLVER"
  )
  if [[ "$PUBLIC_WRITE_TEST" == "1" ]]; then
    args+=(--write-test)
  fi
  certctl_exec "${args[@]}"

  if [[ "$SMOKE_PUBLIC_CERT_ISSUE" != "1" ]]; then
    echo "Public certificate issuance smoke disabled."
    return 0
  fi

  require_env PUBLIC_CERT_COMMON_NAME
  require_env PUBLIC_CERT_EMAIL
  require_env PUBLIC_STORAGE_PASSWORD

  echo "Running public certificate issuance smoke..."
  local issue_args=(
    get
    --common-name "$PUBLIC_CERT_COMMON_NAME"
    --email "$PUBLIC_CERT_EMAIL"
    --provider "$PUBLIC_PROVIDER"
    --api-user "$NAMECHEAP_API_USER"
    --api-key "$NAMECHEAP_API_KEY"
    --client-ip "$NAMECHEAP_CLIENT_IP"
    --dns-resolver "$PUBLIC_DNS_RESOLVER"
    --storage-password "$PUBLIC_STORAGE_PASSWORD"
  )
  if [[ -n "${PUBLIC_CERT_SANS:-}" ]]; then
    issue_args+=(--sans "$PUBLIC_CERT_SANS")
  fi
  if [[ "$PUBLIC_STAGING" == "1" ]]; then
    issue_args+=(--staging)
  fi
  certctl_exec "${issue_args[@]}"
}

mkdir -p "$WORK_DIR"

echo "Starting docker dev stack..."
compose up -d --build

echo "Waiting for Keycloak..."
wait_for_url "$ISSUER_URL/.well-known/openid-configuration" "Keycloak"

echo "Waiting for certctl..."
wait_for_url "$CERTCTL_BASE_URL/healthz" "certctl"

configure_auth
fetch_access_token
verify_admin_endpoints
run_private_csr_smoke
run_public_provider_smoke

echo "Docker smoke test passed."
