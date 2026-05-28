#!/usr/bin/env bash
set -Eeuox pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/test_privateca.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing env file: $ENV_FILE" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$ENV_FILE"

: "${CERTCTL_BIN:?CERTCTL_BIN is required}"
: "${CERT_DB:?CERT_DB is required}"

export CERT_DB

mkdir -p "$EXPORT_DIR"

info() { printf '\n[INFO] %s\n' "$*"; }
ok()   { printf '[OK] %s\n' "$*"; }
die()  { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

require_bin() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

run_cmd_capture() {
  local __outvar="$1"
  shift
  local output
  output="$("$@" 2>&1)" || {
    printf '%s\n' "$output" >&2
    return 1
  }
  printf '%s\n' "$output"
  printf -v "$__outvar" '%s' "$output"
}

extract_id() {
  awk -F': ' '/^id:[[:space:]]+/ {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2)
    print $2
    exit
  }'
}
# extract_id() {
#   awk -F': ' '/^id:[[:space:]]+/ {print $2; exit}' | xargs
# }

build_password_flags() {
  local key_pw="${1:-}"
  local -n _arr_ref="$2"
  _arr_ref=()
  if [[ -n "${key_pw}" ]]; then
    _arr_ref+=(--key-password "$key_pw")
  elif [[ -n "${STORAGE_PASSWORD:-}" ]]; then
    _arr_ref+=(--storage-password "$STORAGE_PASSWORD")
  else
    die "No key password provided and STORAGE_PASSWORD is empty"
  fi
}

build_parent_password_flags() {
  local parent_pw="${1:-}"
  local -n _arr_ref="$2"
  _arr_ref=()
  if [[ -n "${parent_pw}" ]]; then
    _arr_ref+=(--parent-key-password "$parent_pw")
  elif [[ -n "${STORAGE_PASSWORD:-}" ]]; then
    _arr_ref+=(--storage-password "$STORAGE_PASSWORD")
  else
    die "No parent key password provided and STORAGE_PASSWORD is empty"
  fi
}

build_subject_flags() {
  local -n _arr_ref="$1"
  _arr_ref=()
  [[ -n "${ORG:-}" ]] && _arr_ref+=(--org "$ORG")
  [[ -n "${ORG_UNIT:-}" ]] && _arr_ref+=(--org-unit "$ORG_UNIT")
  [[ -n "${COUNTRY:-}" ]] && _arr_ref+=(--country "$COUNTRY")
  [[ -n "${PROVINCE:-}" ]] && _arr_ref+=(--province "$PROVINCE")
  [[ -n "${LOCALITY:-}" ]] && _arr_ref+=(--locality "$LOCALITY")
}

build_san_flags() {
  local sans_string="${1:-}"
  local -n _arr_ref="$2"
  _arr_ref=()
  if [[ -n "$sans_string" ]]; then
    # shellcheck disable=SC2206
    local sans=( $sans_string )
    for s in "${sans[@]}"; do
      _arr_ref+=(--san "$s")
    done
  fi
}

assert_file() {
  local f="$1"
  [[ -f "$f" ]] || die "Expected file not found: $f"
}

require_bin awk
require_bin grep

if [[ "${RESET_DB:-0}" == "1" ]]; then
  info "Resetting DB and export directory"
  rm -f "$CERT_DB"
  rm -rf "$EXPORT_DIR"
  mkdir -p "$EXPORT_DIR"
fi

SUBJECT_FLAGS=()
build_subject_flags SUBJECT_FLAGS

ROOT_PW_FLAGS=()
ICA_PW_FLAGS=()
SERVER_PW_FLAGS=()
CLIENT_PW_FLAGS=()
ROOT_PARENT_FLAGS=()
ICA_PARENT_FLAGS=()

build_password_flags "${ROOT_KEY_PASSWORD:-}" ROOT_PW_FLAGS
build_password_flags "${ICA_KEY_PASSWORD:-}" ICA_PW_FLAGS
build_password_flags "${SERVER_KEY_PASSWORD:-}" SERVER_PW_FLAGS
build_password_flags "${CLIENT_KEY_PASSWORD:-}" CLIENT_PW_FLAGS
build_parent_password_flags "${ROOT_KEY_PASSWORD:-}" ROOT_PARENT_FLAGS
build_parent_password_flags "${ICA_KEY_PASSWORD:-}" ICA_PARENT_FLAGS

SERVER_SAN_FLAGS=()
CLIENT_SAN_FLAGS=()
build_san_flags "${SERVER_SANS:-}" SERVER_SAN_FLAGS
build_san_flags "${CLIENT_SANS:-}" CLIENT_SAN_FLAGS

ROOT_ID="${ROOT_ID:-}"
ICA_ID="${ICA_ID:-}"

if [[ "${CREATE_NEW:-1}" == "1" ]]; then
  info "Creating private root CA"
  root_out=""
  run_cmd_capture root_out \
    "$CERTCTL_BIN" create-root-ca \
      --name "$ROOT_NAME" \
      --common-name "$ROOT_CN" \
      --key-type "$ROOT_KEY_TYPE" \
      --days "$ROOT_DAYS" \
      "${ROOT_PW_FLAGS[@]}" \
      "${SUBJECT_FLAGS[@]}"
  ROOT_ID="$(printf '%s\n' "$root_out" | extract_id)"
  [[ -n "$ROOT_ID" ]] || die "Failed to extract ROOT_ID from create-root-ca output"
  ok "ROOT_ID=$ROOT_ID"

  info "Creating private intermediate CA"
  ica_out=""
  run_cmd_capture ica_out \
    "$CERTCTL_BIN" create-intermediate-ca \
      --root-id "$ROOT_ID" \
      --name "$ICA_NAME" \
      --common-name "$ICA_CN" \
      --key-type "$ICA_KEY_TYPE" \
      --days "$ICA_DAYS" \
      "${ROOT_PARENT_FLAGS[@]}" \
      "${ICA_PW_FLAGS[@]}" \
      "${SUBJECT_FLAGS[@]}"
  ICA_ID="$(printf '%s\n' "$ica_out" | extract_id)"
  [[ -n "$ICA_ID" ]] || die "Failed to extract ICA_ID from create-intermediate-ca output"
  ok "ICA_ID=$ICA_ID"
else
  [[ -n "$ROOT_ID" ]] || die "CREATE_NEW=0 but ROOT_ID is empty"
  [[ -n "$ICA_ID" ]] || die "CREATE_NEW=0 but ICA_ID is empty"
  info "Reusing existing ROOT_ID=$ROOT_ID and ICA_ID=$ICA_ID"
fi

info "Issuing private server certificate"
server_issue_out=""
run_cmd_capture server_issue_out \
  "$CERTCTL_BIN" issue-private-cert \
    --intermediate-id "$ICA_ID" \
    --common-name "$SERVER_CERT_CN" \
    --cert-type server \
    --key-type "$SERVER_KEY_TYPE" \
    --days "$LEAF_DAYS" \
    "${ICA_PARENT_FLAGS[@]}" \
    "${SERVER_PW_FLAGS[@]}" \
    "${SUBJECT_FLAGS[@]}" \
    "${SERVER_SAN_FLAGS[@]}"
SERVER_CERT_ID="$(printf '%s\n' "$server_issue_out" | extract_id)"
[[ -n "$SERVER_CERT_ID" ]] || die "Failed to extract SERVER_CERT_ID"
ok "SERVER_CERT_ID=$SERVER_CERT_ID"

info "Issuing private client certificate"
client_issue_out=""
run_cmd_capture client_issue_out \
  "$CERTCTL_BIN" issue-private-cert \
    --intermediate-id "$ICA_ID" \
    --common-name "$CLIENT_CERT_CN" \
    --cert-type client \
    --key-type "$CLIENT_KEY_TYPE" \
    --days "$LEAF_DAYS" \
    "${ICA_PARENT_FLAGS[@]}" \
    "${CLIENT_PW_FLAGS[@]}" \
    "${SUBJECT_FLAGS[@]}" \
    "${CLIENT_SAN_FLAGS[@]}"
CLIENT_CERT_ID="$(printf '%s\n' "$client_issue_out" | extract_id)"
[[ -n "$CLIENT_CERT_ID" ]] || die "Failed to extract CLIENT_CERT_ID"
ok "CLIENT_CERT_ID=$CLIENT_CERT_ID"

info "Listing private certificates"
"$CERTCTL_BIN" list-private-certs

info "Querying private server certificate"
"$CERTCTL_BIN" query-private-cert \
  --common-name "$SERVER_CERT_CN" \
  "${SERVER_PW_FLAGS[@]}"

info "Querying private client certificate"
"$CERTCTL_BIN" query-private-cert \
  --common-name "$CLIENT_CERT_CN" \
  "${CLIENT_PW_FLAGS[@]}"

info "Exporting server certificate as PEM"
"$CERTCTL_BIN" export-private-cert \
  --common-name "$SERVER_CERT_CN" \
  --format pem \
  --out-dir "$EXPORT_DIR" \
  "${SERVER_PW_FLAGS[@]}"
assert_file "$EXPORT_DIR/$SERVER_CERT_CN.cert.pem"
assert_file "$EXPORT_DIR/$SERVER_CERT_CN.key.pem"

info "Exporting server certificate as DER"
"$CERTCTL_BIN" export-private-cert \
  --common-name "$SERVER_CERT_CN" \
  --format der \
  --out-dir "$EXPORT_DIR" \
  "${SERVER_PW_FLAGS[@]}"
assert_file "$EXPORT_DIR/$SERVER_CERT_CN.cert.der"
assert_file "$EXPORT_DIR/$SERVER_CERT_CN.key.der"

info "Exporting server certificate as PKCS#12"
"$CERTCTL_BIN" export-private-cert \
  --common-name "$SERVER_CERT_CN" \
  --format pkcs12 \
  --export-password "$EXPORT_PASSWORD" \
  --out-dir "$EXPORT_DIR" \
  "${SERVER_PW_FLAGS[@]}"
assert_file "$EXPORT_DIR/$SERVER_CERT_CN.p12"

info "Exporting server certificate as PKCS#7 (leaf + intermediate)"
"$CERTCTL_BIN" export-private-cert \
  --common-name "$SERVER_CERT_CN" \
  --format pkcs7 \
  --out-dir "$EXPORT_DIR"
assert_file "$EXPORT_DIR/$SERVER_CERT_CN.p7b"

info "Exporting server certificate as PKCS#7 (leaf + intermediate + root)"
"$CERTCTL_BIN" export-private-cert \
  --common-name "$SERVER_CERT_CN" \
  --format pkcs7 \
  --include-root \
  --out-dir "$EXPORT_DIR"
assert_file "$EXPORT_DIR/$SERVER_CERT_CN.p7b"

cat <<EOF

========================================
Private CA test run completed successfully
========================================
ROOT_ID=$ROOT_ID
ICA_ID=$ICA_ID
SERVER_CERT_ID=$SERVER_CERT_ID
CLIENT_CERT_ID=$CLIENT_CERT_ID
EXPORT_DIR=$EXPORT_DIR

You can inspect exports with:
  ls -l "$EXPORT_DIR"

Recommended quick checks:
  openssl x509 -in "$EXPORT_DIR/$SERVER_CERT_CN.cert.pem" -noout -text | less
  openssl pkcs12 -in "$EXPORT_DIR/$SERVER_CERT_CN.p12" -info -nodes
EOF
