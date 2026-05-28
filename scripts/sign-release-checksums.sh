#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/dist}"
CHECKSUMS_FILE="$OUT_DIR/checksums.txt"
GPG_KEY_ID="${GPG_KEY_ID:-}"

usage() {
  cat <<'EOF'
Create an armored detached GPG signature for release checksums.

Usage:
  scripts/sign-release-checksums.sh
  GPG_KEY_ID=ABC123 scripts/sign-release-checksums.sh
  OUT_DIR=/tmp/dist scripts/sign-release-checksums.sh

Environment:
  OUT_DIR     Release artifact directory. Default: ./dist
  GPG_KEY_ID  Optional GPG key id, fingerprint, or email to sign with

Outputs:
  - checksums.txt.asc detached armored signature next to checksums.txt
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if ! command -v gpg >/dev/null 2>&1; then
  echo "gpg is required to sign release checksums" >&2
  exit 1
fi

if [[ ! -f "$CHECKSUMS_FILE" ]]; then
  echo "checksums manifest not found: $CHECKSUMS_FILE" >&2
  echo "run scripts/build-release.sh first" >&2
  exit 1
fi

args=(--batch --yes --armor --detach-sign)
if [[ -n "$GPG_KEY_ID" ]]; then
  args+=(-u "$GPG_KEY_ID")
fi

gpg "${args[@]}" --output "${CHECKSUMS_FILE}.asc" "$CHECKSUMS_FILE"

echo "Signed checksums: ${CHECKSUMS_FILE}.asc"
