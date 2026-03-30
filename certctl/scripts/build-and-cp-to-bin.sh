#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_BIN="${GO_BIN:-go}"
GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

cd "$ROOT_DIR"
mkdir -p "$GOCACHE"
GOCACHE="$GOCACHE" "$GO_BIN" build -trimpath -o certctl .
sudo cp certctl /usr/local/bin/
