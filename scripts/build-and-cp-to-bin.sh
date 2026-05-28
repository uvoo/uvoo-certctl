#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-dev}"
COMMIT="${COMMIT:-$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
GO_BIN="${GO_BIN:-go}"
GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

cd "$ROOT_DIR"
mkdir -p "$GOCACHE"
GOCACHE="$GOCACHE" "$GO_BIN" build -trimpath \
  -ldflags="-X uvoocertctl/cmd.version=$VERSION -X uvoocertctl/cmd.commit=$COMMIT -X uvoocertctl/cmd.date=$BUILD_DATE" \
  -o uvoocertctl .
sudo cp uvoocertctl /usr/local/bin/
