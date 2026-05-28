#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SMOKE_PRIVATE_CA="${SMOKE_PRIVATE_CA:-0}" \
exec "$ROOT_DIR/scripts/smoke-docker-stack.sh" "$@"
