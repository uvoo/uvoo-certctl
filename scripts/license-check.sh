#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOWED_GO="${ALLOWED_GO:-Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC,BlueOak-1.0.0,0BSD,MPL-2.0}"

echo "checking Go module licenses"
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required for license checks" >&2
  exit 127
fi
if ! grep -q "Apache License" "$ROOT/LICENSE"; then
  echo "LICENSE must contain the Apache License text" >&2
  exit 1
fi
if [[ ! -s "$ROOT/NOTICE" ]]; then
  echo "NOTICE must exist and be non-empty" >&2
  exit 1
fi

(
  cd "$ROOT"
  ALLOWED_GO="$ALLOWED_GO" python3 scripts/license_check.py
)
