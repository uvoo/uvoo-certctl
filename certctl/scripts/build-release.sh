#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/dist}"
VERSION="${VERSION:-dev}"
COMMIT="${COMMIT:-$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
GO_BIN="${GO_BIN:-go}"
GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

DEFAULT_TARGETS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
)

usage() {
  cat <<'EOF'
Build certctl release binaries for common platforms.

Usage:
  scripts/build-release.sh
  VERSION=v0.1.0 scripts/build-release.sh
  scripts/build-release.sh linux/amd64 darwin/arm64 windows/amd64

Environment:
  VERSION   Release version label used in artifact names. Default: dev
  COMMIT    Commit label embedded into the binary. Default: current git commit
  BUILD_DATE Build timestamp embedded into the binary. Default: current UTC time
  OUT_DIR   Output directory for built artifacts. Default: ./dist
  GO_BIN    Go executable to use. Default: go
  GOCACHE   Go build cache directory. Default: $ROOT_DIR/.gocache
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

TARGETS=("$@")
if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=("${DEFAULT_TARGETS[@]}")
fi

mkdir -p "$OUT_DIR"
mkdir -p "$GOCACHE"

for target in "${TARGETS[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  if [[ -z "$goos" || -z "$goarch" || "$goos" == "$goarch" ]]; then
    echo "invalid target: $target" >&2
    exit 1
  fi

  ext=""
  if [[ "$goos" == "windows" ]]; then
    ext=".exe"
  fi

  artifact_dir="$OUT_DIR/certctl_${VERSION}_${goos}_${goarch}"
  bin_name="certctl${ext}"

  rm -rf "$artifact_dir"
  mkdir -p "$artifact_dir"

  echo "Building $goos/$goarch"
  (
    cd "$ROOT_DIR"
    GOCACHE="$GOCACHE" GOOS="$goos" GOARCH="$goarch" \
      "$GO_BIN" build -trimpath \
        -ldflags="-s -w -X certctl/cmd.version=$VERSION -X certctl/cmd.commit=$COMMIT -X certctl/cmd.date=$BUILD_DATE" \
        -o "$artifact_dir/$bin_name" .
  )

  cp "$ROOT_DIR/README.md" "$artifact_dir/README.md"

  if command -v sha256sum >/dev/null 2>&1; then
    (
      cd "$OUT_DIR"
      sha256sum "certctl_${VERSION}_${goos}_${goarch}/$bin_name" > "certctl_${VERSION}_${goos}_${goarch}.sha256"
    )
  fi
done

echo
echo "Artifacts written to: $OUT_DIR"
