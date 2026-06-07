#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/dist}"
VERSION="${VERSION:-dev}"
COMMIT="${COMMIT:-$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
GO_BIN="${GO_BIN:-go}"
DEFAULT_CACHE_ROOT="${XDG_CACHE_HOME:-${HOME:-$ROOT_DIR/.cache}}"
GOCACHE="${GOCACHE:-$DEFAULT_CACHE_ROOT/uvoo-certctl-gocache}"

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
Build uvoo-certctl release archives for common platforms.

Usage:
  scripts/build-release.sh
  VERSION=v0.1.0 scripts/build-release.sh
  scripts/build-release.sh linux/amd64 darwin/arm64 windows/amd64

Environment:
  VERSION   Release version label used in artifact names. Default: dev
  COMMIT    Commit label embedded into the binary. Default: current git commit
  BUILD_DATE Build timestamp embedded into the binary. Default: current UTC time
  OUT_DIR   Output directory for built archives. Default: ./dist
  GO_BIN    Go executable to use. Default: go
  GOCACHE   Go build cache directory. Default: $HOME/.cache/uvoo-certctl-gocache

Outputs:
  - Per-platform release archives in ./dist
  - Matching per-archive .sha256 files
  - checksums.txt manifest covering all generated archives
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

if ! command -v tar >/dev/null 2>&1; then
  echo "tar is required to build release archives" >&2
  exit 1
fi

if ! command -v sha256sum >/dev/null 2>&1; then
  echo "sha256sum is required to build release checksums" >&2
  exit 1
fi

ARCHIVES=()

ZIP_CMD=""
if command -v zip >/dev/null 2>&1; then
  ZIP_CMD="zip"
elif command -v python3 >/dev/null 2>&1; then
  ZIP_CMD="python3"
fi

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

  artifact_base="uvoo-certctl_${VERSION}_${goos}_${goarch}"
  artifact_dir="$OUT_DIR/$artifact_base"
  bin_name="uvoo-certctl${ext}"
  archive_name="${artifact_base}.tar.gz"
  if [[ "$goos" == "windows" ]]; then
    archive_name="${artifact_base}.zip"
    if [[ -z "$ZIP_CMD" ]]; then
      echo "zip or python3 is required to build Windows release archives" >&2
      exit 1
    fi
  fi

  rm -rf "$artifact_dir"
  rm -f "$OUT_DIR/$archive_name" "$OUT_DIR/${archive_name}.sha256"
  mkdir -p "$artifact_dir"

  echo "Building $goos/$goarch"
  (
    cd "$ROOT_DIR"
    GOCACHE="$GOCACHE" GOOS="$goos" GOARCH="$goarch" \
      "$GO_BIN" build -trimpath \
        -ldflags="-s -w -X uvoo-certctl/cmd.version=$VERSION -X uvoo-certctl/cmd.commit=$COMMIT -X uvoo-certctl/cmd.date=$BUILD_DATE" \
        -o "$artifact_dir/$bin_name" .
  )

  cp "$ROOT_DIR/README.md" "$artifact_dir/README.md"
  if [[ -f "$ROOT_DIR/LICENSE" ]]; then
    cp "$ROOT_DIR/LICENSE" "$artifact_dir/LICENSE"
  fi
  if [[ -f "$ROOT_DIR/NOTICE" ]]; then
    cp "$ROOT_DIR/NOTICE" "$artifact_dir/NOTICE"
  fi
  if [[ -f "$ROOT_DIR/CHANGELOG.md" ]]; then
    cp "$ROOT_DIR/CHANGELOG.md" "$artifact_dir/CHANGELOG.md"
  fi
  if [[ -f "$ROOT_DIR/docs/INSTALL.md" ]]; then
    cp "$ROOT_DIR/docs/INSTALL.md" "$artifact_dir/INSTALL.md"
  fi
  if [[ -f "$ROOT_DIR/docs/CSR_REQUESTS.md" ]]; then
    cp "$ROOT_DIR/docs/CSR_REQUESTS.md" "$artifact_dir/CSR_REQUESTS.md"
  fi

  if [[ "$goos" == "windows" ]]; then
    if [[ "$ZIP_CMD" == "zip" ]]; then
      (
        cd "$OUT_DIR"
        zip -rq "$archive_name" "$artifact_base"
      )
    else
      (
        cd "$OUT_DIR"
        python3 -m zipfile -c "$archive_name" "$artifact_base"
      )
    fi
  else
    (
      cd "$OUT_DIR"
      tar -czf "$archive_name" "$artifact_base"
    )
  fi

  ARCHIVES+=("$archive_name")

  (
    cd "$OUT_DIR"
    sha256sum "$archive_name" > "${archive_name}.sha256"
  )

  rm -rf "$artifact_dir"
done

if [[ ${#ARCHIVES[@]} -gt 0 ]]; then
  (
    cd "$OUT_DIR"
    sha256sum "${ARCHIVES[@]}" > checksums.txt
  )
fi

echo
echo "Release archives written to: $OUT_DIR"
