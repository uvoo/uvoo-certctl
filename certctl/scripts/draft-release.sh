#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${DIST_DIR:-$ROOT_DIR/dist}"
TAG_MESSAGE=""
TITLE=""
NOTES_FILE=""
CREATE_TAG=1
PUSH_TAG=1
SIGN_CHECKSUMS=0
GPG_KEY_ID="${GPG_KEY_ID:-}"
DRY_RUN=0

usage() {
  cat <<'EOF'
Create a GitHub draft release for an existing or newly-created version tag.

Usage:
  scripts/draft-release.sh v0.2.0
  scripts/draft-release.sh v0.2.0 --notes-file docs/RELEASE_NOTES_v0.2.0.md
  scripts/draft-release.sh v0.2.0 --dry-run
  scripts/draft-release.sh v0.2.0 --sign-checksums --gpg-key-id ABC123

Options:
  --notes-file PATH   Release notes markdown file. Defaults to docs/RELEASE_NOTES_<version>.md when present.
  --title TEXT        Release title. Default: <version>
  --tag-message TEXT  Annotated tag message. Default: Release Version <version>
  --dist-dir PATH     Release asset directory. Default: ./dist
  --skip-tag          Do not create a git tag if it is missing
  --skip-push         Do not push the git tag to origin
  --dry-run           Validate inputs and print intended actions without tagging, pushing, signing, or calling GitHub
  --sign-checksums    Sign dist/checksums.txt before creating the draft release
  --gpg-key-id TEXT   GPG key id, fingerprint, or email for signing
  -h, --help          Show help

Requirements:
  - gh authenticated against the target GitHub repository
  - dist artifacts already built for the requested version
  - clean git worktree unless you intentionally bypass this script
EOF
}

if [[ $# -eq 0 ]]; then
  usage >&2
  exit 1
fi

VERSION=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --notes-file)
      NOTES_FILE="${2:?missing value for --notes-file}"
      shift 2
      ;;
    --title)
      TITLE="${2:?missing value for --title}"
      shift 2
      ;;
    --tag-message)
      TAG_MESSAGE="${2:?missing value for --tag-message}"
      shift 2
      ;;
    --dist-dir)
      DIST_DIR="${2:?missing value for --dist-dir}"
      shift 2
      ;;
    --skip-tag)
      CREATE_TAG=0
      shift
      ;;
    --skip-push)
      PUSH_TAG=0
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --sign-checksums)
      SIGN_CHECKSUMS=1
      shift
      ;;
    --gpg-key-id)
      GPG_KEY_ID="${2:?missing value for --gpg-key-id}"
      shift 2
      ;;
    -*)
      echo "unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      if [[ -n "$VERSION" ]]; then
        echo "unexpected extra argument: $1" >&2
        usage >&2
        exit 1
      fi
      VERSION="$1"
      shift
      ;;
  esac
done

if [[ -z "$VERSION" ]]; then
  echo "version is required" >&2
  usage >&2
  exit 1
fi

if [[ -z "$TITLE" ]]; then
  TITLE="$VERSION"
fi
if [[ -z "$TAG_MESSAGE" ]]; then
  TAG_MESSAGE="Release Version $VERSION"
fi
if [[ -z "$NOTES_FILE" ]]; then
  candidate="$ROOT_DIR/docs/RELEASE_NOTES_${VERSION}.md"
  if [[ -f "$candidate" ]]; then
    NOTES_FILE="$candidate"
  fi
fi
if [[ "$DIST_DIR" != /* ]]; then
  DIST_DIR="$ROOT_DIR/${DIST_DIR#./}"
fi
if [[ -n "$NOTES_FILE" && "$NOTES_FILE" != /* ]]; then
  NOTES_FILE="$ROOT_DIR/${NOTES_FILE#./}"
fi

if [[ "$DRY_RUN" -eq 0 ]] && ! command -v gh >/dev/null 2>&1; then
  echo "gh is required to create a draft GitHub release" >&2
  exit 1
fi

if git -C "$ROOT_DIR" rev-parse --show-toplevel >/dev/null 2>&1; then
  if [[ -n "$(git -C "$ROOT_DIR" status --porcelain)" ]]; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      echo "warning: git worktree is not clean; dry run continues for validation" >&2
    else
      echo "git worktree is not clean; commit or stash changes before drafting a release" >&2
      exit 1
    fi
  fi
else
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "warning: no git repository found at $ROOT_DIR; dry run continues for validation" >&2
  else
    echo "git repository not found at $ROOT_DIR" >&2
    exit 1
  fi
fi

if [[ ! -d "$DIST_DIR" ]]; then
  echo "dist directory not found: $DIST_DIR" >&2
  echo "run VERSION=$VERSION ./scripts/build-release.sh first" >&2
  exit 1
fi

if [[ "$SIGN_CHECKSUMS" -eq 1 && "$DRY_RUN" -eq 0 ]]; then
  (
    cd "$ROOT_DIR"
    OUT_DIR="$DIST_DIR" GPG_KEY_ID="$GPG_KEY_ID" ./scripts/sign-release-checksums.sh
  )
fi

shopt -s nullglob
assets=(
  "$DIST_DIR"/certctl_"$VERSION"_*.tar.gz
  "$DIST_DIR"/certctl_"$VERSION"_*.zip
  "$DIST_DIR"/certctl_"$VERSION"_*.tar.gz.sha256
  "$DIST_DIR"/certctl_"$VERSION"_*.zip.sha256
)

if [[ -f "$DIST_DIR/checksums.txt" ]]; then
  assets+=("$DIST_DIR/checksums.txt")
fi
if [[ -f "$DIST_DIR/checksums.txt.asc" ]]; then
  assets+=("$DIST_DIR/checksums.txt.asc")
fi

if [[ ${#assets[@]} -eq 0 ]]; then
  echo "no release assets found for version $VERSION in $DIST_DIR" >&2
  echo "run VERSION=$VERSION ./scripts/build-release.sh first" >&2
  exit 1
fi

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Dry run: validated release inputs for $VERSION"
  echo "Root dir: $ROOT_DIR"
  echo "Dist dir: $DIST_DIR"
  if [[ -n "$NOTES_FILE" ]]; then
    echo "Notes file: $NOTES_FILE"
  else
    echo "Notes file: <inline tag message>"
  fi
  echo "Would create tag if missing: $([[ "$CREATE_TAG" -eq 1 ]] && echo yes || echo no)"
  echo "Would push tag: $([[ "$PUSH_TAG" -eq 1 ]] && echo yes || echo no)"
  echo "Would sign checksums: $([[ "$SIGN_CHECKSUMS" -eq 1 ]] && echo yes || echo no)"
  echo "Assets:"
  for asset in "${assets[@]}"; do
    echo "  - $asset"
  done
  exit 0
fi

if git -C "$ROOT_DIR" rev-parse "$VERSION" >/dev/null 2>&1; then
  echo "Using existing tag: $VERSION"
else
  if [[ "$CREATE_TAG" -eq 0 ]]; then
    echo "tag $VERSION does not exist and --skip-tag was set" >&2
    exit 1
  fi
  git -C "$ROOT_DIR" tag -a "$VERSION" -m "$TAG_MESSAGE"
  echo "Created tag: $VERSION"
fi

if [[ "$PUSH_TAG" -eq 1 ]]; then
  git -C "$ROOT_DIR" push origin "$VERSION"
fi

gh_args=(
  release create "$VERSION"
  --title "$TITLE"
  --draft
)
if [[ -n "$NOTES_FILE" ]]; then
  gh_args+=(--notes-file "$NOTES_FILE")
else
  gh_args+=(--notes "$TAG_MESSAGE")
fi
gh_args+=("${assets[@]}")

(
  cd "$ROOT_DIR"
  gh "${gh_args[@]}"
)
