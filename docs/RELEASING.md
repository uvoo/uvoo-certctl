# Releasing uvoocertctl

`uvoocertctl` keeps release operations intentionally simple:

- run tests
- build release archives
- optionally sign the checksum manifest
- create a GitHub draft release
- review and publish from the GitHub UI

## CI recommendation

Use a plain GitHub Actions workflow for CI.

For this repo, Docker Compose is not necessary for normal validation:

- the project is a single Go binary
- tests already run locally with `go test ./...`
- release archives are produced by `scripts/build-release.sh`

Keeping CI as plain Go plus release-build verification is simpler to audit and easier to maintain than introducing a container stack just for testing.

If you want higher-confidence end-to-end coverage for the built-in server, use the separate optional Docker integration workflow and the local stack documented in [`DOCKER_DEV.md`](DOCKER_DEV.md).

## 1. Verify the tree

```bash
go test ./...
go run . doctor
go run . doctor --warn-days 14
```

Commit any remaining changes before drafting a release.

For routine admin operations outside the release flow, see [`RUNBOOK.md`](RUNBOOK.md).

## 2. Build release archives

```bash
VERSION=v0.4.0 ./scripts/build-release.sh
```

This writes:

- platform archives under `dist/`
- per-archive `.sha256` files
- `dist/checksums.txt`

## 3. Optionally sign checksums

If you use GPG for releases:

```bash
GPG_KEY_ID=you@example.com ./scripts/sign-release-checksums.sh
```

This creates:

- `dist/checksums.txt.asc`

Signing the checksum manifest is usually enough. It gives users an authenticity signal without adding much operational complexity.

## 4. Create a GitHub draft release

Dry-run the release flow first:

```bash
./scripts/draft-release.sh v0.4.0 --notes-file docs/RELEASE_NOTES_v0.4.0.md --dry-run
```

Then create the real draft:

```bash
./scripts/draft-release.sh v0.4.0 --notes-file docs/RELEASE_NOTES_v0.4.0.md
```

With checksum signing:

```bash
./scripts/draft-release.sh v0.4.0 \
  --notes-file docs/RELEASE_NOTES_v0.4.0.md \
  --sign-checksums \
  --gpg-key-id you@example.com
```

The script will:

- require a clean git worktree
- create an annotated tag if it does not already exist
- push the tag to `origin`
- create a GitHub draft release
- upload the matching archives, `.sha256` files, and checksum manifest
- upload `checksums.txt.asc` when present

## 5. Review and publish

Open the draft release in GitHub, verify:

- tag and title match
- release notes are correct
- uploaded assets look complete
- checksums and optional signature are attached

Then publish the release from the GitHub UI.
