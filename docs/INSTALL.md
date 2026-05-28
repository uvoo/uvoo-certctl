# Installing uvoocertctl

`uvoocertctl` ships as a single binary for Linux, macOS, and Windows.

## Verify the download

Each release archive has a matching `.sha256` file. Releases may also include a signed `checksums.txt.asc` file for checksum verification with GPG.

On Linux or macOS:

```bash
sha256sum -c uvoocertctl_v0.2.0_linux_amd64.tar.gz.sha256
```

On macOS without `sha256sum`:

```bash
shasum -a 256 -c uvoocertctl_v0.2.0_darwin_arm64.tar.gz.sha256
```

On Windows PowerShell:

```powershell
Get-FileHash .\uvoocertctl_v0.2.0_windows_amd64.zip -Algorithm SHA256
```

Compare the output with the contents of the matching `.sha256` file, then extract the archive.

If the release includes `checksums.txt` and `checksums.txt.asc`, you can also verify the signed checksum manifest:

```bash
gpg --verify checksums.txt.asc checksums.txt
```

## Extract the archive

On Linux or macOS:

```bash
tar -xzf uvoocertctl_v0.2.0_linux_amd64.tar.gz
cd uvoocertctl_v0.2.0_linux_amd64
```

On Windows PowerShell:

```powershell
Expand-Archive .\uvoocertctl_v0.2.0_windows_amd64.zip -DestinationPath .
Set-Location .\uvoocertctl_v0.2.0_windows_amd64
```

## Install on Linux

```bash
chmod +x uvoocertctl
sudo install -m 0755 uvoocertctl /usr/local/bin/uvoocertctl
uvoocertctl version
```

## Install on macOS

```bash
chmod +x uvoocertctl
sudo install -m 0755 uvoocertctl /usr/local/bin/uvoocertctl
uvoocertctl version
```

## Install on Windows

1. Rename the downloaded file to `uvoocertctl.exe` if needed.
2. Move it into a directory such as `C:\Tools\uvoocertctl\`.
3. Add that directory to `Path`.
4. Open a new PowerShell window and run:

```powershell
uvoocertctl version
```

## Build from source

```bash
go build -o uvoocertctl .
```

Or build the release matrix:

```bash
VERSION=v0.2.0 ./scripts/build-release.sh
```

For day-to-day operations after install, see [`RUNBOOK.md`](RUNBOOK.md).

For tagging, signing, and GitHub draft release creation, see [`RELEASING.md`](RELEASING.md).
