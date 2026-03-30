# Installing certctl

`certctl` ships as a single binary for Linux, macOS, and Windows.

## Verify the download

Each release archive has a matching `.sha256` file.

On Linux or macOS:

```bash
sha256sum -c certctl_v0.1.0_linux_amd64.tar.gz.sha256
```

On macOS without `sha256sum`:

```bash
shasum -a 256 -c certctl_v0.1.0_darwin_arm64.tar.gz.sha256
```

On Windows PowerShell:

```powershell
Get-FileHash .\certctl_v0.1.0_windows_amd64.zip -Algorithm SHA256
```

Compare the output with the contents of the matching `.sha256` file, then extract the archive.

## Extract the archive

On Linux or macOS:

```bash
tar -xzf certctl_v0.1.0_linux_amd64.tar.gz
cd certctl_v0.1.0_linux_amd64
```

On Windows PowerShell:

```powershell
Expand-Archive .\certctl_v0.1.0_windows_amd64.zip -DestinationPath .
Set-Location .\certctl_v0.1.0_windows_amd64
```

## Install on Linux

```bash
chmod +x certctl
sudo install -m 0755 certctl /usr/local/bin/certctl
certctl version
```

## Install on macOS

```bash
chmod +x certctl
sudo install -m 0755 certctl /usr/local/bin/certctl
certctl version
```

## Install on Windows

1. Rename the downloaded file to `certctl.exe` if needed.
2. Move it into a directory such as `C:\Tools\certctl\`.
3. Add that directory to `Path`.
4. Open a new PowerShell window and run:

```powershell
certctl version
```

## Build from source

```bash
go build -o certctl .
```

Or build the release matrix:

```bash
VERSION=v0.1.0 ./scripts/build-release.sh
```
