# Package Publishing Guide

This guide describes how to publish Obliterator packages to Windows Package Manager (WinGet) and Scoop.

## 1. Windows Package Manager (WinGet)

Obliterator manifest files are located in `manifests/winget/`:
- `negg0s.obliterator.yaml` (Version manifest)
- `negg0s.obliterator.installer.yaml` (Installer architecture and URLs)
- `negg0s.obliterator.locale.en-US.yaml` (Package metadata and description)

### Automated Submission via wingetcreate

The recommended method is using Microsoft's official `wingetcreate` CLI tool:

1. Install `wingetcreate`:

   ```powershell
   winget install Microsoft.WingetCreate
   ```

2. Submit release archive URL with GitHub personal access token:

   ```powershell
   wingetcreate submit `
     https://github.com/negg0s/obliterator/releases/download/v0.2.0/obliterator-x64.zip `
     --token <GITHUB_TOKEN>
   ```

### Manual Submission via Pull Request

1. Fork the official [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) repository.
2. Clone your fork locally and create a new branch:

   ```powershell
   git checkout -b update-obliterator-0.2.0
   ```

3. Create the target folder path:

   ```
   manifests/n/negg0s/obliterator/0.2.0/
   ```

4. Copy the 3 files from `manifests/winget/` into that directory:
   - `negg0s.obliterator.yaml`
   - `negg0s.obliterator.installer.yaml`
   - `negg0s.obliterator.locale.en-US.yaml`

5. Update the `InstallerSha256` fields in `negg0s.obliterator.installer.yaml` with the actual SHA-256 hashes from the release `SHA256SUMS` file.

6. Commit, push to your fork, and open a Pull Request to `microsoft/winget-pkgs:master`.

---

## 2. Scoop Package Manager

The Scoop manifest is located at `manifests/scoop/obliterator.json`.

### Hosting in a Custom Bucket

1. Create a public GitHub repository named `scoop-bucket` (for example, `github.com/negg0s/scoop-bucket`).
2. Create a `bucket/` folder in the repository and copy `manifests/scoop/obliterator.json` into `bucket/obliterator.json`.
3. Update the `hash` values in `obliterator.json` with the SHA-256 hashes from the release `SHA256SUMS`.
4. Commit and push the changes.

### User Installation

Users can install Obliterator through Scoop with the following commands:

```powershell
scoop bucket add negg0s https://github.com/negg0s/scoop-bucket
scoop install obliterator
```

### Automated Updates with Checkver

The manifest includes an `autoupdate` section configured for Scoop's automated updater:

```json
"checkver": "github",
"autoupdate": {
    "architecture": {
        "64bit": {
            "url": "https://github.com/negg0s/obliterator/releases/download/v$version/obliterator-x64.zip"
        },
        "arm64": {
            "url": "https://github.com/negg0s/obliterator/releases/download/v$version/obliterator-arm64.zip"
        }
    },
    "hash": {
        "url": "$baseurl/SHA256SUMS"
    }
}
```

To test and run checkver locally in a cloned bucket repository:

```powershell
.\bin\checkver.ps1 -u obliterator
```
