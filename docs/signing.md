# Code Signing Guide

This document describes how to sign Obliterator executables using Microsoft SignTool (`signtool.exe`) in local environments and GitHub Actions CI.

## 1. Prerequisites

- A valid Code Signing Certificate (Standard or Extended Validation / EV) in PKCS#12 (`.pfx`) format.
- Windows SDK with `signtool.exe` installed (standard path: `C:\Program Files (x86)\Windows Kits\10\bin\<version>\x64\signtool.exe`).

> **Security Warning**: Never commit `.pfx` files, certificates, or private keys to the repository or branch history.

## 2. Converting Certificate for GitHub Secrets

To safely provide the certificate to GitHub Actions without committing binary files:

1. Convert your `.pfx` certificate file into a Base64-encoded string:

   ```powershell
   $certBase64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes("certificate.pfx"))
   $certBase64 | Set-Clipboard
   ```

2. Open your GitHub repository in a browser.
3. Navigate to **Settings > Secrets and variables > Actions**.
4. Create two Repository Secrets:
   - `SIGNING_CERT_BASE64`: The full Base64 string copied to clipboard.
   - `SIGNING_CERT_PASSWORD`: The password protecting the `.pfx` file.

## 3. GitHub Actions Integration

The repository CI workflow (`.github/workflows/ci.yml`) includes an optional signing step. It is triggered only when `SIGNING_CERT_BASE64` is configured:

```yaml
- name: Sign Executable
  if: env.SIGNING_CERT_BASE64 != ''
  env:
    SIGNING_CERT_BASE64: ${{ secrets.SIGNING_CERT_BASE64 }}
    SIGNING_CERT_PASSWORD: ${{ secrets.SIGNING_CERT_PASSWORD }}
  shell: powershell
  run: |
    $certBytes = [Convert]::FromBase64String($env:SIGNING_CERT_BASE64)
    $certPath = "$env:TEMP\signing_cert.pfx"
    [System.IO.File]::WriteAllBytes($certPath, $certBytes)
    try {
      & signtool.exe sign /f $certPath /p $env:SIGNING_CERT_PASSWORD /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 bin/obliterator.exe
      & signtool.exe verify /pa /v bin/obliterator.exe
    } finally {
      if (Test-Path $certPath) {
        Remove-Item -Force $certPath
      }
    }
```

The temporary certificate file is stored in `%TEMP%` and securely deleted inside a `finally` block immediately after signing and verification.

## 4. Manual Local Signing

To sign an executable manually on a local development workstation:

```powershell
signtool.exe sign `
  /f "path\to\certificate.pfx" `
  /p "YourCertificatePassword" `
  /fd SHA256 `
  /tr http://timestamp.digicert.com `
  /td SHA256 `
  "bin\obliterator.exe"
```

Verify signature and timestamp validity:

```powershell
signtool.exe verify /pa /v "bin\obliterator.exe"
```
