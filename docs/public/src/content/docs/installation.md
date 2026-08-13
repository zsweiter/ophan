---
title: Installation
description: Install Ophan API Gateway on Linux, macOS, Windows, or Docker
tags: ["getting-started"]
order: 1
---

## Linux / macOS — Quick Script

```bash
# Latest release
curl -sSL https://github.com/zsweiter/ophan/releases/latest/download/install.sh | bash

# Specific version
curl -sSL https://github.com/zsweiter/ophan/releases/latest/download/install.sh | bash -s -- --version v0.1.0
```

## Linux / macOS — Manual

```bash
# Download
VERSION="v0.1.0"
OS="linux"          # or "macos"
ARCH="x86_64"       # or "aarch64"
curl -sSL "https://github.com/zsweiter/ophan/releases/download/${VERSION}/ophan-${VERSION#v}-${OS}-${ARCH}.tar.gz" -o ophan.tar.gz

# Extract
tar -xzf ophan.tar.gz

# Install binary
sudo mv ophan-*/ophan /usr/local/bin/

# Install config
sudo mkdir -p /etc/ophan
sudo cp -r ophan-*/config/* /etc/ophan/
```

### Systemd Service (Linux)

```bash
sudo cp ophan-*/stubs/ophan.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ophan
```

### LaunchDaemon (macOS)

```bash
sudo cp ophan-*/stubs/io.ophan.ophan.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/io.ophan.ophan.plist
```

## Windows — PowerShell

```powershell
# Quick install
powershell -c "iwr -Uri https://github.com/zsweiter/ophan/releases/latest/download/install.ps1 -OutFile install.ps1; .\install.ps1"

# Manual
$VERSION = "v0.1.0"
$ARCH = "x86_64"
$Url = "https://github.com/zsweiter/ophan/releases/download/${VERSION}/ophan-${VERSION#v}-windows-${ARCH}.zip"
Invoke-WebRequest -Uri $Url -OutFile "ophan.zip"
Expand-Archive "ophan.zip" -DestinationPath "C:\Ophan"
```

## Docker

```bash
docker run -p 8080:8080 -v /path/to/config:/etc/ophan ghcr.io/zsweiter/ophan:latest
```

## Verify Checksums

```bash
sha256sum -c ophan-*.tar.gz.sha256
# Or from the release page
curl -sSL https://github.com/zsweiter/ophan/releases/download/v0.1.0/checksums.txt
```

## Next Steps

- Follow the [Quickstart](/quickstart) to write your first configuration.