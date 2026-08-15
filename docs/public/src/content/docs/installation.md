---
title: Installation
description: Install Ophan API Gateway on Linux, macOS, Windows, or Docker
tags: ["getting-started"]
order: 1
---

## Linux / macOS — Quick Script

```bash
# Latest release
curl -fsSL https://raw.githubusercontent.com/zsweiter/ophan/main/scripts/install.sh | bash

# Specific version
curl -sSL https://raw.githubusercontent.com/zsweiter/ophan/main/scripts/install.sh | bash -s -- --version v0.1.0
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

# Install web assets (served by the gateway on /)
sudo mkdir -p /var/www/html
sudo cp ophan-*/config/public/index.html ophan-*/config/public/favicon.svg /var/www/html/
```

### Systemd Service (Linux)

```bash
# The stub contains @SBINDIR@/@CONFIGDIR@ placeholders — substitute them first
sudo sed -e 's|@SBINDIR@|/usr/local/bin|g' -e 's|@CONFIGDIR@|/etc/ophan|g' \
    ophan-*/stubs/systemd.service | \
    sudo tee /etc/systemd/system/ophan.service > /dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now ophan
```

### LaunchDaemon (macOS)

```bash
sudo sed -e 's|@SBINDIR@|/usr/local/bin|g' -e 's|@CONFIGDIR@|/etc/ophan|g' \
    ophan-*/stubs/io.ophan.ophan.plist | \
    sudo tee /Library/LaunchDaemons/io.ophan.ophan.plist > /dev/null
sudo launchctl bootstrap system /Library/LaunchDaemons/io.ophan.ophan.plist
```

## Windows — PowerShell

```powershell
# Quick install
powershell -c "iwr -Uri https://raw.githubusercontent.com/zsweiter/ophan/main/scripts/install.ps1 -OutFile install.ps1; .\install.ps1"

# Manual
$VERSION = "v0.1.0"
$ARCH = "x86_64"
$Url = "https://github.com/zsweiter/ophan/releases/download/${VERSION}/ophan-${VERSION#v}-windows-${ARCH}.zip"
Invoke-WebRequest -Uri $Url -OutFile "ophan.zip"
Expand-Archive "ophan.zip" -DestinationPath "C:\Ophan"
```

## Docker

```bash
# Maps host port 8080 to the gateway's HTTP listener (port 80)
docker run -p 8080:80 -v /path/to/config:/etc/ophan ghcr.io/zsweiter/ophan:latest
```

## Verify Checksums

```bash
sha256sum -c ophan-*.tar.gz.sha256
# Or download the matching checksum for the exact package, e.g.
curl -sSL https://github.com/zsweiter/ophan/releases/download/v0.1.0/ophan-v0.1.0-linux-x86_64.tar.gz.sha256
```

## Next Steps

- Follow the [Quickstart](/quickstart) to write your first configuration.