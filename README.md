<div align="center">
  <img src="docs/assets/ophan.png" alt="Ophan Gateway" width="500" />
  <br />
  <br />
  <h1>🛡️ Ophan API Gateway</h1>
  <p>
    <b>A lightweight, high-performance edge gateway</b>
    <br />
    built on <a href="https://github.com/cloudflare/pingora">Cloudflare Pingora</a>
  </p>
  <p>
    <img src="https://img.shields.io/badge/status-active_development-yellow?style=flat-square" alt="Status: Active Development" />
    <img src="https://img.shields.io/badge/production-not_recommended-red?style=flat-square" alt="Production: Not Recommended" />
    <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License: MIT" />
  </p>
  <br />
</div>

---

> ⚠️ **DISCLAIMER** — Ophan is under **active development**. APIs, config formats, and behavior may change without notice.  
> It is **not recommended for production use** at this stage. Feedback and contributions are welcome.

---

## 📬 Feedback

Found a bug? Have a suggestion? Reach out:

📧 **zsweiter@gmail.com**

We're early-stage and every piece of feedback helps shape the roadmap.

---

## 🔥 Features

Ophan combines reverse proxy, API gateway, load balancer, and static content delivery into a single modular platform.

| Layer | Capabilities |
|---|---|
| **Protocols** | HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC |
| **Security** | TLS termination, mTLS, JWT / OAuth2, API keys, WAF |
| **Traffic** | Rate limiting, CORS, URL rewriting, load balancing |
| **Resilience** | Health checks, circuit breaking, hot reload |
| **Delivery** | Static file serving, CDN integration, edge caching |
| **Transport** | TCP, Unix Domain Sockets |

---

## 📦 Installation

### Linux / macOS — Quick script

```bash
# Latest release
curl -sSL https://github.com/zsweiter/ophan/releases/latest/download/install.sh | bash

# Specific version
curl -sSL https://github.com/zsweiter/ophan/releases/latest/download/install.sh | bash -s -- --version v0.1.0
```

### Linux / macOS — Manual

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

# Install service (Linux)
sudo cp ophan-*/stubs/ophan.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ophan

# Install service (macOS)
sudo cp ophan-*/stubs/io.ophan.ophan.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/io.ophan.ophan.plist
```

### Windows — PowerShell

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

### Docker

```bash
docker run -p 8080:8080 -v /path/to/config:/etc/ophan ghcr.io/zsweiter/ophan:latest
```

### Verify checksums

Every release includes SHA256 checksums:

```bash
# After downloading a package
sha256sum -c ophan-*.tar.gz.sha256

# Or from the release page
curl -sSL https://github.com/zsweiter/ophan/releases/download/v0.1.0/checksums.txt
```

---

## 🏗️ High-Level Architecture

```mermaid
graph TD
    A[Client Request] --> B[Listener]
    B --> C[Router]
    C --> D[Route Match]
    D --> E[Apply Policies]
    E --> F[Static Content]
    E --> H[Upstream]
    F --> J[Send Response]
    H --> J
    J --> K[Client Response]
```

---

## 🔁 Middleware Pipeline

```
request
  → tls termination
  → cors
  → waf
  → rate limit
  → auth (oauth2 / jwt)
  → rewrite
  → route
  → static / upstream proxy
  → response
```

---

## 🧭 Vision

- **Simplicity** — Declarative config, minimal moving parts
- **Performance** — Zero-copy routing, lock-free hot path, ~5M req/s
- **Hot Reload** — Atomic config swap without dropping connections
- **Modular** — Plug policies, backends, and protocols

---

## 🛠️ Development

```bash
make fmt
make lint
make test
make run
```

### CI pipeline

```bash
make ci          # fmt → lint → test → package (auto-detect OS)
make package-all # Build + package for Linux, macOS, Windows
make package-docker  # Build Docker image (musl)
make checksum    # Generate SHA256 checksums
```

---

## 📄 License

MIT
