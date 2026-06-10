#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════
# Ophan API Gateway — Installer
#
# Usage:
#   curl -sSL https://github.com/zsweiter/ophan/releases/latest/download/install.sh | bash
#   ./install.sh [--version v0.1.0] [--prefix /usr/local]
#
# Supported: Linux (x86_64, aarch64), macOS (x86_64, aarch64)
# ═══════════════════════════════════════════════════════════════

REPO="zsweiter/ophan"
VERSION="${VERSION:-latest}"
PREFIX="${PREFIX:-/usr/local}"
BINDIR="${BINDIR:-$PREFIX/bin}"
CONFIGDIR="${CONFIGDIR:-/etc/ophan}"
STUBDIR="${STUBDIR:-$PREFIX/lib/ophan}"

# ---- Parse args ----
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --prefix)  PREFIX="$2"; BINDIR="$PREFIX/bin"; shift 2 ;;
        --bindir)  BINDIR="$2"; shift 2 ;;
        --config)  CONFIGDIR="$2"; shift 2 ;;
        --help)    echo "Usage: $0 [--version vX.Y.Z] [--prefix /usr/local]"; exit 0 ;;
        *)         echo "Unknown: $1"; exit 1 ;;
    esac
done

# ---- Detect OS / Arch ----
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64|amd64) ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
    linux)   EXT="tar.gz" ;;
    darwin)  OS="macos"; EXT="tar.gz" ;;
    *)       echo "Unsupported OS: $OS"; exit 1 ;;
esac

# ---- Resolve version ----
if [ "$VERSION" = "latest" ]; then
    VERSION=$(curl -sSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
fi
VERSION="${VERSION#v}" # strip leading v

PACKAGE="ophan-${VERSION}-${OS}-${ARCH}.${EXT}"
DOWNLOAD_URL="https://github.com/$REPO/releases/download/v${VERSION}/$PACKAGE"

# ---- Download ----
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "⬇️  Downloading $PACKAGE ..."
curl -sSL "$DOWNLOAD_URL" -o "$TMPDIR/$PACKAGE"

# ---- Verify checksum ----
CHECKSUM_URL="$DOWNLOAD_URL.sha256"
if CHECKSUM=$(curl -sSL --fail "$CHECKSUM_URL" 2>/dev/null); then
    echo "$CHECKSUM  $TMPDIR/$PACKAGE" | sha256sum -c || {
        echo "❌ Checksum verification failed"
        exit 1
    }
    echo "✅ Checksum verified"
fi

# ---- Extract ----
echo "📦 Extracting ..."
tar -xzf "$TMPDIR/$PACKAGE" -C "$TMPDIR"
EXTRACTED="$TMPDIR/ophan-${VERSION}"

# ---- Install binary ----
echo "🔧 Installing to $BINDIR ..."
mkdir -p "$BINDIR"
cp "$EXTRACTED/ophan" "$BINDIR/ophan"
chmod +x "$BINDIR/ophan"

# ---- Install config ----
echo "📄 Installing config to $CONFIGDIR ..."
mkdir -p "$CONFIGDIR"
if [ -d "$EXTRACTED/config" ]; then
    cp -r "$EXTRACTED/config/"* "$CONFIGDIR/"
fi

# ---- Service registration ----
if [ "$OS" = "linux" ] && command -v systemctl &>/dev/null; then
    echo "🛠️  Installing systemd service ..."
    mkdir -p "$STUBDIR"
    if [ -f "$EXTRACTED/stubs/ophan.service" ]; then
        sed "s|@SBINDIR@|$BINDIR|g; s|@CONFIGDIR@|$CONFIGDIR|g" \
            "$EXTRACTED/stubs/ophan.service" > /tmp/ophan.service
        cp /tmp/ophan.service "$STUBDIR/ophan.service"
        if [ -d /etc/systemd/system ]; then
            cp "$STUBDIR/ophan.service" /etc/systemd/system/ophan.service
            systemctl daemon-reload
            systemctl enable ophan || true
            echo "✅ systemd service installed and enabled"
        fi
    fi
fi

if [ "$OS" = "macos" ]; then
    echo "🛠️  Installing launchd service ..."
    mkdir -p "$STUBDIR"
    if [ -f "$EXTRACTED/stubs/io.ophan.ophan.plist" ]; then
        sed "s|@SBINDIR@|$BINDIR|g; s|@CONFIGDIR@|$CONFIGDIR|g" \
            "$EXTRACTED/stubs/io.ophan.ophan.plist" > /tmp/io.ophan.ophan.plist
        cp /tmp/io.ophan.ophan.plist "$STUBDIR/io.ophan.ophan.plist"
        cp "$STUBDIR/io.ophan.ophan.plist" /Library/LaunchDaemons/io.ophan.ophan.plist 2>/dev/null || true
        launchctl load /Library/LaunchDaemons/io.ophan.ophan.plist 2>/dev/null || true
        echo "✅ launchd service installed"
    fi
fi

echo ""
echo "✅ Ophan v${VERSION} installed successfully!"
echo "   Binary: $BINDIR/ophan"
echo "   Config: $CONFIGDIR"
echo ""
echo "   Start:  sudo systemctl start ophan    (Linux)"
echo "           sudo launchctl start ophan    (macOS)"
echo ""
