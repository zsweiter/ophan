#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════
# Ophan API Gateway — Installer
# ═══════════════════════════════════════════════════════════════

REPO="zsweiter/ophan"

VERSION="${VERSION:-latest}"
PREFIX="${PREFIX:-/usr/local}"
BINDIR="${BINDIR:-$PREFIX/bin}"
CONFIGDIR="${CONFIGDIR:-/etc/ophan}"

SERVICE_NAME="ophan"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

UPGRADE=false
FORCE=false

TMPDIR=""

# ──────────────────────────────────────────────────────────────
# Colors
# ──────────────────────────────────────────────────────────────

if [[ -t 1 ]]; then
    RESET='\033[0m'
    BOLD='\033[1m'
    DIM='\033[2m'

    RED='\033[31m'
    GREEN='\033[32m'
    YELLOW='\033[33m'
    BLUE='\033[34m'
    CYAN='\033[36m'
else
    RESET=''
    BOLD=''
    DIM=''

    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
fi

# ──────────────────────────────────────────────────────────────
# UI
# ──────────────────────────────────────────────────────────────

line() {
    printf '%s\n' \
        "────────────────────────────────────────────────────────────"
}

header() {
    printf '\n'
    printf '%b\n' "${BOLD}${CYAN}  Ophan API Gateway${RESET}"
    printf '%b\n' "${DIM}  Installer${RESET}"
    printf '\n'
}

step() {
    printf '\n%b%s%b\n' "${BOLD}${BLUE}▶${RESET} " "$1" "$RESET"
}

ok() {
    printf '  %b[ OK ]%b %s\n' "${GREEN}${BOLD}" "$RESET" "$1"
}

warn() {
    printf '  %b[WARN]%b %s\n' "${YELLOW}${BOLD}" "$RESET" "$1"
}

fail() {
    printf '  %b[FAIL]%b %s\n' "${RED}${BOLD}" "$RESET" "$1" >&2
    exit 1
}

info() {
    printf '  %b•%b %s\n' "${DIM}" "$RESET" "$1"
}

# ──────────────────────────────────────────────────────────────
# Cleanup
# ──────────────────────────────────────────────────────────────

cleanup() {
    if [[ -n "$TMPDIR" && -d "$TMPDIR" ]]; then
        rm -rf "$TMPDIR"
    fi
}

trap cleanup EXIT

# ──────────────────────────────────────────────────────────────
# Help
# ──────────────────────────────────────────────────────────────

usage() {
    cat <<EOF

Usage:
  $0 [options]

Options:
  --version VERSION   Install a specific version (default: latest)
  --prefix PATH       Installation prefix (default: /usr/local)
  --bindir PATH       Binary directory (default: PREFIX/bin)
  --config PATH       Configuration directory (default: /etc/ophan)
  --no-service        Do not install systemd service
  --upgrade           Hot upgrade: replace binary with new version (SIGQUIT)
  --force             Force overwrite of existing config/binary even if same version
  --help              Show this help

Idempotent: safe to re-run. By default existing configs are preserved (use --force to overwrite).

Examples:
  sudo ./install.sh
  sudo ./install.sh --version 0.1.23
  sudo ./install.sh --prefix /opt/ophan
  sudo ./install.sh --no-service
  sudo ./install.sh --upgrade --version 0.1.27

EOF
}

# ──────────────────────────────────────────────────────────────
# Parse arguments
# ──────────────────────────────────────────────────────────────

INSTALL_SERVICE=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            [[ $# -ge 2 ]] || fail "--version requires a value"
            VERSION="$2"
            shift 2
            ;;

        --prefix)
            [[ $# -ge 2 ]] || fail "--prefix requires a value"
            PREFIX="$2"
            BINDIR="$PREFIX/bin"
            shift 2
            ;;

        --bindir)
            [[ $# -ge 2 ]] || fail "--bindir requires a value"
            BINDIR="$2"
            shift 2
            ;;

        --config)
            [[ $# -ge 2 ]] || fail "--config requires a value"
            CONFIGDIR="$2"
            shift 2
            ;;

        --no-service)
            INSTALL_SERVICE=false
            shift
            ;;

        --upgrade)
            UPGRADE=true
            shift
            ;;

        --force|--reinstall)
            FORCE=true
            shift
            ;;

        --help|-h)
            usage
            exit 0
            ;;

        *)
            fail "Unknown argument: $1"
            ;;
    esac
done

# ──────────────────────────────────────────────────────────────
# Header
# ──────────────────────────────────────────────────────────────

header

# ──────────────────────────────────────────────────────────────
# Check privileges
# ──────────────────────────────────────────────────────────────

step "Checking privileges"

if [[ "$EUID" -ne 0 ]]; then
    # if command -v sudo >/dev/null 2>&1; then
    #     info "Root privileges required"
    #     info "Re-running installer with sudo"
    #     exec sudo "$0" "$@"
    # fi

    fail "This installer requires root privileges. Run it with sudo."
fi

ok "Running as root"

# ──────────────────────────────────────────────────────────────
# Dependencies
# ──────────────────────────────────────────────────────────────

step "Checking dependencies"

command -v curl >/dev/null 2>&1 ||
    fail "curl is required"

command -v tar >/dev/null 2>&1 ||
    fail "tar is required"

ok "curl"
ok "tar"

# ──────────────────────────────────────────────────────────────
# Detect platform
# ──────────────────────────────────────────────────────────────

step "Detecting platform"

OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)
        OS="linux"
        ;;

    Darwin)
        OS="macos"
        ;;

    *)
        fail "Unsupported operating system: $OS"
        ;;
esac

case "$ARCH" in
    x86_64|amd64)
        ARCH="x86_64"
        ;;

    arm64|aarch64)
        ARCH="aarch64"
        ;;

    *)
        fail "Unsupported architecture: $ARCH"
        ;;
esac

ok "Platform: ${OS}-${ARCH}"

# ──────────────────────────────────────────────────────────────
# Resolve version
# ──────────────────────────────────────────────────────────────

step "Resolving release"

if [[ "$VERSION" == "latest" ]]; then
    VERSION="$(
        curl -fsSL \
            "https://api.github.com/repos/$REPO/releases/latest" |
        sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' |
        head -n 1
    )"

    [[ -n "$VERSION" ]] ||
        fail "Unable to determine latest release"
fi

VERSION="${VERSION#v}"

ok "Version: v${VERSION}"

if [[ -x "$BINDIR/ophan" && "$FORCE" != true && "$UPGRADE" != true ]]; then
    INSTALLED_VER="$("$BINDIR/ophan" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
    if [[ "$INSTALLED_VER" == "$VERSION" ]]; then
        info "Already at v${VERSION} at $BINDIR/ophan (use --force to reinstall or --upgrade for hot upgrade)"
    fi
fi

# ──────────────────────────────────────────────────────────────
# Package
# ──────────────────────────────────────────────────────────────

PACKAGE="ophan-${VERSION}-${OS}-${ARCH}.tar.gz"

BASE_URL="https://github.com/${REPO}/releases/download/v${VERSION}"

DOWNLOAD_URL="${BASE_URL}/${PACKAGE}"
CHECKSUM_URL="${DOWNLOAD_URL}.sha256"

# ──────────────────────────────────────────────────────────────
# Temporary directory
# ──────────────────────────────────────────────────────────────

TMPDIR="$(mktemp -d)"

# ──────────────────────────────────────────────────────────────
# Download
# ──────────────────────────────────────────────────────────────

step "Downloading release"

info "$PACKAGE"

curl -fL \
    --retry 3 \
    --retry-delay 1 \
    "$DOWNLOAD_URL" \
    -o "$TMPDIR/$PACKAGE"

ok "Download complete"

# ──────────────────────────────────────────────────────────────
# Verify checksum
# ──────────────────────────────────────────────────────────────

step "Verifying integrity"

if curl -fLs \
    "$CHECKSUM_URL" \
    -o "$TMPDIR/$PACKAGE.sha256"; then

    if command -v sha256sum >/dev/null 2>&1; then
        (
            cd "$TMPDIR"
            sha256sum -c "$PACKAGE.sha256"
        )

    elif command -v shasum >/dev/null 2>&1; then

        EXPECTED="$(
            awk '{print $1}' "$TMPDIR/$PACKAGE.sha256"
        )"

        ACTUAL="$(
            shasum -a 256 "$TMPDIR/$PACKAGE" |
            awk '{print $1}'
        )"

        [[ "$EXPECTED" == "$ACTUAL" ]] ||
            fail "Checksum verification failed"

    else
        fail "No SHA-256 implementation found"
    fi

    ok "Checksum verified"
else
    warn "Checksum file unavailable"
fi

# ──────────────────────────────────────────────────────────────
# Extract
# ──────────────────────────────────────────────────────────────

step "Extracting package"

tar -xzf \
    "$TMPDIR/$PACKAGE" \
    -C "$TMPDIR"

EXTRACTED="$TMPDIR/ophan-${VERSION}-${OS}-${ARCH}"

if [[ ! -d "$EXTRACTED" ]]; then
    echo
    warn "Archive contents:"
    tar -tzf "$TMPDIR/$PACKAGE"
    fail "Invalid archive layout"
fi

ok "Package extracted"

# ──────────────────────────────────────────────────────────────
# Install binary
# ──────────────────────────────────────────────────────────────

step "Installing Ophan"

mkdir -p "$BINDIR"

if [[ -f "$BINDIR/ophan" ]]; then
    BACKUP_BIN="${BINDIR}/ophan.bak.$(date +%s)"
    cp -a "$BINDIR/ophan" "$BACKUP_BIN" 2>/dev/null || true
    info "Backup of previous binary: $BACKUP_BIN"
fi

install \
    -m 755 \
    "$EXTRACTED/ophan" \
    "$BINDIR/ophan"

ok "Binary installed"
info "$BINDIR/ophan"

# ──────────────────────────────────────────────────────────────
# Install configuration
# ──────────────────────────────────────────────────────────────

step "Installing configuration"

mkdir -p "$CONFIGDIR"

if [[ -d "$EXTRACTED/config" ]]; then
    if [[ -f "$CONFIGDIR/master.conf" && "$FORCE" != true ]]; then
        warn "Config already exists at $CONFIGDIR — preserving (use --force to overwrite)"
        info "Skipping config overwrite (idempotent)"
    else
        cp -R \
            "$EXTRACTED/config/." \
            "$CONFIGDIR/"

        chmod -R u=rwX,go=rX "$CONFIGDIR"

        ok "Configuration installed"
        info "$CONFIGDIR"
    fi
else
    warn "No configuration directory found in package"
fi

# ──────────────────────────────────────────────────────────────
# Install web assets (index.html + favicon)
# ──────────────────────────────────────────────────────────────

step "Installing web assets"

WEBROOT="/var/www/html"

mkdir -p "$WEBROOT"

WEB_SRC=""

if [[ -f "$EXTRACTED/config/public/index.html" ]]; then
    WEB_SRC="$EXTRACTED/config/public"
elif [[ -f "$EXTRACTED/www/index.html" ]]; then
    WEB_SRC="$EXTRACTED/www"
elif [[ -f "$EXTRACTED/defaults/www/index.html" ]]; then
    WEB_SRC="$EXTRACTED/defaults/www"
fi

if [[ -n "$WEB_SRC" && -f "$WEB_SRC/index.html" ]]; then

    install \
        -m 644 \
        "$WEB_SRC/index.html" \
        "$WEBROOT/index.html"

    install \
        -m 644 \
        "$WEB_SRC/favicon.svg" \
        "$WEBROOT/favicon.svg"

    if id www-data >/dev/null 2>&1; then
        chown www-data:www-data \
            "$WEBROOT/index.html" \
            "$WEBROOT/favicon.svg"
    fi

    ok "Web assets installed"
    info "$WEBROOT/index.html"
    info "$WEBROOT/favicon.svg"
else
    warn "No web assets found in package"
fi

# ──────────────────────────────────────────────────────────────
# Install systemd service
# ──────────────────────────────────────────────────────────────

if [[ "$OS" == "linux" && "$INSTALL_SERVICE" == true ]]; then

    step "Installing systemd service"

    if ! command -v systemctl >/dev/null 2>&1; then
        warn "systemd is not available"
    elif [[ ! -f "$EXTRACTED/stubs/systemd.service" ]]; then
        warn "systemd.service not found in package"
    else

        sed \
            -e "s|@SBINDIR@|$BINDIR|g" \
            -e "s|@CONFIGDIR@|$CONFIGDIR|g" \
            "$EXTRACTED/stubs/systemd.service" \
            > "$SERVICE_FILE"

        chmod 644 "$SERVICE_FILE"

        systemctl daemon-reload

        systemctl enable "$SERVICE_NAME"

        ok "systemd service installed"
        info "$SERVICE_FILE"
        info "Enabled: yes"
    fi
fi

# ──────────────────────────────────────────────────────────────
# Validate installation
# ──────────────────────────────────────────────────────────────

step "Validating installation"

if [[ ! -x "$BINDIR/ophan" ]]; then
    fail "Binary installation failed"
fi

ok "Binary is executable"

if [[ "$OS" == "linux" &&
      "$INSTALL_SERVICE" == true &&
      -f "$SERVICE_FILE" ]]; then

    if systemctl is-enabled \
        "$SERVICE_NAME" \
        >/dev/null 2>&1; then

        ok "systemd service is enabled"
    else
        warn "systemd service is not enabled"
    fi
fi

# ──────────────────────────────────────────────────────────────
# Start service (with port 80 diagnostic)
# ──────────────────────────────────────────────────────────────

if [[ "$OS" == "linux" &&
      "$INSTALL_SERVICE" == true &&
      -f "$SERVICE_FILE" ]]; then

    if [[ "$UPGRADE" == true ]] && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        step "Hot upgrade (zero-downtime) via Pingora"

        # Validate new binary can parse current config before signalling
        if [[ -f "$CONFIGDIR/master.conf" ]]; then
            if ! "$BINDIR/ophan" -t -c "$CONFIGDIR/master.conf" >/dev/null 2>&1; then
                warn "Config test failed with new binary — aborting hot upgrade"
                fail "Run with --force to bypass or fix $CONFIGDIR/master.conf"
            fi
            ok "Config test passed with new binary"
        fi

        PIDFILE="/run/ophan.pid"
        # Try to get PID from config if custom
        if [[ -f "$CONFIGDIR/master.conf" ]]; then
            CFG_PID="$(sed -n 's/.*pid[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIGDIR/master.conf" | head -n1 || true)"
            [[ -n "$CFG_PID" ]] && PIDFILE="$CFG_PID"
        fi

        OLD_PID="$(cat "$PIDFILE" 2>/dev/null | tr -d '[:space:]' || true)"

        if [[ -n "$OLD_PID" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
            info "Current PID: $OLD_PID → sending SIGQUIT for graceful upgrade"
            if kill -QUIT "$OLD_PID" 2>/dev/null; then ok "Sent SIGQUIT to $OLD_PID"
            elif "$BINDIR/ophan" --upgrade >/dev/null 2>&1; then ok "Sent upgrade via ophan --upgrade"
            else warn "SIGQUIT failed"; fi

            sleep 2
            # Health check — new PID should appear
            for i in $(seq 1 12); do
                sleep 1
                if [[ -f "$PIDFILE" ]]; then
                    NEW_PID="$(cat "$PIDFILE" 2>/dev/null | tr -d '[:space:]' || true)"
                    if [[ -n "$NEW_PID" && "$NEW_PID" != "$OLD_PID" ]] && kill -0 "$NEW_PID" 2>/dev/null; then
                        ok "Hot upgrade succeeded — new PID $NEW_PID"
                        break
                    fi
                fi
                if [[ $i -eq 12 ]]; then
                    warn "Hot upgrade did not rotate PID — falling back to restart"
                    systemctl restart "$SERVICE_NAME" || fail "systemctl restart failed"
                    ok "Service restarted via systemd"
                fi
            done
        else
            warn "No running PID found — doing cold start"
            systemctl restart "$SERVICE_NAME" 2>/dev/null || systemctl start "$SERVICE_NAME" || fail "systemctl start failed"
            ok "Service started"
        fi

        # Final health
        sleep 1
        if systemctl is-active --quiet "$SERVICE_NAME"; then ok "Service is active"
        else fail "Service not active after upgrade — check: journalctl -u $SERVICE_NAME -f"; fi

    else
        step "Starting service"

        PORT_PROGRAM=""

        if command -v ss >/dev/null 2>&1; then
            PORT_PROGRAM="$(
                ss -ltnp 'sport = :80' 2>/dev/null |
                sed -n '2p'
            )"
        elif command -v lsof >/dev/null 2>&1; then
            PORT_PROGRAM="$(
                lsof -nP -iTCP:80 -sTCP:LISTEN 2>/dev/null |
                sed -n '2p'
            )"
        elif command -v fuser >/dev/null 2>&1; then
            PORT_PROGRAM="$(fuser 80/tcp 2>&1 || true)"
        fi

        if [[ -n "$PORT_PROGRAM" && "$FORCE" != true && "$UPGRADE" != true ]]; then
            if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
                info "Port 80 in use by active ophan service — skipping start (idempotent)"
            else
                fail "Ophan could not be started because another service is already using port 80: $PORT_PROGRAM"
            fi
        else
            [[ -z "$PORT_PROGRAM" ]] && ok "Port 80 is free" || info "Port 80 in use — proceeding with restart (force/upgrade)"

            if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
                if systemctl restart "$SERVICE_NAME" >/dev/null 2>&1; then ok "Service restarted"
                else fail "systemctl restart failed — check: journalctl -u $SERVICE_NAME -f"; fi
            else
                if systemctl start "$SERVICE_NAME" >/dev/null 2>&1; then ok "Service started"
                else fail "Ophan could not be started. Check the logs: journalctl -u $SERVICE_NAME -f"; fi
            fi
        fi
    fi
fi

# ──────────────────────────────────────────────────────────────
# Final
# ──────────────────────────────────────────────────────────────

printf '\n'
line
printf '\n'

printf '%b\n' \
    "${GREEN}${BOLD}  Ophan v${VERSION} installed successfully.${RESET}"

printf '\n'

info "Binary   : $BINDIR/ophan"
info "Config   : $CONFIGDIR"

if [[ "$OS" == "linux" &&
      "$INSTALL_SERVICE" == true &&
      -f "$SERVICE_FILE" ]]; then

    info "Service  : $SERVICE_FILE"

    printf '\n'
    printf '%b\n' "${BOLD}  Next steps${RESET}"
    printf '\n'

    printf '  Start service:\n'
    printf '    %bsudo systemctl start ophan%b\n' "$CYAN" "$RESET"

    printf '\n'

    printf '  Check status:\n'
    printf '    %bsystemctl status ophan%b\n' "$CYAN" "$RESET"

    printf '\n'

    printf '  View logs:\n'
    printf '    %bjournalctl -u ophan -f%b\n' "$CYAN" "$RESET"
fi

printf '\n'
line
printf '\n'
