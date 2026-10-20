#!/bin/sh
# Ophan container entrypoint: prepare runtime dirs / config, then exec the gateway.
set -eu

OPHAN_BIN="${OPHAN_BIN:-/usr/local/bin/ophan}"
CONFIG_DIR="${OPHAN_CONFIG_DIR:-/etc/ophan}"
CONFIG_SEED_DIR="${OPHAN_CONFIG_SEED_DIR:-/usr/share/ophan/config}"
DEFAULT_CONFIG="${CONFIG_DIR}/master.conf"
WWW_DIR="${OPHAN_WWW_DIR:-/var/www}"
LOG_DIR="${OPHAN_LOG_DIR:-/var/log/ophan}"
RUN_DIR="${OPHAN_RUN_DIR:-/var/run/ophan}"

warn() { 
    printf 'ophan-entrypoint: %s\n' "$*" >&2; 
}

for dir in "$CONFIG_DIR" "$WWW_DIR" "$LOG_DIR" "$RUN_DIR"; do
    mkdir -p "$dir" 2>/dev/null || warn "cannot create '$dir' (read-only volume?)"
done

if [ ! -f "$DEFAULT_CONFIG" ]; then
    if [ -d "$CONFIG_SEED_DIR" ]; then
        warn "no config at $DEFAULT_CONFIG — seeding defaults from $CONFIG_SEED_DIR"
        cp -R "$CONFIG_SEED_DIR/." "$CONFIG_DIR/" 2>/dev/null \
            || warn "could not seed $CONFIG_DIR — mount your own master.conf"
    else
        warn "no config at $DEFAULT_CONFIG and no seed directory available"
    fi
fi

if [ -n "${OPHAN_SOCKET_PATH:-}" ]; then
    sock_dir=$(dirname "$OPHAN_SOCKET_PATH")
    if ! mkdir -p "$sock_dir" 2>/dev/null; then
        warn "cannot create socket directory '$sock_dir' — listener unix:$OPHAN_SOCKET_PATH will not bind"
    elif [ ! -w "$sock_dir" ]; then
        warn "socket directory '$sock_dir' is not writable by '$(id -un)' — mount it writable or run with --user root"
    fi
fi

export CONFIG_PATH="${CONFIG_PATH:-$DEFAULT_CONFIG}"
export OPHAN_PID_FILE="${OPHAN_PID_FILE:-$RUN_DIR/ophan.pid}"

if [ "${OPHAN_SKIP_CONFIG_TEST:-0}" != "1" ] && [ -f "$CONFIG_PATH" ]; then
    if ! "$OPHAN_BIN" -t -c "$CONFIG_PATH"; then
        warn "configuration test failed for $CONFIG_PATH"
        warn "fix the config or set OPHAN_SKIP_CONFIG_TEST=1 to start anyway"
        exit 1
    fi
fi

if [ "$#" -eq 0 ]; then
    set -- -c "$CONFIG_PATH"
fi

case "$1" in
    -*)
        exec "$OPHAN_BIN" "$@"
        ;;
    *)
        # An explicit command was passed (e.g. `docker run … sh`)
        exec "$@"
        ;;
esac
