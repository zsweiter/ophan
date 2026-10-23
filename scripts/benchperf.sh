#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════
# Ophan — HTTP benchmark harness (ophan vs nginx)
# ═══════════════════════════════════════════════════════════════
#
# Measures identical scenarios twice — first against ophan, then
# against an equally-configured nginx. Both bind the SAME ephemeral
# port one at a time (never concurrently), serving the same files
# through the same micro upstream, so byte counts and keep-alive
# semantics stay comparable.
#
# Scenarios:
#   static_1k     1 KiB static file, keep-alive
#   static_100k   100 KiB static file, keep-alive
#   proxy         reverse-proxy pass-through to the micro upstream
#   purepath      route-matched proxy path (no static stack)
#
# Metrics per scenario and runtime: RPS, latency p50/p90/p99 (wrk or hey),
# plus CPU% of the whole process tree and RSS avg/peak, sampled every
# second from /proc/<pid>/stat and /proc/<pid>/status.  --perf adds a
# perf stat profile of the ophan master process (perf-ophan.txt).
#
# Both stacks run tuned: ophan with nproc workers and a pre-sized upstream
# keep-alive pool; nginx with epoll/multi_accept/sendfile/TCP tuning and
# SO_REUSEPORT accept balancing.
#
# Usage:
#   scripts/benchperf.sh [--tool hey|wrk] [--concurrency N] [--rate N]
#                        [--warmup S] [--duration S]
#                        [--scenarios static_1k,proxy] [--perf]
#                        [--no-nginx] [--keep-tmp] [--help]
#
# Requirements: hey (Debian/Ubuntu: apt install hey; Go: go install
#   github.com/rakyll/hey@latest) and/or wrk in $PATH (or ~/.local/bin/wrk).
# ═══════════════════════════════════════════════════════════════

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

OPHAN_BIN="${OPHAN_BIN:-$REPO_ROOT/target/release/ophan}"
TOOL=hey
CONCURRENCY=64
RATE=0            # total requests/second target (0 = unlimited; wrk cannot)
DURATION=10
WARMUP=2
NPROC="$(nproc)"
SCEN_USER="static_1k,static_100k,proxy,purepath"
WITH_NGINX=true
PERF=false
KEEP_TMP=false

MASTER_PID=""
NGINX_PID=""
UPSTREAM_PID=""
PERF_PID=""
CLK_TCK="$(getconf CLK_TCK 2>/dev/null || echo 100)"

# ──────────────────────────────────────────────────────────────
# Colors & helpers
# ──────────────────────────────────────────────────────────────

if [[ -t 1 ]]; then
    BOLD='\033[1m'; GREEN='\033[32m'; RED='\033[31m'; YELLOW='\033[33m'; RESET='\033[0m'
else
    BOLD=''; GREEN=''; RED=''; YELLOW=''; RESET=''
fi

info() { printf "${GREEN}▸${RESET} %s\n" "$*"; }
warn() { printf "${YELLOW}▸${RESET} %s\n" "$*"; }
fail() { printf "${RED}✖ %s${RESET}\n" "$*" >&2; exit 1; }

usage() {
    sed -n '3,34p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tool)         TOOL=$2;          shift 2 ;;
        --concurrency)  CONCURRENCY=$2;   shift 2 ;;
        --rate)      RATE=$2;          shift 2 ;;
        --warmup)    WARMUP=$2;        shift 2 ;;
        --duration)  DURATION=$2;      shift 2 ;;
        --scenarios) SCEN_USER="$2";   shift 2 ;;
        --no-nginx)  WITH_NGINX=false; shift ;;
        --perf)      PERF=true;        shift ;;
        --keep-tmp)  KEEP_TMP=true;    shift ;;
        -h|--help)   usage ;;
        *) fail "unknown option: $1 (see --help)" ;;
    esac
done

# ──────────────────────────────────────────────────────────────
# Load tool (wrk or hey)
# ──────────────────────────────────────────────────────────────

TOOL_BIN=""
case "$TOOL" in
    hey)
        command -v hey >/dev/null 2>&1 || fail "hey not found — it drives the HTTP load. Install it:
  Debian/Ubuntu: apt install hey
  Go:            GOBIN=~/.local/bin go install github.com/rakyll/hey@latest"
        TOOL_BIN="$(command -v hey)"
        ;;
    wrk)
        for candidate in wrk "$HOME/.local/bin/wrk" /usr/local/bin/wrk; do
            if command -v "$candidate" >/dev/null 2>&1; then TOOL_BIN="$(command -v "$candidate")"; break; fi
            [[ -x "$candidate" ]] && TOOL_BIN="$candidate" && break
        done
        [[ -n "$TOOL_BIN" ]] || fail "wrk not found — build it: git clone --depth 1 https://github.com/wg/wrk && (cd wrk && make) && cp wrk/wrk ~/.local/bin/"
        (( RATE == 0 )) || warn "--rate is ignored with wrk (use wrk2 for constant throughput)"
        ;;
    *) fail "unknown tool '$TOOL' (hey|wrk)" ;;
esac
command -v python3 >/dev/null 2>&1 || fail "python3 not found (needed for the micro upstream)"

if [[ "$PERF" == true ]] && ! command -v perf >/dev/null 2>&1; then
    warn "--perf requested but perf is not installed; running without a profile"
    PERF=false
fi

if [[ "$WITH_NGINX" == true ]]; then
    NGINX_BIN="$(command -v nginx 2>/dev/null || true)"
    [[ -z "$NGINX_BIN" && -x /usr/sbin/nginx ]] && NGINX_BIN=/usr/sbin/nginx
    if [[ -z "$NGINX_BIN" ]]; then
        warn "nginx not installed — running ophan-only benchmarks"
        WITH_NGINX=false
    fi
fi

# ──────────────────────────────────────────────────────────────
# Fixture runtime directory
# ──────────────────────────────────────────────────────────────

ROOT="$(mktemp -d /tmp/ophan-bench-XXXXXX)"
mkdir -p "$ROOT/conf/gateways" "$ROOT/www/api" "$ROOT/run"

PORT_GATEWAY=18080
PORT_UPSTREAM=19001

cleanup() {
    kill_tree "$PERF_PID"
    kill_tree "$MASTER_PID"
    kill_tree "$NGINX_PID"
    kill_tree "$UPSTREAM_PID"
    [[ "$KEEP_TMP" == true ]] || rm -rf "$ROOT"
}
trap cleanup EXIT

# ──────────────────────────────────────────────────────────────
# ophan fixture config — minimal validated set for this run.
# Structure mirrors defaults/config: master.conf includes the
# gateways dir; one flat gateway conf defines the listener, one
# upstream and the route flavours under test.
# ──────────────────────────────────────────────────────────────

CURRENT_USER="$(id -un)"

cat > "$ROOT/conf/master.conf" <<EOF
master "bench" {
    user = "$CURRENT_USER"
    workers = $NPROC
    pid = "$ROOT/run/ophan.pid"
    error_log = "$ROOT/run/ophan-error.log"
    includes = "gateways/*.conf"
}
EOF

cat > "$ROOT/conf/gateways/bench.conf" <<EOF
name = "bench"

listeners {
    listener "http" {
        address = "127.0.0.1:$PORT_GATEWAY"
        protocols = ["http1"]
    }
}

upstreams {
    upstream "api" {
        static_servers = "127.0.0.1:$PORT_UPSTREAM"
    }
}

routes {
    route "/api/*" {
        backend = upstream("api")

        rewrite {
            strip_prefix "/api"
        }
    }

    route "/health" {
        backend = upstream("api")
    }

    route "/*" {
        backend = static("$ROOT/www")

        static_config {
            listing  = false
            dotfiles = false
            index = true
        }
    }
}
EOF

# Payloads: exact byte counts, mildly non-compressible, shared by both runtimes
python3 - "$ROOT/www" <<'PYEOF'
import os, sys
root = sys.argv[1]
pattern = bytes(range(1, 256)) * 500
for name, size in (("api/1k.bin", 1024), ("api/100k.bin", 102400), ("1k.bin", 1024), ("100k.bin", 102400), ("health", 16)):
    with open(os.path.join(root, name), "wb") as f:
        f.write(pattern[:size])
PYEOF

# ──────────────────────────────────────────────────────────────
# nginx fixture — same port + same upstream + same docroot,
# keep-alive on, upstream connections reused (Connection: "").
# ──────────────────────────────────────────────────────────────

cat > "$ROOT/run/nginx.conf" <<EOF
pid $ROOT/run/nginx.pid;
error_log $ROOT/run/nginx-error.log warn;
worker_processes auto;

events {
    use epoll;
    multi_accept on;
    worker_connections 4096;
}

http {
    access_log off;
    sendfile on;
    sendfile_max_chunk 512k;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    keepalive_requests 10000;

    server {
        listen 127.0.0.1:$PORT_GATEWAY reuseport;
        root $ROOT/www;

        location /api/ {
            proxy_pass http://127.0.0.1:$PORT_UPSTREAM/;
            proxy_set_header Host \$host;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_buffering off;
        }

        location /health {
            proxy_pass http://127.0.0.1:$PORT_UPSTREAM/health;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_buffering off;
        }
    }
}
EOF

# ──────────────────────────────────────────────────────────────
# Process helpers
# ──────────────────────────────────────────────────────────────

kill_tree() {
    [[ -z "${1:-}" ]] && return 0
    pkill -TERM -P "$1" 2>/dev/null || true
    kill -TERM "$1" 2>/dev/null || true
}

tree_pids() {  # master + its immediate children (ophan/nginx workers)
    local pid="$1"
    echo "$pid"
    [[ -n "$pid" ]] && pgrep -P "$pid" 2>/dev/null || true
}

proc_ticks() {  # sum utime+stime (clock ticks) over the process tree
    local total=0 p v
    for p in "$@"; do
        [[ -n "$p" && -r "/proc/$p/stat" ]] || continue
        v=$(awk '{print $14 + $15}' "/proc/$p/stat" 2>/dev/null || echo 0)
        total=$((total + v))
    done
    echo "$total"
}

proc_rss_kb() {
    local total=0 p v
    for p in "$@"; do
        [[ -n "$p" && -r "/proc/$p/status" ]] || continue
        v=$(awk '/^VmRSS:/ {print $2}' "/proc/$p/status" 2>/dev/null || echo 0)
        total=$((total + v))
    done
    echo "$total"
}

# Samples once per second until the stop file appears, then emits
# "<cpu_avg_pct> <rss_avg_kb> <rss_peak_kb>" into the output file.
resource_sampler() {  # $1 pidfile  $2 outfile  $3 stopfile
    local pidfile=$1 outfile=$2 stopfile=$3
    local prev=0 ticks pids rss
    local n_rates=0 sum_rates=0 n_rss=0 sum_rss=0 peak=0

    while [[ ! -f "$stopfile" ]]; do
        pids=$(tree_pids "$(cat "$pidfile" 2>/dev/null || echo "")" 2>/dev/null || true)
        ticks=$(proc_ticks $pids)
        rss=$(proc_rss_kb $pids)

        if (( prev > 0 )); then
            # delta_ticks / CLK_TCK per 1s sample = CPU% of one core
            sum_rates=$((sum_rates + (ticks - prev) * 100 / CLK_TCK))
            n_rates=$((n_rates + 1))
        fi
        sum_rss=$((sum_rss + rss)); n_rss=$((n_rss + 1))
        (( rss > peak )) && peak=$rss
        prev=$ticks
        sleep 1
    done

    local cpu=0 rss_avg=0
    (( n_rates > 0 )) && cpu=$((sum_rates / n_rates))
    (( n_rss > 0 )) && rss_avg=$((sum_rss / n_rss))
    echo "$cpu $rss_avg $peak" > "$outfile"
}

# ──────────────────────────────────────────────────────────────
# Run subjects
# ──────────────────────────────────────────────────────────────

start_upstream() {
    # Micro upstream standalone: HTTP/1.1 keep-alive enabled explicitly.
    python3 - "$ROOT/www" "$PORT_UPSTREAM" <<'PYEOF' > "$ROOT/run/upstream.log" 2>&1 &
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class KeepAlive(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"


upstream = ThreadingHTTPServer(("127.0.0.1", int(sys.argv[2])), KeepAlive)
upstream.request_queue_size = 512
upstream.serve_forever()
PYEOF
    UPSTREAM_PID=$!
}

validate_ophan() {
    info "Validating ophan fixture config (ophan -t)"
    if ! "$OPHAN_BIN" -t -c "$ROOT/conf/master.conf" > "$ROOT/run/validate.log" 2>&1; then
        echo "── ophan -t output ──" >&2
        cat "$ROOT/run/validate.log" >&2
        echo "─────────────────────" >&2
        fail "fixture config rejected by ophan — nothing was benchmarked"
    fi
}

wait_port() {  # $1 = port
    for _ in $(seq 1 50); do
        (echo > /dev/tcp/127.0.0.1/"$1") 2>/dev/null && return 0
        sleep 0.2
    done
    return 1
}

start_ophan() {
    "$OPHAN_BIN" --pid-file "$ROOT/run/ophan.pid" -c "$ROOT/conf/master.conf" \
        > "$ROOT/run/ophan.log" 2>&1 &
    MASTER_PID=$!
    wait_port "$PORT_GATEWAY" || { cat "$ROOT/run/ophan.log" >&2; fail "ophan did not open :$PORT_GATEWAY"; }
}

start_nginx() {
    "$NGINX_BIN" -c "$ROOT/run/nginx.conf" -p "$ROOT/run" > "$ROOT/run/nginx-stdout.log" 2>&1
    NGINX_PID="$(cat "$ROOT/run/nginx.pid")"
    wait_port "$PORT_GATEWAY" || { cat "$ROOT/run/nginx-error.log" >&2; fail "nginx did not open :$PORT_GATEWAY"; }
}

stop_nginx() {
    kill -QUIT "$NGINX_PID" 2>/dev/null || true
    sleep 0.5
    NGINX_PID=""
}

# ──────────────────────────────────────────────────────────────
# Load-tool invocation & parsing (wrk or hey)
# ──────────────────────────────────────────────────────────────

tool_flags() {  # $1 = seconds
    if [[ "$TOOL" == hey ]]; then
        printf -- "-c %d -z %ds -keepalive" "$CONCURRENCY" "$1"
    else
        local threads=$(( CONCURRENCY < NPROC ? CONCURRENCY : NPROC ))
        printf -- "-t%d -c%d -d%ds --latency" "$threads" "$CONCURRENCY" "$1"
    fi
}

rate_flags() {  # hey -q is QPS *per connection*
    if [[ "$TOOL" == hey && $RATE -gt 0 ]]; then
        awk -v r="$RATE" -v c="$CONCURRENCY" 'BEGIN { printf "-q %.3f", r / c }'
    fi
}

# Latency rows read like:
#   hey: `  50% in 0.0010 secs`      -> field $3 (unit: secs)
#   wrk: `     50%   1.05ms`         -> field $2 (unit: ms/us)
parse_rps() {
    awk '/^Requests\/(sec):/ {print $2}' "$1"
}

parse_latency() {
    if [[ "$TOOL" == hey ]]; then
        awk -v q="$2%" '$1 == q {print $3}' "$1"
    else
        awk -v q="$2%" '$1 == q {print $2}' "$1"
    fi
}

run_one() {  # $1 subject  $2 url  $3 tool-out-file  $4 pidfile
    local subject=$1 url=$2 out=$3 pidfile=$4
    local stopfile="$ROOT/run/stop.flag"
    rm -f "$stopfile"

    # optional perf profile of the "ophan" tree (discarded runs keep it hidden)
    if [[ "$PERF" == true && "$subject" == *ophan* ]]; then
        perf stat -o "$ROOT/run/perf-ophan.txt" -p "$(cat "$pidfile" 2>/dev/null || echo 1)" \
            -- sleep "$DURATION" &
        PERF_PID=$!
    fi

    # warmup run, discarded
    "$TOOL_BIN" $(tool_flags "$WARMUP") $(rate_flags) "$url" > /dev/null 2>&1 || true

    resource_sampler "$pidfile" "$ROOT/run/res-$subject.txt" "$stopfile" &
    local sampler_pid=$!

    "$TOOL_BIN" $(tool_flags "$DURATION") $(rate_flags) "$url" > "$out" 2>&1 \
        || warn "$TOOL reported errors — full output in $out"

    touch "$stopfile"
    wait "$sampler_pid" 2>/dev/null || true
    [[ -z "$PERF_PID" ]] || { sleep 1; kill_tree "$PERF_PID"; PERF_PID=""; }
}

# ──────────────────────────────────────────────────────────────
# Corpus flow
# ──────────────────────────────────────────────────────────────

SCENARIOS=(
    "static_1k|1k.bin"
    "static_100k|100k.bin"
    "proxy|api/100k.bin"
    "purepath|health"
)

bench_scenario() {  # $1 name  $2 url-path
    local name=$1 path=$2

    start_ophan
    run_one ophan "http://127.0.0.1:$PORT_GATEWAY/$path" "$ROOT/run/$name-ophan.hey" "$ROOT/run/ophan.pid"
    kill_tree "$MASTER_PID"; MASTER_PID=""

    # give the OS a few cycles to free the port before nginx rebinds it
    for _ in {1..30}; do
        wait_port "$PORT_GATEWAY" 2>/dev/null || break
        sleep 0.3
    done

    [[ "$WITH_NGINX" == true ]] || return 0

    start_nginx
    run_one nginx "http://127.0.0.1:$PORT_GATEWAY/$path" "$ROOT/run/$name-nginx.hey" "$ROOT/run/nginx.pid"
    stop_nginx
}

[[ -x "$OPHAN_BIN" ]] || fail "ophan binary not found at $OPHAN_BIN — build it first: make build"

validate_ophan
info "Starting micro upstream on :$PORT_UPSTREAM"
start_upstream
wait_port "$PORT_UPSTREAM" || { cat "$ROOT/run/upstream.log" >&2; fail "upstream did not start"; }

info "Benchmarking: tool=$TOOL scenarios=[$SCEN_USER] duration=${DURATION}s warmup=${WARMUP}s concurrency=$CONCURRENCY workers=$NPROC rate=${RATE:-unlimited}"

declare -A OP_RPS OP_P50 OP_P90 OP_P99 OP_CPU OP_RSS OP_PEAK
declare -A NG_RPS NG_P50 NG_P90 NG_P99 NG_CPU NG_RSS NG_PEAK

for entry in "${SCENARIOS[@]}"; do
    name="${entry%%|*}"; path="${entry##*|}"
    [[ ",$SCEN_USER," == *",$name,"* ]] || continue

    info "▶ scenario: $name"
    bench_scenario "$name" "$path"

    f="$ROOT/run/$name-ophan.hey"
    OP_RPS[$name]="$(parse_rps "$f")"
    OP_P50[$name]="$(parse_latency "$f" 50)"
    OP_P90[$name]="$(parse_latency "$f" 90)"
    OP_P99[$name]="$(parse_latency "$f" 99)"
    read -r c r p < "$ROOT/run/res-ophan.txt"
    OP_CPU[$name]="$c"; OP_RSS[$name]="$r"; OP_PEAK[$name]="$p"

    if [[ "$WITH_NGINX" == true ]]; then
        f="$ROOT/run/$name-nginx.hey"
        NG_RPS[$name]="$(parse_rps "$f")"
        NG_P50[$name]="$(parse_latency "$f" 50)"
        NG_P90[$name]="$(parse_latency "$f" 90)"
        NG_P99[$name]="$(parse_latency "$f" 99)"
        read -r c r p < "$ROOT/run/res-nginx.txt"
        NG_CPU[$name]="$c"; NG_RSS[$name]="$r"; NG_PEAK[$name]="$p"
    fi
done

kill_tree "$UPSTREAM_PID"; UPSTREAM_PID=""

# ═════════════════════════════════════════════════════════════
# Markdown summary
# ═════════════════════════════════════════════════════════════

echo ""
echo "### Results — ophan vs nginx"
echo ""
echo "| scenario | stack | rps | p50 | p90 | p99 | cpu% | rss_avg_kb | rss_peak_kb |"
echo "|----------|-------|-----|-----|-----|-----|------|------------|-------------|"

emit_row() {  # $1 scenario  $2 array prefix  $3 label
    local name=$1 prefix=$2 label=$3
    local rps r50 r90 r99 cpu rss peak
    rps=${prefix}RPS; r50=${prefix}P50; r90=${prefix}P90; r99=${prefix}P99
    cpu=${prefix}CPU; rss=${prefix}RSS; peak=${prefix}PEAK
    printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s |\n" \
        "$name" "$label" \
        "${!rps}" "${!r50}" "${!r90}" "${!r99}" \
        "${!cpu}" "${!rss}" "${!peak}"
}

for entry in "${SCENARIOS[@]}"; do
    name="${entry%%|*}"; path="${entry##*|}"
    [[ ",$SCEN_USER," == *",$name,"* ]] || continue
    emit_row "$name" OP_ ophan
    [[ "$WITH_NGINX" == true ]] && emit_row "$name" NG_ nginx
done

echo ""
printf "${BOLD}Raw wrk/hey outputs and logs:${RESET} %s/run/\n" "$ROOT"
[[ "$KEEP_TMP" == true ]] || echo "(fixture removed; rerun with --keep-tmp to inspect)"
