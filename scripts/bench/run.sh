#!/usr/bin/env bash
# Gateway benchmark: CPU cost per request of one or more ophan binaries.
#
# Usage:
#   scripts/bench/run.sh [-d SECONDS] [-r ROUNDS] [-c CONNECTIONS] NAME=BINARY [NAME=BINARY ...]
#
# Example:
#   scripts/bench/run.sh -d 15 -r 3 before=/tmp/ophan-main after=target/release/ophan
#
# Requires: go, hey (go install github.com/rakyll/hey@latest), taskset, curl.
# Optional: perf (instructions and cycles per request; needs kernel.perf_event_paranoid <= 1).
#
# CPU sets (adjust to the machine):
#   OPHAN_CPUS=0-3  BACKEND_CPUS=4-7  LOAD_CPUS=8-15
# Ports:
#   PORT=18080  BACKEND_PORT=18081

set -uo pipefail

DURATION=15
ROUNDS=3
CONNECTIONS=64
WARMUP=3

OPHAN_CPUS="${OPHAN_CPUS:-0-3}"
BACKEND_CPUS="${BACKEND_CPUS:-4-7}"
LOAD_CPUS="${LOAD_CPUS:-8-15}"
PORT="${PORT:-18080}"
BACKEND_PORT="${BACKEND_PORT:-18081}"

usage() {
    sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

while getopts "d:r:c:h" opt; do
    case "$opt" in
        d) DURATION="$OPTARG" ;;
        r) ROUNDS="$OPTARG" ;;
        c) CONNECTIONS="$OPTARG" ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

[[ $# -ge 1 ]] || usage

for tool in go hey taskset curl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing: $tool" >&2; exit 1; }
done

PERF=false
if command -v perf >/dev/null 2>&1 && perf stat -e instructions:u -- true >/dev/null 2>&1; then
    PERF=true
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
RESULTS="$WORK/results.txt"
BACKEND_PID=""
OPHAN_PID=""
CLK_TCK="$(getconf CLK_TCK)"

cleanup() {
    [[ -n "$OPHAN_PID" ]] && kill -9 "$OPHAN_PID" 2>/dev/null
    [[ -n "$BACKEND_PID" ]] && kill "$BACKEND_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

wait_port() {
    for _ in $(seq 100); do
        (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

# utime + stime of the whole process, in clock ticks
cpu_ticks() {
    awk '{ print $14 + $15 }' "/proc/$1/stat"
}

stop_ophan() {
    kill -INT "$OPHAN_PID" 2>/dev/null
    for _ in $(seq 100); do
        kill -0 "$OPHAN_PID" 2>/dev/null || break
        sleep 0.1
    done
    kill -9 "$OPHAN_PID" 2>/dev/null
    wait "$OPHAN_PID" 2>/dev/null
    OPHAN_PID=""
}

# ── Configuration ────────────────────────────────────────────

mkdir -p "$WORK/gateways"

cat > "$WORK/master.conf" <<EOF
master "bench" {
    user = "$(id -un)"
    workers = 4
    pid = "$WORK/ophan.pid"
    error_log = "$WORK/error.log"
    includes = "$WORK/gateways/*.conf"
}
EOF

cat > "$WORK/gateways/bench.conf" <<EOF
name = "bench"

listeners {
    listener "http" {
        address = "127.0.0.1:$PORT"
        protocols = ["http1"]
    }
}

upstreams {
    upstream "api" {
        static_servers = ["127.0.0.1:$BACKEND_PORT"]
        health_check = { path = "/health", interval = 5s, timeout = 1s }
    }
}

routes {
    route "/api/*" {
        methods = ["GET", "POST"]
        backend = upstream("api")

        policies {
            limiter = "limiter-bench"
        }

        rewrite {
            strip_prefix "/api"
        }
    }
}

policy limiter "limiter-bench" {
    rate = 100000000/s
    identifier = "ip"
}
EOF

# ── Backend ──────────────────────────────────────────────────

go build -o "$WORK/backend" "$SCRIPT_DIR/backend.go" || exit 1
taskset -c "$BACKEND_CPUS" "$WORK/backend" "127.0.0.1:$BACKEND_PORT" >/dev/null 2>&1 &
BACKEND_PID=$!
wait_port "$BACKEND_PORT" || { echo "backend did not start" >&2; exit 1; }

URL="http://127.0.0.1:$PORT/api/ping"

echo "duration ${DURATION}s, ${ROUNDS} rounds, ${CONNECTIONS} connections, perf: $PERF"
echo "cpus: ophan $OPHAN_CPUS, backend $BACKEND_CPUS, load $LOAD_CPUS"
echo

# ── Rounds (binaries interleaved) ────────────────────────────

for round in $(seq "$ROUNDS"); do
    for spec in "$@"; do
        name="${spec%%=*}"
        bin="${spec#*=}"

        taskset -c "$OPHAN_CPUS" "$bin" -c "$WORK/master.conf" >"$WORK/$name.log" 2>&1 &
        OPHAN_PID=$!

        if ! wait_port "$PORT"; then
            echo "[$name] did not start, see its log:" >&2
            tail -5 "$WORK/$name.log" >&2
            stop_ophan
            continue
        fi

        code=$(curl -s -o /dev/null -w '%{http_code}' "$URL")
        if [[ "$code" != "200" ]]; then
            echo "[$name] smoke request returned $code" >&2
        fi

        taskset -c "$LOAD_CPUS" hey -z "${WARMUP}s" -c "$CONNECTIONS" "$URL" >/dev/null

        cpu_before=$(cpu_ticks "$OPHAN_PID")

        if $PERF; then
            perf stat -x, -e instructions:u,instructions:k,cycles -p "$OPHAN_PID" \
                -o "$WORK/perf-$name.txt" -- sleep "$DURATION" &
            perf_pid=$!
        fi

        out=$(taskset -c "$LOAD_CPUS" hey -z "${DURATION}s" -c "$CONNECTIONS" "$URL")

        $PERF && wait "$perf_pid"
        cpu_after=$(cpu_ticks "$OPHAN_PID")

        ok=$(grep -oP '\[200\]\s+\K\d+' <<<"$out" || echo 0)
        rps=$(awk '/Requests\/sec/ { print $2 }' <<<"$out")
        p50=$(awk '/ 50%+ in/ { print $3 * 1000 }' <<<"$out")
        p99=$(awk '/ 99%+ in/ { print $3 * 1000 }' <<<"$out")

        us_req=$(awk -v t="$((cpu_after - cpu_before))" -v hz="$CLK_TCK" -v n="$ok" \
            'BEGIN { printf "%.1f", (n > 0 ? t / hz * 1e6 / n : 0) }')

        instr_u=0 instr_k=0 cycles=0
        if $PERF; then
            read -r instr_u instr_k cycles < <(awk -F, -v n="$ok" '
                $1 ~ /^[0-9]+$/ && $3 ~ /instructions[:\/]u/ { u += $1 }
                $1 ~ /^[0-9]+$/ && $3 ~ /instructions[:\/]k/ { k += $1 }
                $1 ~ /^[0-9]+$/ && $3 ~ /cycles/              { c += $1 }
                END { if (n > 0) printf "%.0f %.0f %.0f\n", u / n, k / n, c / n; else print "0 0 0" }
            ' "$WORK/perf-$name.txt")
        fi

        printf '%s %s %s %s %s %s %s %s %s\n' \
            "$name" "$round" "$us_req" "$rps" "$p50" "$p99" "$instr_u" "$instr_k" "$cycles" >>"$RESULTS"

        printf 'round %s %-10s %7s us/req  %9.0f req/s  p50 %5.2f ms  p99 %5.2f ms' \
            "$round" "$name" "$us_req" "$rps" "$p50" "$p99"
        $PERF && printf '  user %s instr/req  kernel %s instr/req  %s cycles/req' "$instr_u" "$instr_k" "$cycles"
        printf '\n'

        stop_ophan
        sleep 1
    done
done

# ── Summary ──────────────────────────────────────────────────

echo
echo "average over $ROUNDS rounds"
awk -v perf="$PERF" '
    {
        if (!($1 in n)) order[++count] = $1
        n[$1]++; us[$1] += $3; rps[$1] += $4; p99[$1] += $6
        iu[$1] += $7; ik[$1] += $8; cy[$1] += $9
    }
    END {
        for (i = 1; i <= count; i++) {
            k = order[i]
            printf "%-10s %7.1f us/req  %9.0f req/s  p99 %5.2f ms", k, us[k] / n[k], rps[k] / n[k], p99[k] / n[k]
            if (perf == "true")
                printf "  user %.0f instr/req  kernel %.0f instr/req  %.0f cycles/req", iu[k] / n[k], ik[k] / n[k], cy[k] / n[k]
            printf "\n"
        }
    }
' "$RESULTS"
