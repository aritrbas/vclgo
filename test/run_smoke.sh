#!/bin/bash
# End-to-end native preload smoke test against an already-running VPP.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"
require_vpp_paths
require_vclgo_paths

if [ -z "${VCL_CONFIG:-}" ] || [ ! -f "$VCL_CONFIG" ]; then
    echo "run_smoke.sh: set VCL_CONFIG to a readable VCL configuration" >&2
    exit 2
fi

PORT="${PORT:-9876}"
LOG_DIR="${LOG_DIR:-/tmp/vclgo-smoke}"
CLIENT_TIMEOUT="${CLIENT_TIMEOUT:-30}"
mkdir -p "$LOG_DIR"
ulimit -c unlimited 2>/dev/null || true

TRACKED_PIDS=()

spawn_bg() {
    local logfile=$1
    shift
    setsid bash -c 'run_as_user "$@"' _ "$@" >"$logfile" 2>&1 &
    SPAWN_PID=$!
    TRACKED_PIDS+=("$SPAWN_PID")
}

cleanup() {
    local rc=$?
    trap - EXIT INT TERM HUP
    local pid
    for pid in "${TRACKED_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM -"$pid" 2>/dev/null ||
                kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    for _ in $(seq 1 20); do
        local alive=0
        for pid in "${TRACKED_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                alive=1
                break
            fi
        done
        [ "$alive" -eq 0 ] && break
        sleep 0.1
    done
    for pid in "${TRACKED_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL -"$pid" 2>/dev/null ||
                kill -KILL "$pid" 2>/dev/null || true
        fi
    done
    exit "$rc"
}
trap cleanup EXIT INT TERM HUP

echo "[smoke] starting native echo server on 127.0.0.1:$PORT"
spawn_bg "$LOG_DIR/server.log"     "$VCLGO_BIN/vclgo" run "$VCLGO_BIN/examples/echo_server"     -addr "127.0.0.1:$PORT"
SERVER_PID=$SPAWN_PID

ready=0
for _ in $(seq 1 50); do
    if grep -q 'listening on' "$LOG_DIR/server.log" 2>/dev/null; then
        ready=1
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        break
    fi
    sleep 0.2
done
if [ "$ready" -ne 1 ]; then
    echo "[smoke] server failed to become ready" >&2
    cat "$LOG_DIR/server.log" >&2
    exit 1
fi

echo "[smoke] running client"
if run_as_user timeout --kill-after=5 "$CLIENT_TIMEOUT"     "$VCLGO_BIN/vclgo" run "$VCLGO_BIN/examples/echo_client"     -addr "127.0.0.1:$PORT" -conc 4 -msgs 8 -size 1024     >"$LOG_DIR/client.log" 2>&1
then
    echo "[smoke] OK"
    tail -4 "$LOG_DIR/client.log"
else
    rc=$?
    echo "[smoke] FAIL (client rc=$rc)" >&2
    cat "$LOG_DIR/client.log" >&2
    tail -40 "$LOG_DIR/server.log" >&2
    exit 1
fi
