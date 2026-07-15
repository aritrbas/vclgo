#!/bin/bash
# Multi-owner stress: payload integrity plus Go deadline cancellation.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"
require_vpp_paths
require_vclgo_paths

if [ -z "${VCL_CONFIG:-}" ] || [ ! -f "$VCL_CONFIG" ]; then
    echo "run_concurrency.sh: set VCL_CONFIG to a readable file" >&2
    exit 2
fi

PORT="${PORT:-9987}"
CONC="${CONC:-128}"
MSGS="${MSGS:-32}"
SIZE="${SIZE:-4096}"
DEADLINE_CONC="${DEADLINE_CONC:-100}"
CLIENT_TIMEOUT="${CLIENT_TIMEOUT:-120}"
LOG_DIR="${LOG_DIR:-/tmp/vclgo-concurrency}"
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
    echo "[conc] server failed to become ready" >&2
    cat "$LOG_DIR/server.log" >&2
    exit 1
fi

echo "[conc] payload: $CONC connections x $MSGS messages x $SIZE bytes"
if run_as_user timeout --kill-after=5 "$CLIENT_TIMEOUT" \
    "$VCLGO_BIN/vclgo" run "$VCLGO_BIN/examples/echo_client" \
    -addr "127.0.0.1:$PORT" -conc "$CONC" -msgs "$MSGS" -size "$SIZE" \
    -timeout 30s >"$LOG_DIR/client.log" 2>&1
then
    :
else
    rc=$?
    echo "[conc] payload FAIL (rc=$rc)" >&2
    tail -80 "$LOG_DIR/client.log" >&2
    tail -80 "$LOG_DIR/server.log" >&2
    exit 1
fi
tail -4 "$LOG_DIR/client.log"

echo "[conc] deadlines: $DEADLINE_CONC blocked reads"
if run_as_user timeout --kill-after=5 "$CLIENT_TIMEOUT" \
    "$VCLGO_BIN/vclgo" run "$VCLGO_BIN/examples/echo_client" \
    -addr "127.0.0.1:$PORT" -conc "$DEADLINE_CONC" -idle-read \
    -dial-timeout 30s -timeout 250ms \
    >"$LOG_DIR/deadline-client.log" 2>&1
then
    :
else
    rc=$?
    echo "[conc] deadline FAIL (rc=$rc)" >&2
    tail -80 "$LOG_DIR/deadline-client.log" >&2
    tail -80 "$LOG_DIR/server.log" >&2
    exit 1
fi
tail -4 "$LOG_DIR/deadline-client.log"

echo "[conc] OK"
