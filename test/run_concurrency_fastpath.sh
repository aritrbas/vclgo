#!/bin/bash
# Multi-owner stress under the fastpath (libvclgo_gum_vcl.so) preload.
# Uses LD_PRELOAD to load the in-process syscall patcher end-to-end at
# both endpoints.
#
# Two phases:
#   1. payload integrity  : CONC × MSGS × SIZE  (default 128 × 32 × 4096)
#   2. deadline correctness: DEADLINE_CONC idle-read connections with
#                            a 250 ms Go read deadline; each must fire
#                            i/o timeout, no early cancellation and no
#                            payload leakage.
#
# Requires:
#   * A running VPP with loop0 up on 127.0.0.1/8 (see test/start_vpp.sh).
#   * VCL_CONFIG pointing at a readable VCL config.
#   * A built libvclgo_gum_vcl.so and echo_server/echo_client binaries.
#
# G-D2 makes `timeout` safe under this LD_PRELOAD: the fastpath ctor now
# probes .text for Go-shaped syscall sites BEFORE touching VPP, so a
# non-Go helper like `timeout` runs the ctor, finds nothing to patch,
# and exits without registering with VPP. That means we can use the
# ordinary `timeout` wrapper here — no manual watchdog needed — even
# though we could not in the pre-G-D2 smoke harness.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"
require_vpp_paths

VCLGO_GUM_LIB="${VCLGO_GUM_LIB:-$VCLGO_REPO/preload/fastpath/build/libvclgo_gum_vcl.so}"
if [ ! -e "$VCLGO_GUM_LIB" ]; then
    echo "run_concurrency_fastpath.sh: missing $VCLGO_GUM_LIB" >&2
    echo "Build first: make -C $VCLGO_REPO/preload/fastpath gum_vcl" >&2
    exit 2
fi
for path in "$VCLGO_BIN/examples/echo_server" "$VCLGO_BIN/examples/echo_client"; do
    if [ ! -x "$path" ]; then
        echo "run_concurrency_fastpath.sh: missing $path" >&2
        echo "Build first: make -C $VCLGO_REPO build" >&2
        exit 2
    fi
done

if [ -z "${VCL_CONFIG:-}" ] || [ ! -f "$VCL_CONFIG" ]; then
    echo "run_concurrency_fastpath.sh: set VCL_CONFIG to a readable file" >&2
    exit 2
fi

# G-D1: export EVERY variable the exported `run_fastpath` reads so the
# `setsid bash -c '...'` subshell inherits them. Without this the server
# child sees LD_PRELOAD="" and falls through to the kernel path, and the
# whole run silently degenerates into a kernel-only stress test.
export VCLGO_GUM_LIB
[ -n "${VCL_CONFIG:-}"          ] && export VCL_CONFIG
[ -n "${VCLGO_LOG:-}"           ] && export VCLGO_LOG
[ -n "${GOTRACEBACK:-}"         ] && export GOTRACEBACK
[ -n "${VCLGO_FASTPATH_TRACE:-}" ] && export VCLGO_FASTPATH_TRACE

PORT="${PORT:-9987}"
CONC="${CONC:-128}"
MSGS="${MSGS:-32}"
SIZE="${SIZE:-4096}"
DEADLINE_CONC="${DEADLINE_CONC:-100}"
CLIENT_TIMEOUT="${CLIENT_TIMEOUT:-180}"
LOG_DIR="${LOG_DIR:-/tmp/vclgo-concurrency-fastpath}"
mkdir -p "$LOG_DIR"
ulimit -c unlimited 2>/dev/null || true

run_fastpath() {
    local -a env_pairs=(
        "LD_LIBRARY_PATH=$VPP_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        "LD_PRELOAD=$VCLGO_GUM_LIB"
        "VCL_CONFIG=${VCL_CONFIG:-}"
        "VCLGO_LOG=${VCLGO_LOG:-1}"
        "GOTRACEBACK=${GOTRACEBACK:-crash}"
    )
    if [ -n "${VCLGO_FASTPATH_TRACE:-}" ]; then
        env_pairs+=("VCLGO_FASTPATH_TRACE=$VCLGO_FASTPATH_TRACE")
    fi
    if [ "$(id -u)" -eq 0 ] && [ "$RUN_AS_USER" != "root" ]; then
        sudo -u "$RUN_AS_USER" env "${env_pairs[@]}" \
            "PATH=$PATH" "HOME=$RUN_AS_HOME" "$@"
    else
        env "${env_pairs[@]}" "$@"
    fi
}
export -f run_fastpath

TRACKED_PIDS=()
spawn_bg() {
    local logfile=$1
    shift
    setsid bash -c 'run_fastpath "$@"' _ "$@" >"$logfile" 2>&1 &
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

echo "[conc-fp] fastpath lib: $VCLGO_GUM_LIB"
echo "[conc-fp] starting fastpath echo server on 127.0.0.1:$PORT"
spawn_bg "$LOG_DIR/server.log" \
    "$VCLGO_BIN/examples/echo_server" -addr "127.0.0.1:$PORT"
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
    echo "[conc-fp] server failed to become ready" >&2
    cat "$LOG_DIR/server.log" >&2
    exit 1
fi

# Sanity: server must have actually loaded the fastpath preload with a
# real VCL bring-up (not passthrough). If the server silently reverted
# to the kernel path (G-D1 regression) every subsequent measurement is
# meaningless, so fail loudly here.
if ! grep -q '^\[vclgo/gum\] vclgo_init ok .*passthrough=0' \
    "$LOG_DIR/server.log"; then
    echo "[conc-fp] server did not initialize the fastpath preload (passthrough=0)" >&2
    tail -40 "$LOG_DIR/server.log" >&2
    exit 1
fi

echo "[conc-fp] payload: $CONC connections x $MSGS messages x $SIZE bytes"
if run_fastpath timeout --kill-after=5 "$CLIENT_TIMEOUT" \
    "$VCLGO_BIN/examples/echo_client" \
    -addr "127.0.0.1:$PORT" -conc "$CONC" -msgs "$MSGS" -size "$SIZE" \
    -timeout 30s >"$LOG_DIR/client.log" 2>&1
then
    :
else
    rc=$?
    echo "[conc-fp] payload FAIL (rc=$rc)" >&2
    tail -80 "$LOG_DIR/client.log" >&2
    tail -80 "$LOG_DIR/server.log" >&2
    exit 1
fi
tail -4 "$LOG_DIR/client.log"

echo "[conc-fp] deadlines: $DEADLINE_CONC blocked reads (250ms)"
if run_fastpath timeout --kill-after=5 "$CLIENT_TIMEOUT" \
    "$VCLGO_BIN/examples/echo_client" \
    -addr "127.0.0.1:$PORT" -conc "$DEADLINE_CONC" -idle-read \
    -dial-timeout 30s -timeout 250ms \
    >"$LOG_DIR/deadline-client.log" 2>&1
then
    :
else
    rc=$?
    echo "[conc-fp] deadline FAIL (rc=$rc)" >&2
    tail -80 "$LOG_DIR/deadline-client.log" >&2
    tail -80 "$LOG_DIR/server.log" >&2
    exit 1
fi
tail -4 "$LOG_DIR/deadline-client.log"

echo "[conc-fp] OK"
