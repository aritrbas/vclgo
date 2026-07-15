#!/bin/bash
# End-to-end fastpath (libvclgo_gum_vcl.so) smoke test.
#
# Uses LD_PRELOAD with the in-process syscall patcher instead of the
# seccomp launcher used by run_smoke.sh.  Requires an already-running
# VPP.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"
require_vpp_paths

VCLGO_GUM_LIB="${VCLGO_GUM_LIB:-$VCLGO_REPO/preload/fastpath/build/libvclgo_gum_vcl.so}"
if [ ! -e "$VCLGO_GUM_LIB" ]; then
    echo "run_smoke_fastpath.sh: missing $VCLGO_GUM_LIB" >&2
    echo "Build first: make -C $VCLGO_REPO/preload/fastpath gum_vcl" >&2
    exit 2
fi
# G-D1: `spawn_bg` reaches `run_fastpath` through a fresh `bash -c` subshell,
# which only inherits *exported* variables. `run_fastpath` reads $VCLGO_GUM_LIB
# to populate LD_PRELOAD; if that variable is not exported the server child
# sees LD_PRELOAD="" and falls through to the raw kernel path — leaving the
# preloaded client unable to reach the VCL listener ("connect: bad address").
# The same applies to VCL_CONFIG (env-passed but not always re-exported) and
# to VCLGO_FASTPATH_TRACE when set.
export VCLGO_GUM_LIB
[ -n "${VCL_CONFIG:-}" ] && export VCL_CONFIG
[ -n "${VCLGO_LOG:-}" ] && export VCLGO_LOG
[ -n "${GOTRACEBACK:-}" ] && export GOTRACEBACK
[ -n "${VCLGO_FASTPATH_TRACE:-}" ] && export VCLGO_FASTPATH_TRACE
for path in "$VCLGO_BIN/examples/echo_server" "$VCLGO_BIN/examples/echo_client"; do
    if [ ! -x "$path" ]; then
        echo "run_smoke_fastpath.sh: missing $path" >&2
        echo "Build first: make -C $VCLGO_REPO build" >&2
        exit 2
    fi
done

if [ -z "${VCL_CONFIG:-}" ] || [ ! -f "$VCL_CONFIG" ]; then
    echo "run_smoke_fastpath.sh: set VCL_CONFIG to a readable VCL configuration" >&2
    exit 2
fi

PORT="${PORT:-9876}"
LOG_DIR="${LOG_DIR:-/tmp/vclgo-smoke-fastpath}"
CLIENT_TIMEOUT="${CLIENT_TIMEOUT:-30}"
mkdir -p "$LOG_DIR"
ulimit -c unlimited 2>/dev/null || true

# Preload settings shared between server + client. Route all VCL traffic
# through the fastpath library so it is exercised at both endpoints.
run_fastpath() {
    echo "[run_fastpath] cmd: $*" >&2
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

    echo "[run_fastpath] LD_PRELOAD=$VCLGO_GUM_LIB (root=$(id -u), as=$RUN_AS_USER)" >&2
    if [ "$(id -u)" -eq 0 ] && [ "$RUN_AS_USER" != "root" ]; then
        sudo -u "$RUN_AS_USER" env "${env_pairs[@]}" \
            "PATH=$PATH" "HOME=$RUN_AS_HOME" "$@"
    else
        env "${env_pairs[@]}" "$@"
    fi
}

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
export -f run_fastpath

echo "[smoke-fp] using fastpath lib: $VCLGO_GUM_LIB"
echo "[smoke-fp] starting fastpath echo server on 127.0.0.1:$PORT"
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
    echo "[smoke-fp] server failed to become ready" >&2
    cat "$LOG_DIR/server.log" >&2
    exit 1
fi

echo "[smoke-fp] running fastpath client"
# NOTE: do NOT wrap with `timeout` here — timeout is a non-Go binary
# that our preload happily loads into (finding nothing to patch) but
# every LD_PRELOAD-triggered vclgo_init registers with VPP. When
# `timeout` execs echo_client, echo_client's VCL init collides with
# the still-registered session from `timeout` and segfaults. We rely
# on the surrounding shell trap to reap runaways instead.
if run_fastpath \
    "$VCLGO_BIN/examples/echo_client" \
    -addr "127.0.0.1:$PORT" -conc 4 -msgs 8 -size 1024 \
    >"$LOG_DIR/client.log" 2>&1
then
    echo "[smoke-fp] OK"
    tail -4 "$LOG_DIR/client.log"
else
    rc=$?
    echo "[smoke-fp] FAIL (client rc=$rc)" >&2
    cat "$LOG_DIR/client.log" >&2
    tail -40 "$LOG_DIR/server.log" >&2
    exit 1
fi
