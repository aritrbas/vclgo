#!/bin/bash
# End-to-end fastpath (libvclgo_gum_vcl.so) smoke test.
#
# Uses LD_PRELOAD with the Approach #4 in-process syscall patcher.
# Requires an already-running VPP.

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
# `spawn_bg` reaches `run_fastpath` through a fresh `bash -c` subshell,
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

PORT="${PORT:-9876}"
TCP_NETWORK="${TCP_NETWORK:-tcp}"
SERVER_ADDR="${SERVER_ADDR:-127.0.0.1:$PORT}"
CLIENT_ADDR="${CLIENT_ADDR:-$SERVER_ADDR}"
SERVER_VCL_CONFIG="${SERVER_VCL_CONFIG:-${VCL_CONFIG:-}}"
CLIENT_VCL_CONFIG="${CLIENT_VCL_CONFIG:-${VCL_CONFIG:-}}"
LOG_DIR="${LOG_DIR:-/tmp/vclgo-smoke-fastpath}"
CLIENT_TIMEOUT="${CLIENT_TIMEOUT:-30}"
mkdir -p "$LOG_DIR"
ulimit -c unlimited 2>/dev/null || true

for config in "$SERVER_VCL_CONFIG" "$CLIENT_VCL_CONFIG"; do
    if [ -z "$config" ] || [ ! -f "$config" ]; then
        echo "run_smoke_fastpath.sh: server/client VCL config is not readable: $config" >&2
        exit 2
    fi
done

# Preload settings shared between server + client. Route all VCL traffic
# through the fastpath library so it is exercised at both endpoints.
run_fastpath() {
    local config=$1
    shift
    echo "[run_fastpath] cmd: $*" >&2
    local -a env_pairs=(
        "LD_LIBRARY_PATH=$VPP_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        "LD_PRELOAD=$VCLGO_GUM_LIB"
        "VCL_CONFIG=$config"
        "VCLGO_WORKERS=${VCLGO_WORKERS:-4}"
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
    local config=$2
    shift 2
    setsid bash -c 'run_fastpath "$@"' _ "$config" "$@" >"$logfile" 2>&1 &
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
echo "[smoke-fp] starting fastpath echo server on $SERVER_ADDR ($TCP_NETWORK)"
spawn_bg "$LOG_DIR/server.log" "$SERVER_VCL_CONFIG" \
    "$VCLGO_BIN/examples/echo_server" \
    -network "$TCP_NETWORK" -addr "$SERVER_ADDR"
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
# Keep this smallest smoke path free of an extra wrapper process. The
# constructor now recognizes non-Go helpers before VCL initialization, so
# timeout is safe where the longer stress harnesses need it.
if run_fastpath "$CLIENT_VCL_CONFIG" \
    "$VCLGO_BIN/examples/echo_client" \
    -network "$TCP_NETWORK" -addr "$CLIENT_ADDR" \
    -conc "${TCP_CONC:-4}" -msgs "${TCP_MSGS:-8}" -size "${TCP_SIZE:-1024}" \
    >"$LOG_DIR/client.log" 2>&1
then
    echo "[smoke-fp] TCP echo OK"
    tail -4 "$LOG_DIR/client.log"
else
    rc=$?
    echo "[smoke-fp] FAIL (client rc=$rc)" >&2
    cat "$LOG_DIR/client.log" >&2
    tail -40 "$LOG_DIR/server.log" >&2
    exit 1
fi

echo "[smoke-fp] checking six-argument raw syscall fallback"
run_fastpath "$CLIENT_VCL_CONFIG" "$VCLGO_BIN/examples/echo_client" -mmap-probe \
    >"$LOG_DIR/mmap-probe.log" 2>&1
grep 'mmap sixth-argument probe OK' "$LOG_DIR/mmap-probe.log"

echo "[smoke-fp] checking sendfile on a VCL-owned output fd"
run_fastpath "$CLIENT_VCL_CONFIG" "$VCLGO_BIN/examples/echo_client" \
    -network "$TCP_NETWORK" -addr "$CLIENT_ADDR" \
    -timeout "${CLIENT_TIMEOUT}s" -sendfile-probe \
    >"$LOG_DIR/sendfile-probe.log" 2>&1
grep 'sendfile probe OK' "$LOG_DIR/sendfile-probe.log"

echo "[smoke-fp] checking close_range lifecycle and flag modes"
run_fastpath "$CLIENT_VCL_CONFIG" "$VCLGO_BIN/examples/echo_client" \
    -network "$TCP_NETWORK" -addr "$CLIENT_ADDR" \
    -timeout "${CLIENT_TIMEOUT}s" -close-range-probe \
    >"$LOG_DIR/close-range-probe.log" 2>&1
grep 'close_range probe OK' "$LOG_DIR/close-range-probe.log"

echo "[smoke-fp] checking TCP half-close"
run_fastpath "$CLIENT_VCL_CONFIG" "$VCLGO_BIN/examples/echo_client" \
    -network "$TCP_NETWORK" -addr "$CLIENT_ADDR" \
    -timeout "${CLIENT_TIMEOUT}s" -half-close-probe \
    >"$LOG_DIR/half-close-probe.log" 2>&1
grep 'half-close probe OK' "$LOG_DIR/half-close-probe.log"

if [ -n "${REFUSED_ADDR:-}" ]; then
    echo "[smoke-fp] checking connection-refused delivery from $REFUSED_ADDR"
    run_fastpath "$CLIENT_VCL_CONFIG" "$VCLGO_BIN/examples/echo_client" \
        -network "$TCP_NETWORK" -addr "$REFUSED_ADDR" \
        -timeout "${CLIENT_TIMEOUT}s" -refused-probe \
        >"$LOG_DIR/refused-probe.log" 2>&1
    grep 'connection-refused probe OK' "$LOG_DIR/refused-probe.log"
fi

# The reset server consumes one byte, deliberately leaves the rest of a
# 256-KiB write unread, and closes. VPP's TCP close path must therefore emit
# RST; EOF is not accepted as an equivalent result.
if [ "${RESET_PROBE:-0}" = 1 ]; then
    RESET_SERVER_ADDR="${RESET_SERVER_ADDR:-$SERVER_ADDR}"
    RESET_CLIENT_ADDR="${RESET_CLIENT_ADDR:-$RESET_SERVER_ADDR}"
    spawn_bg "$LOG_DIR/reset-server.log" "$SERVER_VCL_CONFIG" \
        "$VCLGO_BIN/examples/echo_server" \
        -network "$TCP_NETWORK" -addr "$RESET_SERVER_ADDR" -reset-after-read
    RESET_SERVER_PID=$SPAWN_PID
    reset_ready=0
    for _ in $(seq 1 100); do
        if grep -q 'echo_server: listening on' "$LOG_DIR/reset-server.log" 2>/dev/null; then
            reset_ready=1
            break
        fi
        if ! kill -0 "$RESET_SERVER_PID" 2>/dev/null; then
            break
        fi
        sleep 0.1
    done
    if [ "$reset_ready" -ne 1 ]; then
        echo "[smoke-fp] reset server failed to become ready" >&2
        cat "$LOG_DIR/reset-server.log" >&2
        exit 1
    fi
    if ! run_fastpath "$CLIENT_VCL_CONFIG" \
        "$VCLGO_BIN/examples/echo_client" \
        -network "$TCP_NETWORK" -addr "$RESET_CLIENT_ADDR" \
        -timeout "${CLIENT_TIMEOUT}s" -peer-reset-probe \
        >"$LOG_DIR/reset-client.log" 2>&1
    then
        echo "[smoke-fp] reset delivery failed" >&2
        cat "$LOG_DIR/reset-client.log" >&2
        exit 1
    fi
    grep 'peer-reset probe OK' "$LOG_DIR/reset-client.log"
fi

echo "[smoke-fp] OK"
