#!/bin/bash
# End-to-end UDP smoke test under the fastpath (libvclgo_gum_vcl.so)
# preload. Mirrors run_smoke_fastpath.sh (TCP) but uses the UDP echo
# server + client so we exercise the full UDP path:
#
#     socket(AF_INET, SOCK_DGRAM) -> bind -> recvfrom -> sendto
#
# both from a `net.ListenPacket`-style server AND from a `net.DialUDP`
# style connected client AND from a `net.ListenPacket`-style
# unconnected client (via -unconnected). Requires an already-running
# VPP.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"
require_vpp_paths

VCLGO_GUM_LIB="${VCLGO_GUM_LIB:-$VCLGO_REPO/preload/fastpath/build/libvclgo_gum_vcl.so}"
if [ ! -e "$VCLGO_GUM_LIB" ]; then
    echo "run_smoke_udp_fastpath.sh: missing $VCLGO_GUM_LIB" >&2
    echo "Build first: make -C $VCLGO_REPO/preload/fastpath gum_vcl" >&2
    exit 2
fi
# Same LD_PRELOAD-inheritance requirement as the TCP harness: any variable
# that spawn_bg's subshell needs must be exported here, since bash -c
# starts fresh env otherwise. See run_smoke_fastpath.sh for the full note.
export VCLGO_GUM_LIB
[ -n "${VCL_CONFIG:-}" ] && export VCL_CONFIG
[ -n "${VCLGO_LOG:-}" ] && export VCLGO_LOG
[ -n "${GOTRACEBACK:-}" ] && export GOTRACEBACK
[ -n "${VCLGO_FASTPATH_TRACE:-}" ] && export VCLGO_FASTPATH_TRACE

for path in "$VCLGO_BIN/examples/udp_echo_server" \
            "$VCLGO_BIN/examples/udp_echo_client"; do
    if [ ! -x "$path" ]; then
        echo "run_smoke_udp_fastpath.sh: missing $path" >&2
        echo "Build first: make -C $VCLGO_REPO build-fastpath" >&2
        exit 2
    fi
done

PORT="${PORT:-9877}"
SERVER_ADDR="${SERVER_ADDR:-127.0.0.1:$PORT}"
CLIENT_LOCAL_ADDR="${CLIENT_LOCAL_ADDR:-127.0.0.1:0}"
SERVER_VCL_CONFIG="${SERVER_VCL_CONFIG:-${VCL_CONFIG:-}}"
CLIENT_VCL_CONFIG="${CLIENT_VCL_CONFIG:-${VCL_CONFIG:-}}"
CASE_TIMEOUT="${CASE_TIMEOUT:-60}"
UDP_CONC="${UDP_CONC:-4}"
UDP_MSGS="${UDP_MSGS:-8}"
UDP_SIZE="${UDP_SIZE:-1024}"
LOG_DIR="${LOG_DIR:-/tmp/vclgo-smoke-udp-fastpath}"
mkdir -p "$LOG_DIR"
ulimit -c unlimited 2>/dev/null || true

for config in "$SERVER_VCL_CONFIG" "$CLIENT_VCL_CONFIG"; do
    if [ -z "$config" ] || [ ! -f "$config" ]; then
        echo "run_smoke_udp_fastpath.sh: server/client VCL config is not readable: $config" >&2
        exit 2
    fi
done

run_fastpath() {
    local vcl_config=$1
    shift
    echo "[run_fastpath] cmd: $*" >&2
    local -a env_pairs=(
        "LD_LIBRARY_PATH=$VPP_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        "LD_PRELOAD=$VCLGO_GUM_LIB"
        "VCL_CONFIG=$vcl_config"
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

echo "[smoke-udp-fp] using fastpath lib: $VCLGO_GUM_LIB"
echo "[smoke-udp-fp] starting UDP echo server on $SERVER_ADDR"
spawn_bg "$LOG_DIR/server.log" "$SERVER_VCL_CONFIG" \
    "$VCLGO_BIN/examples/udp_echo_server" -addr "$SERVER_ADDR"
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
    echo "[smoke-udp-fp] server failed to become ready" >&2
    cat "$LOG_DIR/server.log" >&2
    exit 1
fi

# Confirm the server actually initialized the fastpath preload; if not,
# it's running on the kernel stack and we're not testing what we think
# we are.
if ! grep -q '^\[vclgo/gum\] vclgo_init ok .*passthrough=0' \
    "$LOG_DIR/server.log"; then
    echo "[smoke-udp-fp] server did not initialize fastpath (passthrough=0)" >&2
    tail -40 "$LOG_DIR/server.log" >&2
    exit 1
fi

run_case() {
    local label=$1
    shift
    echo "[smoke-udp-fp] $label"
    if run_fastpath "$CLIENT_VCL_CONFIG" \
        timeout "$CASE_TIMEOUT" \
        "$VCLGO_BIN/examples/udp_echo_client" \
        -addr "$SERVER_ADDR" "$@" \
        >"$LOG_DIR/client-$label.log" 2>&1
    then
        grep '^udp_echo_client:' "$LOG_DIR/client-$label.log" | tail -1
    else
        rc=$?
        echo "[smoke-udp-fp] FAIL ($label rc=$rc)" >&2
        cat "$LOG_DIR/client-$label.log" >&2
        tail -80 "$LOG_DIR/server.log" >&2
        exit 1
    fi
}

# Connected UDP path: Dial/Write/Read == connect + write + read.
run_case connected -conc "$UDP_CONC" -msgs "$UDP_MSGS" -size "$UDP_SIZE"

# Unconnected UDP path: ListenPacket/WriteTo/ReadFrom == bind + sendto + recvfrom.
run_case unconnected -conc "$UDP_CONC" -msgs "$UDP_MSGS" -size "$UDP_SIZE" \
    -local "$CLIENT_LOCAL_ADDR" -unconnected

echo "[smoke-udp-fp] OK"
