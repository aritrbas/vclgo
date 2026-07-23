#!/bin/bash
# Routed gRPC health-check gate under the Frida-Gum/VCL preload.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"
require_vpp_paths

VCLGO_GUM_LIB="${VCLGO_GUM_LIB:-$VCLGO_REPO/preload/fastpath/build/libvclgo_gum_vcl.so}"
SERVER_VCL_CONFIG="${SERVER_VCL_CONFIG:-${VCL_CONFIG:-}}"
CLIENT_VCL_CONFIG="${CLIENT_VCL_CONFIG:-${VCL_CONFIG:-}}"
for path in "$VCLGO_GUM_LIB" "$VCLGO_BIN/examples/grpc_server" \
            "$VCLGO_BIN/examples/grpc_client" \
            "$SERVER_VCL_CONFIG" "$CLIENT_VCL_CONFIG"; do
    if [ -z "$path" ] || [ ! -e "$path" ]; then
        echo "run_grpc_fastpath.sh: required path is missing: $path" >&2
        exit 2
    fi
done

GRPC_NETWORK="${GRPC_NETWORK:-tcp}"
SERVER_ADDR="${SERVER_ADDR:-127.0.0.1:50051}"
CLIENT_ADDR="${CLIENT_ADDR:-$SERVER_ADDR}"
GRPC_CONC="${GRPC_CONC:-100}"
GRPC_REQS="${GRPC_REQS:-100}"
CASE_TIMEOUT="${CASE_TIMEOUT:-180}"
LOG_DIR="${LOG_DIR:-/tmp/vclgo-grpc-fastpath}"
mkdir -p "$LOG_DIR"

export VCLGO_GUM_LIB
[ -n "${VCLGO_FASTPATH_TRACE:-}" ] && export VCLGO_FASTPATH_TRACE

run_fastpath() {
    local config=$1
    shift
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
            kill -TERM -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    for _ in $(seq 1 30); do
        local alive=0
        for pid in "${TRACKED_PIDS[@]}"; do
            kill -0 "$pid" 2>/dev/null && alive=1
        done
        [ "$alive" -eq 0 ] && break
        sleep 0.1
    done
    for pid in "${TRACKED_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL -"$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
        fi
    done
    exit "$rc"
}
trap cleanup EXIT INT TERM HUP

echo "[grpc-fp] starting $GRPC_NETWORK server on $SERVER_ADDR"
spawn_bg "$LOG_DIR/server.log" "$SERVER_VCL_CONFIG" \
    "$VCLGO_BIN/examples/grpc_server" \
    -network "$GRPC_NETWORK" -addr "$SERVER_ADDR"
SERVER_PID=$SPAWN_PID

ready=0
for _ in $(seq 1 100); do
    if grep -q 'grpc_server: listening on' "$LOG_DIR/server.log" 2>/dev/null; then
        ready=1
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        break
    fi
    sleep 0.2
done
if [ "$ready" -ne 1 ] ||
   ! grep -q '^\[vclgo/gum\] vclgo_init ok .*passthrough=0' "$LOG_DIR/server.log"; then
    echo "[grpc-fp] server did not initialize VCL fastpath" >&2
    tail -80 "$LOG_DIR/server.log" >&2
    exit 1
fi

if run_fastpath "$CLIENT_VCL_CONFIG" timeout --kill-after=5 "$CASE_TIMEOUT" \
    "$VCLGO_BIN/examples/grpc_client" \
    -network "$GRPC_NETWORK" -addr "$CLIENT_ADDR" \
    -conc "$GRPC_CONC" -reqs "$GRPC_REQS" \
    -timeout "${GRPC_TIMEOUT:-30s}" >"$LOG_DIR/client.log" 2>&1
then
    :
else
    rc=$?
    echo "[grpc-fp] client failed (rc=$rc)" >&2
    tail -80 "$LOG_DIR/client.log" >&2
    exit 1
fi

summary="$(grep '^grpc_client:' "$LOG_DIR/client.log" | tail -1)"
if [ -z "$summary" ] || ! grep -q 'fail=0' <<<"$summary"; then
    echo "[grpc-fp] invalid client result: $summary" >&2
    exit 1
fi
echo "[grpc-fp] $summary"
echo "[grpc-fp] OK"
