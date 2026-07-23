#!/bin/bash
# run_http_soak_fastpath.sh — HTTP soak gate for the fastpath preload
# preload. Uses LD_PRELOAD with libvclgo_gum_vcl.so so the entire
# HTTP path — Go net/http, VCL, VPP session layer — runs against the
# in-process syscall patcher at both endpoints.
#
# Invariants checked per round:
#
#   1. Client `fail` count must be zero.
#   2. No "unsolicited response" / "superfluous response" / "WriteHeader
#      on hijacked" warning may appear in the client or server log.
#      These are exactly what a duplicate-write or torn-frame bug in the
#      fastpath dispatcher would look like at the HTTP layer.
#   3. After the server stops, VPP must show zero application/session
#      residue.
#
# Defaults produce the release-gate scenario: 5 rounds * (100 workers *
# 100 reqs) = 50 000 requests. Override via ROUNDS, CONC, REQS.
#
# Both keepalive-on and keepalive-off modes are supported.
# Pass HTTP_CLIENT_EXTRA='-no-keepalive' from the caller to exercise the
# per-connection path; the default (no flag) uses net/http's default
# keepalive Transport.
#
# For the multi-worker TCP gate, run server and client on separate VPP
# instances and set SERVER_VCL_CONFIG, CLIENT_VCL_CONFIG, SERVER_ADDR,
# CLIENT_URL, VPP_CLI_SOCK, and CLIENT_VPP_CLI_SOCK. A same-VPP
# app-scope-local test exercises VPP cut-through transport instead of TCP.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"
require_vpp_paths

VCLGO_GUM_LIB="${VCLGO_GUM_LIB:-$VCLGO_REPO/preload/fastpath/build/libvclgo_gum_vcl.so}"
if [ ! -e "$VCLGO_GUM_LIB" ]; then
    echo "run_http_soak_fastpath.sh: missing $VCLGO_GUM_LIB" >&2
    echo "Build first: make -C $VCLGO_REPO/preload/fastpath gum_vcl" >&2
    exit 2
fi
for path in "$VCLGO_BIN/examples/http_server" "$VCLGO_BIN/examples/http_client"; do
    if [ ! -x "$path" ]; then
        echo "run_http_soak_fastpath.sh: missing $path" >&2
        echo "Build first: make -C $VCLGO_REPO build" >&2
        exit 2
    fi
done

SERVER_VCL_CONFIG="${SERVER_VCL_CONFIG:-${VCL_CONFIG:-}}"
CLIENT_VCL_CONFIG="${CLIENT_VCL_CONFIG:-${VCL_CONFIG:-}}"
for config in "$SERVER_VCL_CONFIG" "$CLIENT_VCL_CONFIG"; do
    if [ -z "$config" ] || [ ! -f "$config" ]; then
        echo "run_http_soak_fastpath.sh: server/client VCL config is not readable: $config" >&2
        exit 2
    fi
done

# Export the variables run_fastpath reads so the setsid subshell
# sees them. Same rationale as run_smoke_fastpath.sh.
export VCLGO_GUM_LIB
[ -n "${VCLGO_LOG:-}"           ] && export VCLGO_LOG
[ -n "${GOTRACEBACK:-}"         ] && export GOTRACEBACK
[ -n "${VCLGO_FASTPATH_TRACE:-}" ] && export VCLGO_FASTPATH_TRACE

PORT="${PORT:-8088}"
ROUNDS="${ROUNDS:-5}"
CONC="${CONC:-100}"
REQS="${REQS:-100}"
CLIENT_TIMEOUT="${CLIENT_TIMEOUT:-180}"
LOG_DIR="${LOG_DIR:-/tmp/vclgo-http-soak-fastpath}"
VPPCTL_CMD="${VPPCTL_CMD:-$VPPCTL}"
VPP_CLI_SOCK="${VPP_CLI_SOCK:-/run/vpp/cli.sock}"
CLIENT_VPP_CLI_SOCK="${CLIENT_VPP_CLI_SOCK:-$VPP_CLI_SOCK}"
SERVER_ADDR="${SERVER_ADDR:-127.0.0.1:$PORT}"
CLIENT_URL="${CLIENT_URL:-http://127.0.0.1:$PORT/}"
HTTP_NETWORK="${HTTP_NETWORK:-tcp}"
mkdir -p "$LOG_DIR"
ulimit -c unlimited 2>/dev/null || true

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
    if [ -n "${NO_PROXY:-}" ]; then
        env_pairs+=("NO_PROXY=$NO_PROXY")
    fi
    if [ -n "${no_proxy:-}" ]; then
        env_pairs+=("no_proxy=$no_proxy")
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

# --- start http_server under the fastpath preload -------------------------

echo "[soak-fp] fastpath lib: $VCLGO_GUM_LIB"
echo "[soak-fp] starting http_server on $SERVER_ADDR"
spawn_bg "$LOG_DIR/server.log" "$SERVER_VCL_CONFIG" \
    "$VCLGO_BIN/examples/http_server" \
    -network "$HTTP_NETWORK" -addr "$SERVER_ADDR" ${HTTP_SERVER_EXTRA:-}
SERVER_PID=$SPAWN_PID

ready=0
for _ in $(seq 1 100); do
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
    echo "[soak-fp] server failed to become ready" >&2
    tail -80 "$LOG_DIR/server.log" >&2
    exit 1
fi

# Fail loudly if the server did not actually initialize the fastpath
# preload with a live VCL bring-up. Otherwise the whole soak silently
# degenerates into a kernel-only HTTP test (which passes but proves
# nothing about our data path).
if ! grep -q '^\[vclgo/gum\] vclgo_init ok .*passthrough=0' \
    "$LOG_DIR/server.log"; then
    echo "[soak-fp] server did not initialize the fastpath preload (passthrough=0)" >&2
    tail -40 "$LOG_DIR/server.log" >&2
    exit 1
fi

# --- warmup notes ----------------------------------------------------------
#
# Optional in-process warmup is retained for local cut-through diagnostics.
# The routed global-scope TCP gate is validated with WARMUP_REQS=0 and
# retries disabled.
WARMUP_REQS="${WARMUP_REQS:-16}"
WARMUP_CONC="${WARMUP_CONC:-1}"

# --- helpers ----------------------------------------------------------------

check_unsolicited() {
    local log=$1
    local label=$2
    if grep -Ei '(unsolicited|superfluous) response|response.WriteHeader on hijacked' "$log" >/dev/null; then
        echo "[soak-fp] FAIL: '$label' log contains unsolicited-response warning" >&2
        grep -Ei '(unsolicited|superfluous) response|response.WriteHeader on hijacked' "$log" >&2
        exit 1
    fi
}

check_vpp_residue_one() {
    local round=$1
    local role=$2
    local socket=$3
    local app_output session_output apps sessions attempt
    for attempt in $(seq 0 "${RESIDUE_RETRIES:-30}"); do
        if ! app_output="$(sudo "$VPPCTL_CMD" -s "$socket" show app 2>&1)"; then
            echo "[soak-fp] FAIL after $round: cannot query $role VPP at $socket" >&2
            echo "$app_output" >&2
            exit 1
        fi
        if ! session_output="$(sudo "$VPPCTL_CMD" -s "$socket" show session verbose 1 2>&1)"; then
            echo "[soak-fp] FAIL after $round: cannot query $role VPP sessions at $socket" >&2
            echo "$session_output" >&2
            exit 1
        fi
        apps="$(printf '%s\n' "$app_output" | awk 'NR>1 && NF>0 {print}' | wc -l)"
        sessions="$(printf '%s\n' "$session_output" | grep -cE '^\[' || true)"
        if [ "$apps" -eq 0 ] && [ "$sessions" -eq 0 ]; then
            return
        fi
        [ "$attempt" -lt "${RESIDUE_RETRIES:-30}" ] && sleep 1
    done
    echo "[soak-fp] FAIL after $round: $role VPP residue apps=$apps sessions=$sessions" >&2
    echo "$app_output" >&2
    echo "$session_output" >&2
    exit 1
}

check_vpp_residue() {
    local round=$1
    check_vpp_residue_one "$round" server "$VPP_CLI_SOCK"
    if [ "$CLIENT_VPP_CLI_SOCK" != "$VPP_CLI_SOCK" ]; then
        check_vpp_residue_one "$round" client "$CLIENT_VPP_CLI_SOCK"
    fi
}

# --- soak loop --------------------------------------------------------------

total_ok=0
total_fail=0
soak_start=$(date +%s)

for round in $(seq 1 "$ROUNDS"); do
    round_log="$LOG_DIR/client-round-$round.log"
    echo "[soak-fp] round $round/$ROUNDS: conc=$CONC reqs=$REQS (total=$((CONC * REQS)))"
    if run_fastpath "$CLIENT_VCL_CONFIG" timeout --kill-after=5 "$CLIENT_TIMEOUT" \
        "$VCLGO_BIN/examples/http_client" \
        -url "$CLIENT_URL" \
        -conc "$CONC" -reqs "$REQS" -timeout "${HTTP_TIMEOUT:-30s}" \
        -warmup-reqs "$WARMUP_REQS" -warmup-conc "$WARMUP_CONC" \
        ${HTTP_CLIENT_EXTRA:-} \
        >"$round_log" 2>&1
    then
        :
    else
        rc=$?
        echo "[soak-fp] round $round FAIL: http_client rc=$rc" >&2
        tail -40 "$round_log" >&2
        exit 1
    fi

    summary="$(grep '^http_client:' "$round_log" | tail -1)"
    if [ -z "$summary" ]; then
        echo "[soak-fp] round $round: missing summary line" >&2
        tail -20 "$round_log" >&2
        exit 1
    fi
    echo "          $summary"

    ok="$(echo "$summary" | grep -oP 'ok=\K[0-9]+')"
    fail="$(echo "$summary" | grep -oP 'fail=\K[0-9]+')"
    total_ok=$((total_ok + ok))
    total_fail=$((total_fail + fail))
    if [ "$fail" -ne 0 ]; then
        echo "[soak-fp] round $round FAIL: $fail requests failed" >&2
        exit 1
    fi

    check_unsolicited "$round_log" "client round $round"
    check_unsolicited "$LOG_DIR/server.log" "server (through round $round)"

    if [ "$round" -lt "$ROUNDS" ]; then
        sleep "${INTER_ROUND_SLEEP:-1}"
    fi
done

soak_elapsed=$(( $(date +%s) - soak_start ))

listeners="$(sudo "$VPPCTL_CMD" -s "$VPP_CLI_SOCK" show session verbose 1 2>/dev/null | grep -c ' LISTEN' || true)"
established="$(sudo "$VPPCTL_CMD" -s "$VPP_CLI_SOCK" show session verbose 1 2>/dev/null | grep -c ' ESTABLISHED' || true)"
echo "[soak-fp] mid-soak snapshot: LISTEN=$listeners ESTABLISHED=$established"

if kill -0 "$SERVER_PID" 2>/dev/null; then
    kill -TERM -"$SERVER_PID" 2>/dev/null ||
        kill -TERM "$SERVER_PID" 2>/dev/null || true
fi
for _ in $(seq 1 30); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
sleep 1
check_vpp_residue "final (after server stop)"

echo "[soak-fp] OK — $ROUNDS rounds, $total_ok OK, $total_fail fail, elapsed ${soak_elapsed}s"
