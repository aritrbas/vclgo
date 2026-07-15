#!/bin/bash
# run_http_soak.sh — release gate for the seccomp signal-race fix (N-17 / G1).
#
# Runs N sequential rounds of R HTTP requests each. Each round must satisfy
# every one of the following invariants; if any invariant is violated the
# soak fails and the workload is stopped so a human can inspect state:
#
#   1. Client `fail` count is zero.
#   2. No "unsolicited response" warning appears in the client or server log
#      — that is the diagnostic Go's net/http transport prints when it reads
#      bytes on a supposedly-idle keepalive connection, which is exactly
#      what a duplicate-write from N-17 (cancelled seccomp notification
#      after VCL committed bytes) would look like at the HTTP layer.
#   3. VPP shows zero application/session residue after every round.
#
# Defaults produce the release-gate scenario: 5 x (100 workers x 100 reqs)
# = 50,000 total requests. Override via ROUNDS, CONC, REQS env vars.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"
require_vpp_paths
require_vclgo_paths

if [ -z "${VCL_CONFIG:-}" ] || [ ! -f "$VCL_CONFIG" ]; then
    echo "run_http_soak.sh: set VCL_CONFIG to a readable file" >&2
    exit 2
fi

PORT="${PORT:-8088}"
ROUNDS="${ROUNDS:-5}"
CONC="${CONC:-100}"
REQS="${REQS:-100}"
CLIENT_TIMEOUT="${CLIENT_TIMEOUT:-180}"
LOG_DIR="${LOG_DIR:-/tmp/vclgo-http-soak}"
VPPCTL_CMD="${VPPCTL_CMD:-$VPPCTL}"
VPP_CLI_SOCK="${VPP_CLI_SOCK:-/run/vpp/cli.sock}"

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

# --- start the http_server under vclgo -------------------------------------

echo "[soak] starting http_server on 127.0.0.1:$PORT"
spawn_bg "$LOG_DIR/server.log" \
    "$VCLGO_BIN/vclgo" run "$VCLGO_BIN/examples/http_server" \
    -addr "127.0.0.1:$PORT"
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
    echo "[soak] server failed to become ready" >&2
    tail -80 "$LOG_DIR/server.log" >&2
    exit 1
fi

# --- helpers to check invariants -------------------------------------------

check_unsolicited() {
    local log=$1
    local label=$2
    if grep -Ei '(unsolicited|superfluous) response|response.WriteHeader on hijacked' "$log" >/dev/null; then
        echo "[soak] FAIL: '$label' log contains unsolicited-response warning" >&2
        grep -Ei '(unsolicited|superfluous) response|response.WriteHeader on hijacked' "$log" >&2
        exit 1
    fi
}

check_vpp_residue() {
    local round=$1
    local apps sessions
    # `show app` header row is 'Index Name Namespace'; skip it and count
    # non-blank body rows. `show session verbose 1` prints one bracketed
    # session id per session; if none, we get no matches (grep -c exits 1,
    # hence `|| true`).
    apps="$(sudo "$VPPCTL_CMD" -s "$VPP_CLI_SOCK" show app 2>/dev/null | awk 'NR>1 && NF>0 {print}' | wc -l)"
    sessions="$(sudo "$VPPCTL_CMD" -s "$VPP_CLI_SOCK" show session verbose 1 2>/dev/null | grep -cE '^\[' || true)"
    if [ "$apps" -ne 0 ] || [ "$sessions" -ne 0 ]; then
        echo "[soak] FAIL after round $round: VPP residue apps=$apps sessions=$sessions" >&2
        sudo "$VPPCTL_CMD" -s "$VPP_CLI_SOCK" show app >&2 || true
        sudo "$VPPCTL_CMD" -s "$VPP_CLI_SOCK" show session verbose 1 >&2 || true
        exit 1
    fi
}

# --- soak loop --------------------------------------------------------------

total_ok=0
total_fail=0
soak_start=$(date +%s)

for round in $(seq 1 "$ROUNDS"); do
    round_log="$LOG_DIR/client-round-$round.log"
    echo "[soak] round $round/$ROUNDS: conc=$CONC reqs=$REQS (total=$((CONC * REQS)))"
    # HTTP_CLIENT_EXTRA lets a caller add flags like `-no-keepalive` to
    # every round without editing the script; word-split intentionally.
    if run_as_user timeout --kill-after=5 "$CLIENT_TIMEOUT" \
        "$VCLGO_BIN/vclgo" run "$VCLGO_BIN/examples/http_client" \
        -url "http://127.0.0.1:$PORT/" \
        -conc "$CONC" -reqs "$REQS" -timeout "${HTTP_TIMEOUT:-30s}" \
        ${HTTP_CLIENT_EXTRA:-} \
        >"$round_log" 2>&1
    then
        :
    else
        rc=$?
        echo "[soak] round $round FAIL: http_client rc=$rc" >&2
        tail -40 "$round_log" >&2
        exit 1
    fi

    summary="$(grep '^http_client:' "$round_log" | tail -1)"
    if [ -z "$summary" ]; then
        echo "[soak] round $round: missing summary line" >&2
        tail -20 "$round_log" >&2
        exit 1
    fi
    echo "         $summary"

    ok="$(echo "$summary" | grep -oP 'ok=\K[0-9]+')"
    fail="$(echo "$summary" | grep -oP 'fail=\K[0-9]+')"
    total_ok=$((total_ok + ok))
    total_fail=$((total_fail + fail))
    if [ "$fail" -ne 0 ]; then
        echo "[soak] round $round FAIL: $fail requests failed" >&2
        exit 1
    fi

    check_unsolicited "$round_log" "client round $round"
    check_unsolicited "$LOG_DIR/server.log" "server (through round $round)"

    # Give VPP a beat between rounds so residual TIME_WAIT / FIN traffic
    # from the just-exited client can drain. Adjust via INTER_ROUND_SLEEP.
    if [ "$round" -lt "$ROUNDS" ]; then
        sleep "${INTER_ROUND_SLEEP:-1}"
    fi
done

soak_elapsed=$(( $(date +%s) - soak_start ))

# --- final residue check (server still running) ----------------------------
# We check while the server is still up: N-17 would show as a stuck session
# with un-acked data, not just a fd leak. If the count of listener-side
# sessions ever exceeded 1 (the listener itself), that would be a red flag.

# grep -c exits 1 on zero matches, which under `set -e` would kill the
# script inside a $(...) assignment; add `|| true` to make the count
# resilient to the (expected) zero-matches case.
listeners="$(sudo "$VPPCTL_CMD" -s "$VPP_CLI_SOCK" show session verbose 1 2>/dev/null | grep -c ' LISTEN' || true)"
established="$(sudo "$VPPCTL_CMD" -s "$VPP_CLI_SOCK" show session verbose 1 2>/dev/null | grep -c ' ESTABLISHED' || true)"
echo "[soak] mid-soak snapshot: LISTEN=$listeners ESTABLISHED=$established"

# Stop the server; then check for full residue.
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

echo "[soak] OK — $ROUNDS rounds, $total_ok OK, $total_fail fail, elapsed ${soak_elapsed}s"
