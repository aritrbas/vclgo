#!/bin/bash
# kill_all.sh — nuke every vclgo-related process on this host.
#
# Use this when a fastpath test script has been Ctrl-Z'd, killed uncleanly,
# or otherwise left orphan LD_PRELOAD-spawned targets (echo_{server,client},
# http_{server,client}, udp_echo_{server,client}) behind. Safe to run at
# any time; matches only vclgo-owned names.
#
# Usage:
#   sudo bash test/kill_all.sh          # normal run
#   sudo VERBOSE=1 bash test/kill_all.sh # show what would/did die

set -euo pipefail

VERBOSE="${VERBOSE:-0}"

# In practice everything the fastpath tests launch is a leaf, so order is
# advisory.
PATTERNS=(
    'examples/echo_server'               # TCP echo target
    'examples/echo_client'               # TCP echo target
    'examples/http_server'               # HTTP target
    'examples/http_client'               # HTTP target
    'examples/udp_echo_server'           # UDP echo target
    'examples/udp_echo_client'           # UDP echo target
    'bash test/run_smoke_fastpath\.sh'
    'bash test/run_smoke_udp_fastpath\.sh'
    'bash test/run_concurrency_fastpath\.sh'
    'bash test/run_http_soak_fastpath\.sh'
)

any=0
for pat in "${PATTERNS[@]}"; do
    pids="$(pgrep -f -- "$pat" 2>/dev/null || true)"
    if [ -n "$pids" ]; then
        any=1
        [ "$VERBOSE" = "1" ] && echo "kill_all: TERM /$pat/ pids: $pids"
        # shellcheck disable=SC2086
        pkill -TERM -f -- "$pat" 2>/dev/null || true
    fi
done

# Give the tree ~1s to unwind cleanly, then SIGKILL anything that stuck.
sleep 1
for pat in "${PATTERNS[@]}"; do
    pids="$(pgrep -f -- "$pat" 2>/dev/null || true)"
    if [ -n "$pids" ]; then
        [ "$VERBOSE" = "1" ] && echo "kill_all: KILL /$pat/ pids: $pids"
        pkill -KILL -f -- "$pat" 2>/dev/null || true
    fi
done

if [ "$any" = "0" ]; then
    echo "kill_all: nothing to kill."
else
    echo "kill_all: done."
fi
