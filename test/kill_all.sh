#!/bin/bash
# kill_all.sh — nuke every vclgo-related process on this host.
#
# Use this when a test script has been Ctrl-Z'd, killed uncleanly, or
# otherwise left orphan `vclgo run` / `frida` / `echo_{server,client}`
# processes behind. Safe to run at any time; matches only vclgo-owned
# names.
#
# Usage:
#   sudo bash test/kill_all.sh          # normal run
#   sudo VERBOSE=1 bash test/kill_all.sh # show what would/did die

set -euo pipefail

VERBOSE="${VERBOSE:-0}"

# Order matters: kill the deepest layer first so parents don't restart
# children. In practice everything vclgo launches is a leaf so order is
# advisory, but we start with the frida-spawned targets to reduce log
# noise from "attempted to write to closed peer" during teardown.
PATTERNS=(
    'frida.*interceptor\.js'         # frida CLI + interceptor
    'examples/echo_server'           # frida-spawned target
    'examples/echo_client'           # frida-spawned target
    'bin/vclgo run'                  # Go launcher
    'bash test/run_smoke\.sh'        # smoke script itself
    'bash test/run_concurrency\.sh'  # concurrency script
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
