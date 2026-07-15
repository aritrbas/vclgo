#!/bin/bash
# start_vpp.sh — start VPP for vclgo integration testing. Nearly identical
# to vclnet/test/start_vpp.sh but scoped to this repo so vclgo can be tested
# without a vclnet checkout.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "$SCRIPT_DIR/env.sh"
require_vpp_paths

CLI_SOCK=/run/vpp/cli.sock
APP_SOCK=/run/vpp/app_ns_sockets/default

sudo killall vpp 2>/dev/null || true
sleep 1
sudo rm -f "$CLI_SOCK"

sudo "$VPP_BIN" \
  unix { log /tmp/vpp.log full-coredump cli-listen "$CLI_SOCK" } \
  api-trace { on } \
  session { enable use-app-socket-api }

echo "Waiting for VPP to start..."
for _ in $(seq 1 20); do
    if [ -S "$CLI_SOCK" ] && [ -S "$APP_SOCK" ]; then
        break
    fi
    sleep 1
done

if [ ! -S "$APP_SOCK" ]; then
    echo "ERROR: VPP app socket not found after 20s"
    tail -20 /tmp/vpp.log || true
    exit 1
fi

sudo chmod o+w "$CLI_SOCK"
sudo chmod o+w "$APP_SOCK"

# Configure a loopback interface inside VPP with 127.0.0.1/8 and ::1/128 so
# apps talking through VCL can resolve localhost through VPP's session layer.
# Without this, `vls_connect` to 127.0.0.1 has no route inside VPP and simply
# hangs waiting for a SYN-ACK that never comes (the client parks in
# `vclgo_poller_wait` for EPOLLOUT and the server's `Accept` never fires).
# Idempotent: `create loopback interface` re-creates the next free loopN, so
# check if `loop0` already exists and skip if so.
#
# NOTE: `vppctl show interface loop0` returns exit 0 EVEN WHEN THE INTERFACE
# IS ABSENT, printing the diagnostic "show interface: unknown input `loop0'"
# — that string literally contains the substring "loop0", so a naive
# `grep -q loop0` false-positives and we end up skipping creation on a fresh
# VPP. Grep the FULL interface list against a name-anchored regex instead:
# `show interface` prints one row per interface with the name in column 1.
if ! "$VPPCTL" -s "$CLI_SOCK" show interface 2>/dev/null \
        | awk '{ print $1 }' | grep -qx 'loop0'; then
    "$VPPCTL" -s "$CLI_SOCK" create loopback interface
    "$VPPCTL" -s "$CLI_SOCK" set interface state loop0 up
    "$VPPCTL" -s "$CLI_SOCK" set interface ip address loop0 127.0.0.1/8
    "$VPPCTL" -s "$CLI_SOCK" set interface ip address loop0 ::1/128
    echo "Loopback loop0 configured with 127.0.0.1/8 and ::1/128"
else
    echo "Loopback loop0 already present, skipping reconfiguration"
fi

echo "VPP started successfully:"
"$VPPCTL" -s "$CLI_SOCK" show version
echo "App socket: $APP_SOCK"
