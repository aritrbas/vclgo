#!/bin/bash
# Shared path resolution and process environment for vclgo tests.
#
# vclgo now ships a single backend: the Approach #4 in-process fastpath
# preload (libvclgo_gum_vcl.so). This file provides the VPP-side path
# resolution common to every test harness under test/. Fastpath-specific
# variables (e.g. VCLGO_GUM_LIB) live in the individual test scripts.

set -o pipefail

: "${VPP_PREFIX:=/usr}"
: "${VPP_BIN:=$VPP_PREFIX/bin/vpp}"
: "${VPPCTL:=$VPP_PREFIX/bin/vppctl}"

if [ -z "${VPP_LIB:-}" ]; then
    _multiarch=""
    if command -v dpkg-architecture >/dev/null 2>&1; then
        _multiarch="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || true)"
    fi
    for _candidate in         "$VPP_PREFIX/lib${_multiarch:+/$_multiarch}"         "$VPP_PREFIX/lib64"         "$VPP_PREFIX/lib"
    do
        if [ -d "$_candidate" ] &&
           ls "$_candidate"/libvppcom.so* >/dev/null 2>&1; then
            VPP_LIB="$_candidate"
            break
        fi
    done
    : "${VPP_LIB:=$VPP_PREFIX/lib${_multiarch:+/$_multiarch}}"
    unset _multiarch _candidate
fi

: "${VCLGO_REPO:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
: "${VCLGO_BIN:=$VCLGO_REPO/bin}"

if [ -z "${RUN_AS_USER:-}" ]; then
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        RUN_AS_USER="$SUDO_USER"
    else
        RUN_AS_USER="$(id -un)"
    fi
fi
if [ -z "${RUN_AS_HOME:-}" ]; then
    RUN_AS_HOME="$(getent passwd "$RUN_AS_USER" | cut -d: -f6)"
    : "${RUN_AS_HOME:=/tmp}"
fi

export VPP_PREFIX VPP_BIN VPPCTL VPP_LIB
export VCLGO_REPO VCLGO_BIN RUN_AS_USER RUN_AS_HOME

require_vpp_paths() {
    local missing=0
    local variable
    for variable in VPP_BIN VPPCTL; do
        if [ ! -x "${!variable}" ]; then
            echo "env.sh: $variable (${!variable}) is not executable" >&2
            missing=1
        fi
    done
    if ! ls "$VPP_LIB"/libvppcom.so* >/dev/null 2>&1; then
        echo "env.sh: VPP_LIB ($VPP_LIB) has no libvppcom.so" >&2
        missing=1
    fi
    if [ "$missing" -ne 0 ]; then
        cat >&2 <<HINT

Set VPP_PREFIX to the matching VPP install, for example:

  VPP_PREFIX=/home/aritrbas/vpp/vpp/build-root/install-vpp-native/vpp \
    VCL_CONFIG=... bash test/run_smoke_fastpath.sh
HINT
        return 1
    fi
}
