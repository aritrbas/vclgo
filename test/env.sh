#!/bin/bash
# Shared path resolution and process environment for native vclgo tests.

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
: "${VCLGO_PRELOAD:=$VCLGO_BIN/libvclgo_preload.so}"

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
export VCLGO_REPO VCLGO_BIN VCLGO_PRELOAD RUN_AS_USER RUN_AS_HOME

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
    VCL_CONFIG=... bash test/run_smoke.sh
HINT
        return 1
    fi
}

require_vclgo_paths() {
    local missing=0
    local path
    for path in         "$VCLGO_BIN/vclgo"         "$VCLGO_BIN/libvclgo_dispatcher.so"         "$VCLGO_PRELOAD"         "$VCLGO_BIN/examples/echo_server"         "$VCLGO_BIN/examples/echo_client"
    do
        if [ ! -e "$path" ]; then
            echo "env.sh: missing $path" >&2
            missing=1
        fi
    done
    if [ "$missing" -ne 0 ]; then
        echo "Build first: make -C $VCLGO_REPO build" >&2
        return 1
    fi
}

# Run a command as the invoking non-root user while preserving only the
# settings required by the native preload backend.
run_as_user() {
    local workers="${VCLGO_WORKERS:-4}"
    local notifiers="${VCLGO_NOTIFIERS:-32}"
    local -a command_env=(
        env
        "LD_LIBRARY_PATH=$VPP_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        "VCL_CONFIG=${VCL_CONFIG:-}"
        "VCLGO_PRELOAD=$VCLGO_PRELOAD"
        "VCLGO_WORKERS=$workers"
        "VCLGO_NOTIFIERS=$notifiers"
        "VCLGO_LOG=${VCLGO_LOG:-1}"
        "GOTRACEBACK=${GOTRACEBACK:-crash}"
    )

    if [ "$(id -u)" -eq 0 ] && [ "$RUN_AS_USER" != "root" ]; then
        sudo -u "$RUN_AS_USER" "${command_env[@]}"             "PATH=$PATH" "HOME=$RUN_AS_HOME" "$@"
    else
        "${command_env[@]}" "$@"
    fi
}

export -f run_as_user
