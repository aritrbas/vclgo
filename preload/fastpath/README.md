# Frida-Gum fastpath preload

This directory builds the only vclgo preload:

```text
build/libvclgo_gum_vcl.so
```

It embeds the native Frida-Gum library and Capstone. The constructor inspects
the main Linux/amd64 Go executable, emits near-text thunks plus a shared ABI
shim, and patches recognized raw-syscall paths in memory. There is no
external agent or service.

## Build

```bash
make -C ../.. pc VPP_PREFIX=/matching/vpp/prefix
make -C ../.. build-fastpath
```

The resulting preload links to
`../../bin/libvclgo_dispatcher.so` and matching VPP/VCL libraries.

## Run

```bash
export VCL_CONFIG=/absolute/path/to/vcl.conf
export VCLGO_WORKERS=4
export LD_LIBRARY_PATH=/matching/vpp/lib:${LD_LIBRARY_PATH:-}
export LD_PRELOAD=$PWD/build/libvclgo_gum_vcl.so
exec /absolute/path/to/go-application
```

## Current responsibilities

| Area | Implementation |
|---|---|
| Discovery | Enumerate the main executable's `.text`; classify immediate-number syscall sites and generic Go wrappers |
| Code generation | Allocate an 8 KiB near-text region; emit per-site thunks, wrapper trampolines, and one shared shim |
| ABI bridge | Convert Go/Linux syscall registers to SysV C arguments, including stack argument `a5` |
| Stack safety | Enter C dispatch on a 512 KiB pthread-local mapping and restore the Go stack before returning |
| Dispatch | Route supported VCL-owned TCP/UDP operations to the native dispatcher; preserve all six arguments on raw kernel calls |
| Go return path | Resume the original Go `.text` result/error translation without a trampoline return PC |
| Lifecycle | Initialize VCL only after recognizing a Go target; coordinate terminal application detach |

The dispatcher in `../../dispatcher/` owns session routing, permanent VCL
owner pthreads, socket-pair readiness surrogates, and all `vls_*` calls.

## Required startup evidence

Run initial validation with `VCLGO_LOG=1` and require:

```text
[vclgo/gum] vclgo_init ok ... passthrough=0
[vclgo/gum] patched M2:<patched>/<discovered> wrappers:<patched>/<resolved>
```

An immediate-site table overflow is separated from non-immediate sites and
refuses patching before VCL initialization. Any other incomplete required
patch set is a deployment failure even though the constructor still only
logs individual write failures or unresolved wrappers.

## Boundaries

This remains a laboratory implementation. Raw-kernel argument six,
`sendfile`, and `close_range` now have live regressions, but patch installation
is not atomic and arbitrary invalid user pointers are not safely contained as
`EFAULT`. Compatibility, protocol, endurance, fault-injection,
listener-scaling, deployment-policy, and observability gates are tracked in
[status](../../docs/status.md).

Detailed machine-code, memory, register, and stack layouts are in
[text patching](../../docs/text_patching.md); the end-to-end design is in
[architecture](../../docs/architecture.md); validated network layouts are in
[test topology](../../docs/test_topology.md).
