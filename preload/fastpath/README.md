# Approach #4 fastpath preload

This directory contains the current Frida-Gum native fastpath for unmodified
Go applications:

```text
build/libvclgo_gum_vcl.so
```

It is not the retired Frida `Interceptor.attach`/JavaScript implementation.
It uses the Frida-Gum C library and Capstone for executable inspection,
near-text allocation, and controlled in-memory patch installation.

## Current capability

- discovers and patches Go raw-syscall sites and generic wrappers;
- converts the Linux syscall ABI to the C/SysV dispatcher ABI;
- switches to a 512 KiB pthread-local dispatcher stack;
- routes TCP and UDP through the shared permanent-owner VCL dispatcher;
- preserves Go epoll/netpoll through real socket-pair surrogate fds;
- supports kernel passthrough when `VCL_CONFIG` is unset;
- skips VCL initialization when the preloaded target is not a recognized Go
  binary.

The current lab evidence includes 128-way cut-through TCP, routed connected
and unconnected UDP, and routed HTTP with and without keepalive. See
[status](../../docs/status.md) and
[test topology](../../docs/test_topology.md) for exact results and
limitations.

## Build

```bash
make -C ../.. pc VPP_PREFIX=/matching/vpp/prefix
make -C ../.. build-fastpath
```

## Files

| File | Purpose |
|---|---|
| `gum_vcl.c` | VCL-routing preload (shipping) |
| `Makefile` | Builds `build/libvclgo_gum_vcl.so` |
| `vendor/` | Vendored Frida-Gum and Capstone |

Bring-up milestones (M1 read-only probe, M2 identity patcher, M2.5 wrapper
patcher, M2+M2.5 combined, M3a C-dispatcher routing) that led to
`gum_vcl.c` have been removed from the tree. The design record is preserved
in [architecture_fastpath.md](../../docs/architecture_fastpath.md) and the
per-milestone diagrams in
[architecture_diagrams_fastpath.md](../../docs/architecture_diagrams_fastpath.md).

The active dispatcher lives in `../../dispatcher/src/*_native.c`. It was
originally shared with the retired Approach #3 seccomp preload; that
backend has been removed from the codebase, so the dispatcher now serves
this fastpath preload exclusively.

## Boundaries

This is still an engineering prototype. The Go-version/container matrices,
higher-protocol and long-duration soaks, fault injection, listener sharding,
and the tested VPP branch's heavy local cut-through churn defect remain open.

Historical context:

- [Approach comparison](../../docs/comparison_approaches.md)
- [Why Frida Interceptor was dropped](../../docs/why_frida_dropped.md)
- [Fastpath architecture](../../docs/architecture_fastpath.md)
- [Open gates](../../docs/plan.md)
