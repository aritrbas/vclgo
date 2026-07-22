# vclgo documentation

Last synchronized with code and tests: 2026-07-22.

The root of this directory documents the only implementation in the current
tree: **Approach #4, the native Frida-Gum fastpath**.

## Reading order

| Document | Purpose | Authority |
|---|---|---|
| [Current status](status.md) | Verified evidence, unsupported behavior, and production gates | Readiness source of truth |
| [Test topology](test_topology.md) | What each cut-through or routed test actually proves | Test-claim source of truth |
| [Architecture](architecture.md) | End-to-end patcher, dispatcher, VCL/VLS, and lifecycle design | Design source of truth |
| [Text patching](text_patching.md) | Concrete Go `.text` bytes, thunks, trampolines, ABI conversion, and stack layouts | Machine-code source of truth |
| [Architecture diagrams](architecture_diagrams.md) | Process, memory, register, stack, readiness, and lifecycle diagrams | Visual design atlas |
| [Goroutine/pthread model](model_goroutine_pthread.md) | Mapping among goroutines, Go Ms, owner pthreads, VLS, and VPP workers | Ownership source of truth |
| [Concurrency analysis](analysis_goroutine_pthread.md) | Scheduling, blocking, close races, and scaling analysis | Detailed concurrency rationale |
| [Architecture decisions](analysis_architecture.md) | Accepted decisions and consequences | Decision record |
| [Bug and risk ledger](analysis_bugs.md) | Fixed defects, open risks, and stop conditions | Risk source of truth |
| [Adoption guide](adoption_guide.md) | Build, configure, validate, deploy, and roll back | Operator guide |
| [Plan](plan.md) | Ordered work required before production promotion | Work queue |

## Documentation rules

- A test claim includes topology, load, VCL owner count, VPP worker count,
  and result.
- Same-VPP local scope is called **VCL cut-through**. It is never presented
  as TCP/UDP packet-dataplane validation.
- Two-VPP global scope over memif is called **routed acceptance**.
- Implemented behavior is separated from tested behavior. For example, IPv6
  paths exist, but the recorded routed acceptance matrix is IPv4.
- Known production blockers remain visible in
  [status.md](status.md) and [analysis_bugs.md](analysis_bugs.md).
- Machine-code examples name the Go version and binary used to obtain them.

## Current design in one paragraph

`libvclgo_gum_vcl.so` is loaded with `LD_PRELOAD`. Its constructor uses
Frida-Gum and Capstone to discover Go raw-syscall paths and patch the main
executable's in-memory `.text`. A native shim preserves Linux syscall
semantics, switches from the goroutine stack to a dedicated dispatcher stack,
and calls a POSIX-shaped API. Each VLS handle remains permanently attached to
one registered owner pthread. A real nonblocking Unix socketpair represents
the VCL session to Go, allowing the ordinary runtime epoll/netpoll and
deadline machinery to remain authoritative.

## Historical archive

Designs that are not present in the current codebase are isolated under
[deprecated/](deprecated/). They are retained only for engineering history
and are not part of the build, runtime, or current test matrix.
