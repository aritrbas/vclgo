# vclgo production-readiness plan

Last updated: 2026-07-22.

## Goal

Run dynamically linked, unmodified Linux/amd64 Go applications through VPP
VCL with:

- direct `LD_PRELOAD=libvclgo_gum_vcl.so`;
- native Frida-Gum patching of Go raw-syscall paths;
- correct Go scheduling, netpoll, deadlines, stacks, and error results;
- multiple permanent VCL owner pthreads and multi-worker VPP;
- sustained workloads with 100 or more goroutines.

Approach #4 is the only implementation built from this repository. There is
no runtime backend or phase selector.

## Completed implementation

- Immediate-number `SYSCALL` sites and the three generic Go syscall wrappers
  are discovered in the main executable and patched in memory.
- The shim converts Linux syscall registers to SysV arguments, switches to a
  512 KiB pthread-local native stack, and returns through valid Go `.text`.
- The native dispatcher routes supported INET TCP/UDP calls to permanent VLS
  owner pthreads and leaves unrelated kernel descriptors on the raw path.
- Real nonblocking socket-pair surrogates integrate VCL readiness with Go
  epoll/netpoll and Go-managed deadlines.
- Sessions have exact registry ownership, reference-counted lifetime, and one
  immutable VCL owner; accepted children inherit their listener owner.
- Connected and unconnected UDP, TCP control/data, HTTP/1, close, and terminal
  VCL application detach are implemented at the documented surface.
- The July 22 validation matrix passed cut-through TCP/deadlines and routed
  UDP/HTTP on two multi-worker VPP instances. Exact evidence is in
  [status.md](status.md).

## Ordered gates

The first two items are correctness blockers. Scale or protocol results do
not compensate for them.

| Priority | Gate | Required completion evidence |
|---:|---|---|
| P0 | Forward syscall argument 6 on raw fallback | Replace the five-argument raw helper; test a known six-argument kernel syscall through both passthrough and non-owned-fd paths |
| P0 | Make patch installation atomic | Resolve and preflight every required site first; either install the complete set or restore all modified bytes, tear VCL down, and refuse startup |
| P0 | Add executable tests | Unit tests for ABI/result conversion, classification, registry/refcounts, address conversion, unsupported calls, and injected startup failures |
| P0 | Prove Go-buffer lifetime | Prove that borrowed buffers remain reachable and stationary while an owner pthread uses them, or implement an explicit pin/copy contract; validate with forced GC and async preemption |
| P0 | Prove direct-site register liveness | For every recognized immediate syscall site, prove the continuation does not consume SysV caller-saved registers or preserve the required register set explicitly |
| P1 | Routed raw TCP | Repeatable two-VPP echo payload, deadline, reset, refused-connect, half-close, and shutdown matrix |
| P1 | Owned-fd syscall policy | Translate or explicitly reject every relevant operation; never let operations such as `sendfile`, `splice`, or unknown `ioctl` act on the surrogate as if it carried payload |
| P1 | Constructor compatibility | Supported Go-version matrix, PIE/non-PIE and stripped binaries, wrapper-layout checks, rollback tests, and explicit unsupported-binary behavior |
| P1 | Runtime safety soak | Multi-hour asynchronous-preemption/profiling run at high `GOMAXPROCS` and 100–1,000 goroutines with core/log scanning |
| P1 | Protocol matrix | TLS, HTTP/2, gRPC, IPv6, large bodies, cancellation, slow peers, and error propagation |
| P1 | Lifecycle/fault matrix | VPP restart, application-socket loss, resource exhaustion, signal termination, active connection shutdown, and startup failures |
| P1 | Deployment matrix | Exact production VPP/VCL revision, container image, hard `RLIMIT_NOFILE`, executable-memory policy, LSM, capabilities, and shared-memory permissions |
| P1 | Cut-through defect | Isolate and fix the same-VPP heavy HTTP churn crash in the tested VPP branch, or explicitly exclude that topology |
| P2 | Listener scaling | Measure the single-listener owner hot spot; add and test listener sharding/reuse-port if required |
| P2 | Observability | Export patch, dispatch, queue-depth, wake, error, owner/session, and teardown counters with actionable alerts |
| P2 | Continuous regression | Provision both topologies from clean state, assert VCL routing at both endpoints, collect VPP state, and fail on residue or crash signatures |

## Promotion criteria

An internal beta requires all P0 gates plus routed TCP/UDP/HTTP reproducibility
on the target Go and VPP versions. Production additionally requires every P1
gate relevant to the deployed topology and workload, a sustained-load
capacity result with safety margin, monitoring, rollback, and automated
regression coverage.

The following are not acceptable substitutes:

- a same-VPP local-scope pass presented as routed TCP or UDP evidence;
- `go test ./...` reported as unit coverage while packages say
  `[no test files]`;
- startup that logs a skipped required patch and continues;
- successful TCP/HTTP tests used to infer six-argument raw-syscall safety;
- a successful short soak used as a substitute for a Go-pointer lifetime proof;
- a configured number of VCL owners used to infer even session or VPP-worker
  distribution.

## Scope boundaries

- Static and privileged executables are outside the `LD_PRELOAD` model.
- Full Linux socket ABI compatibility is not claimed.
- A goroutine is never mapped one-to-one to a VCL owner or VPP worker.
- Active teardown and reinitialization inside one process are unsupported.

See [architecture.md](architecture.md),
[text_patching.md](text_patching.md), and
[test_topology.md](test_topology.md) for the design and evidence model.
