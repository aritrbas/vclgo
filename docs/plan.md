# vclgo production-readiness plan

Last updated: 2026-07-23.

## Goal

Run dynamically linked, unmodified Linux/amd64 Go applications through VPP
VCL with:

- direct `LD_PRELOAD=libvclgo_gum_vcl.so`;
- native Frida-Gum patching of Go raw-syscall paths;
- correct Go scheduling, netpoll, deadlines, stacks, and error results;
- multiple permanent VCL owner pthreads and multi-worker VPP;
- same-VPP app-local VCL cut-through as the production transport;
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
- Raw fallback forwards a0–a5, `sendfile` translates regular-file input to a
  VCL TCP output, and `close_range` preserves registry/session semantics.
- Immediate-site capacity overflow is explicit and refuses a truncated patch
  set before VCL initialization; Syscall6 byte dumps are trace-only.
- The July 23 composed matrix passed routed IPv6 TCP/UDP, exact TCP errors,
  TLS/HTTP1, TLS/HTTP2, cancellation, gRPC, and an IPv4 UDP ICMP-error gate on
  two multi-worker VPP instances. Wildcard `[::]:0` UDP passed at 100-way
  concurrency. Exact evidence is in [status.md](status.md).

## Ordered gates

Every P0 item is a correctness blocker. Scale or routed protocol results do
not compensate for them.

| Priority | Gate | Required completion evidence |
|---:|---|---|
| P0 | Make patch installation atomic | Resolve and preflight every required site first; either install the complete set or restore all modified bytes, tear VCL down, and refuse startup |
| P0 | Add executable tests | Unit tests for ABI/result conversion, classification, registry/refcounts, address conversion, unsupported calls, and injected startup failures |
| P0 | Prove Go-buffer lifetime | Prove that borrowed buffers remain reachable and stationary while an owner pthread uses them, or implement an explicit pin/copy contract; validate with forced GC and async preemption |
| P0 | Prove direct-site register liveness | For every recognized immediate syscall site, prove the continuation does not consume SysV caller-saved registers or preserve the required register set explicitly |
| P0 | Fix the production cut-through crash | Reproduce, isolate, and fix the same-VPP heavy HTTP churn failure in the tested VPP cut-through accept/cleanup path; routed HTTP success is not closure evidence |
| P1 | Production cut-through matrix | Run app-local UDP, HTTP/1.1, TLS, HTTP/2, cancellation, gRPC, half-close/refused/reset, residue, and repeated churn gates while asserting live VPP sessions contain `[CT:*]` |
| P1 | Routed raw TCP | IPv6 echo, reset, refused-connect, and half-close pass in the complete matrix; add routed deadlines, bidirectional shutdown stress, and repeatability runs |
| P1 | Owned-fd syscall policy | Translate or explicitly reject every relevant operation; `sendfile`/`close_range` are covered, while `splice`, unknown `ioctl`, OOB, and complex control-message paths remain |
| P1 | Invalid-pointer containment | Invalid non-null buffers/iovecs/headers/sockaddrs/lengths/offsets must return `EFAULT`, never SIGSEGV a dispatcher pthread |
| P1 | Constructor compatibility | Supported Go-version matrix, PIE/non-PIE and stripped binaries, wrapper-layout checks, rollback tests, and explicit unsupported-binary behavior |
| P1 | Runtime safety soak | Multi-hour asynchronous-preemption/profiling run at high `GOMAXPROCS` and 100–1,000 goroutines with core/log scanning |
| P1 | Protocol matrix | IPv6, TLS, HTTP/2, gRPC, cancellation, TCP errors, wildcard UDP, and supported IPv4 ICMP delivery pass once end-to-end; add repetition, large/streaming bodies, slow peers, WebSocket, UDP truncation/control data, and an upstream VPP IPv6-ICMP implementation or explicit exclusion |
| P1 | Lifecycle/fault matrix | VPP restart, application-socket loss, resource exhaustion, signal termination, active connection shutdown, and startup failures |
| P1 | Deployment matrix | Exact production VPP/VCL revision, container image, hard `RLIMIT_NOFILE`, executable-memory policy, LSM, capabilities, and shared-memory permissions |
| P2 | Fork boundary | Detect/reject forked-child VCL inheritance or implement a tested at-fork reset contract |
| P2 | Listener scaling | Measure the single-listener owner hot spot; add and test listener sharding/reuse-port if required |
| P2 | Observability | Export patch, dispatch, queue-depth, wake, error, owner/session, and teardown counters with actionable alerts |
| P2 | Continuous regression | Provision both topologies from clean state, assert VCL routing at both endpoints, collect VPP state, and fail on residue or crash signatures |

## Promotion criteria

An internal beta requires all P0 gates plus reproducible app-local
cut-through TCP/UDP/HTTP results on the target Go and VPP versions. Routed
TCP/UDP/HTTP reproducibility remains required supporting evidence but cannot
replace the target-topology gate. Production additionally requires every P1
gate relevant to the deployed workload, a sustained-load capacity result
with safety margin, monitoring, rollback, and automated regression coverage.

The following are not acceptable substitutes:

- a same-VPP local-scope pass presented as routed TCP or UDP evidence;
- a routed memif pass presented as app-local cut-through evidence;
- `go test ./...` reported as unit coverage while packages say
  `[no test files]`;
- startup that logs a skipped required patch and continues;
- focused a5/sendfile/close-range probes used to infer safety for every other
  syscall, pointer, or concurrency case;
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
