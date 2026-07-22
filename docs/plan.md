# vclgo project plan

Last updated: 2026-07-22.

## Goal

Run dynamically linked, unmodified Go applications through VPP VCL using
`LD_PRELOAD`, while preserving Go netpoll/deadlines and supporting hundreds
of goroutines, multiple VCL owner pthreads, and multi-worker VPP.

## Approach map

| # | Name | Decision |
|---:|---|---|
| 1 | vclnet/source integration | Use when application source can change (separate repo) |
| 2 | Frida Interceptor/JavaScript | Retired; code deleted (docs retained) |
| 3 | seccomp user notification | Retired; code deleted (docs retained) |
| 4 | Frida-Gum native fastpath | **Only shipping backend** |

The old Phase 1/2/3 labels are chronology, not configurable modes. Approach
number 4 is selected with `LD_PRELOAD=.../libvclgo_gum_vcl.so`.

## Completed for Approach #4

- Native Frida-Gum/Capstone discovery and in-memory patching of Go syscall
  sites and generic wrappers.
- Explicit Linux syscall ABI to SysV conversion and kernel-style result/error
  conversion back to Go's original wrapper.
- Per-pthread 512 KiB dispatcher stack; no VLS/VCL frames on a goroutine
  stack.
- Shared dispatcher with real socket-pair surrogate fds and permanent VLS
  owner pthreads.
- TCP control/data, epoll readiness, deadlines, options, shutdown, and close.
- UDP connected/unconnected data paths, ephemeral bind allocation, connected
  peer caching, and name/error semantics.
- Terminal detach-only teardown that avoids a per-session disconnect storm.
- Non-Go `LD_PRELOAD` guard and server/client preload propagation.
- Cut-through TCP concurrency/deadline validation.
- Routed two-VPP UDP and HTTP-over-TCP validation.

Exact results are in [status.md](status.md); topology and test commands are in
[test_topology.md](test_topology.md).

## Approach D fastpath open gates

The original gate identifiers are retained so older design links remain
meaningful.

| Gate | State | Evidence or remaining work |
|---|---|---|
| G-D1 preload reaches both endpoints | Closed | Harness checks `passthrough=0` |
| G-D2 skip VCL init for non-Go helpers | Closed | Helpers such as `timeout` no longer double-register |
| G-D3 two-process VCL bring-up | Closed | TCP echo and routed HTTP endpoints initialize VCL |
| G-D4 128-way payload integrity | Closed for cut-through | 16 MiB each way, zero errors |
| G-D5 100 simultaneous deadlines | Closed for cut-through | 250 ms blocked-read test passed |
| G-D6 routed HTTP integrity/failure gate | Closed at tested scale | Keepalive on/off: 50,000 requests each, plus 128-way runs |
| G-D7 target container `mprotect` policy | Open | Test intended image/LSM/seccomp profile |
| G-D8 launcher `--backend=fastpath` | Open | Direct `LD_PRELOAD` is currently authoritative |
| G-D9 Go-version matrix | Open | Exercise supported Go releases |
| G-D10 unknown-prologue degradation | Closed in code; matrix open | Unrecognized wrappers are logged/skipped; verify across Go versions |
| G-D11 operational counters | Open | Export/dump fastpath and owner statistics |
| G-D12 async-preemption soak | Open | Multi-hour `SIGPROF`/high-`GOMAXPROCS` run |
| G-D13 exact `accept4` flag matrix | Open | Verify every flag combination |
| G-D14 fault injection | Open | VPP restart, app-socket loss, resource pressure |
| G-D15 CI gates | Open | Automate build, CT, and routed tests |
| G-D16 UDP VCL path | Closed at tested scale | Connected and unconnected 128-way routed runs passed |
| G-D17 heavy local cut-through churn | External/open | Reproduce/fix in tested VPP branch |
| G-D18 listener-owner sharding | Open | Add multiple listeners/`SO_REUSEPORT` if server scaling needs it |
| G-D19 higher protocols | Open | TLS, HTTP/2, and gRPC soaks |
| G-D20 endurance/scale | Open | Multi-hour mixed workload at 100–1,000 goroutines |

## Next work, in order

1. Preserve the current routed UDP and HTTP tests as repeatable scripts or CI
   jobs that also create the two-VPP topology.
2. Add a routed raw-TCP echo gate so TCP payload testing does not rely only on
   HTTP and cut-through echo.
3. Run TLS/HTTP2/gRPC and connection-error/half-close/reset matrices.
4. Run the Go-version and target-container compatibility matrices.
5. Add long-duration preemption, churn, and 1,000-goroutine soaks.
6. Decide whether the workload needs multiple listeners to distribute
   accepted sessions over several VCL owners.
7. Isolate the same-VPP cut-through crash in VPP; do not hide it by calling a
   routed test a cut-through test or vice versa.

## Promotion criteria

Approach #4 can move from engineering prototype to an internal beta when:

- routed TCP, UDP, HTTP, and higher-protocol gates are repeatable from a clean
  topology;
- the intended Go versions and container profile pass;
- no Go unwinder, register, stack, heap, or VCL TLS signature appears in an
  extended preemption/soak run;
- all VPP applications/sessions drain after normal shutdown;
- owner saturation and listener concentration are acceptable for the target
  workload;
- unsupported socket operations are either explicitly rejected or covered by
  tests with defined semantics.

Production readiness additionally requires operational monitoring, automated
regression coverage, fault injection, and acceptance on the exact deployed
VPP revision.

## Non-goals

- Supporting static or privileged executables via `LD_PRELOAD`.
- Claiming full Linux socket ABI compatibility.
- Mapping one goroutine to one VCL or VPP worker.
- Treating same-VPP local cut-through as routed TCP/UDP evidence.
- Reintroducing Frida Interceptor/JavaScript callbacks into Go runtime frames.

## Decision summary

Approach #4 is the preferred technical direction because it keeps the
unmodified-binary deployment model, removes seccomp's per-call kernel
round-trip, preserves the permanent-owner correctness model, and has passed
the current routed UDP/HTTP tests. It remains an engineering prototype until
the open compatibility and endurance gates above are closed.
