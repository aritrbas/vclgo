# Current status

Last updated: 2026-07-22.

## Outcome

**Approach #4 / Approach D, the Frida-Gum fastpath, is the current focus.**
It is a native `LD_PRELOAD` solution:

```text
libvclgo_gum_vcl.so constructor
  -> Frida-Gum + Capstone discover and patch Go SYSCALL sites
  -> native ABI shim switches to a 512 KiB dispatcher stack
  -> shared POSIX-shaped dispatcher
  -> permanent VLS/VCL owner pthreads
  -> multi-worker VPP
```

It is Frida-Gum-based, not Frida-Interceptor-based, seccomp-based, or
eBPF-based. The older seccomp backend remains in-tree as Approach #3, but it
is not the focus of the evidence below.

The historical “Phase 1/Phase 2” labels are development history, not runtime
modes. Approach #4 is selected by preloading
`preload/fastpath/build/libvclgo_gum_vcl.so`; there is no phase switch.

## Implemented scope

| Capability | State | Important qualification |
|---|---|---|
| Unmodified dynamic Go binary | Implemented | No application import or custom `net.Conn` |
| Stripped Go binary | Supported by design | Patcher uses instruction/prologue scans |
| TCP/IPv4 and TCP/IPv6 | Implemented | Recorded routed HTTP evidence is IPv4 |
| UDP/IPv4 and UDP/IPv6 | Implemented | Recorded connected/unconnected evidence is IPv4 |
| `net/http` over TCP | Implemented and routed-soak tested | Keepalive on and off |
| Go epoll/netpoll | Native behavior retained | Real socket-pair surrogate fd |
| Go deadlines | Implemented | Go timers remain authoritative |
| Multiple VCL owners | Implemented | `VCLGO_WORKERS=1..64` |
| Multi-worker VPP/VLS mode 2 | Implemented | Requires `multi-thread-workers` |
| Kernel passthrough | Implemented | Used when `VCL_CONFIG` is unset |
| Accepted-session migration | Intentionally disabled | Children stay on listener owner |
| Process-exit teardown | Implemented | Single authoritative app detach |
| `dup` / `TCPConn.File` | Unsupported | Hard failure for VCL-owned fds |

## Recorded validation evidence

The following results were recorded on 2026-07-21 against the matching local
VPP build. Each VCL process used four owner pthreads and each routed VPP
instance used two dataplane workers.

| Test | Topology | Load | Result |
|---|---|---:|---|
| Build | No VPP | `make build-fastpath` | Passed |
| Go tests | No VPP | `go test ./...` | Passed |
| Go vet | No VPP | `go vet ./...` | Passed |
| TCP echo payload | One VPP, local scope, cut-through | 128 × 32 × 4096 B | 16 MiB each direction, zero errors |
| TCP read deadlines | One VPP, local scope, cut-through | 100 blocked reads, 250 ms | Passed |
| Connected UDP | Two VPPs, global scope, memif | 128 × 8 × 512 B | 524,288 B each direction, zero errors |
| Unconnected UDP | Two VPPs, global scope, memif | 128 × 8 × 512 B | 524,288 B each direction, zero errors |
| HTTP keepalive | Two VPPs, global scope, memif | 5 × 100 × 100 | 50,000/50,000 OK; zero warnings; zero residue |
| HTTP no keepalive | Two VPPs, global scope, memif | 5 × 100 × 100 | 50,000/50,000 OK; zero warnings; zero residue |
| HTTP keepalive, 128-way | Two VPPs, global scope, memif | 128 × 100 | 12,800/12,800 OK |
| HTTP no keepalive, 128-way | Two VPPs, global scope, memif | 128 × 100 | 12,800/12,800 OK |

The routed HTTP runs used `WARMUP_REQS=0` and no client retries. VPP
application/session residue was checked on both instances after shutdown.

These results show that the current code works at the tested scale. They do
not establish production readiness across other VPP revisions, Go versions,
kernels, containers, or multi-hour workloads.

## What the two topologies prove

One VPP with `app-scope-local` selects VPP's local cut-through transport.
It is useful for regression testing the interceptor, owner handoff, VLS local
sessions, surrogate readiness, deadlines, and concurrency. It does not send
TCP segments or UDP packets through VPP's packet graph.

The TCP/UDP acceptance topology is two isolated VPP processes connected by
memif, with global-only VCL configurations. The server binds
`10.77.0.1`; the client uses `10.77.0.2`. This forces traffic through the
routed VPP transport/data plane.

See [test_topology.md](test_topology.md) for the diagrams, configuration
matrix, commands, and per-harness interpretation.

## Defects fixed in the current Approach #4 code

| Area | Prior defect | Current resolution |
|---|---|---|
| UDP bind | VCL treated literal port 0 incorrectly for this path | Owner allocates an ephemeral port in 32768–60999 with bounded collision retries |
| Connected UDP | Nonblocking `vls_connect` did not establish the expected peer state | Owner temporarily clears nonblocking, connects, restores flags, and caches the peer |
| UDP send/name | Connected `write`/null-destination `sendto` and `getpeername` diverged | Cached peer supplies POSIX-shaped semantics |
| Process exit | Per-session disconnects immediately before app detach flooded/raced cut-through cleanup | Exit abandons dispatcher/surrogate records and performs one bootstrap-owned `vppcom_app_destroy()` |
| Exit concurrency | Other threads could race VCL destruction | Owners quiesce; nonbootstrap and bootstrap owner threads park until raw `exit_group` |
| Go stack | Deep native calls could overflow a small goroutine stack | Shim switches to a per-pthread 512 KiB dispatcher stack |
| Go ABI | Foreign callbacks/register rewrites corrupted Go state | Native shim has explicit Linux-syscall/SysV conversion; original Go wrapper finishes normally |
| VCL TLS | Goroutines migrate between runtime threads | Raw VLS handles stay on permanent owner pthreads |
| Go netpoll | Synthetic fds could not be epoll targets | Every VCL session has a real socket-pair surrogate |

Normal application `close(2)` still closes the individual VLS session. The
detach-only behavior applies only to terminal process teardown.

## Known limitations and open risks

- One listener belongs to one owner, so all accepted sessions from that
  listener remain concentrated on that owner. Outbound sockets and separate
  listeners are round-robin distributed.
- The number of VCL owners and the number of VPP dataplane workers are
  independent. A four-owner application connected to a two-worker VPP does
  not imply a fixed owner-to-worker mapping.
- Heavy same-VPP, local-scope HTTP connection churn can crash the tested VPP
  branch in cut-through cleanup/accept handling
  (`ct_session_close`, `ct_accept_rpc_wrk_handler`, or out-of-order
  `svm_msg_q` messages). Simple cut-through echo/deadline tests pass. Routed
  HTTP does not reproduce the crash.
- TLS, HTTP/2, gRPC, half-close/reset/refused-connect matrices, signal storms,
  VPP restart, and multi-hour 100–1,000-goroutine soaks remain to be run.
- The fastpath skips and logs an unrecognized wrapper prologue; a Go-version
  matrix is still needed to validate that degradation path.
- The target container's executable-memory/`mprotect` policy has not been
  validated.
- Static and privileged executables, forked-child VCL inheritance, descriptor
  duplication, and active teardown/reinit are unsupported.
- This is a focused socket compatibility layer, not a complete emulation of
  every Linux socket extension.

## Is Approach #4 the best solution?

It is the best current candidate in this repository for the stated goal:
unmodified Go applications, `LD_PRELOAD`, low interception overhead,
100+ goroutines, and multi-worker VPP/VCL. It avoids the retired
Frida-Interceptor ABI/stack failure and the seccomp per-syscall kernel
round-trip.

That conclusion is architectural and evidence-based, not final. Production
promotion still depends on the open validation items above. If application
source can be changed, a source-level VCL integration such as vclnet remains
simpler and easier to support.

## Source of truth

| Concern | File |
|---|---|
| Rewriter, ABI shim, syscall routing | `preload/fastpath/gum_vcl.c` |
| Owner workers and VLS session operations | `dispatcher/src/pool_native.c` |
| POSIX-shaped public API | `dispatcher/src/api_native.c` |
| Exact fd registry and surrogate readiness | `dispatcher/src/registry_native.c` |
| Lifecycle | `dispatcher/src/lifecycle_native.c` |
| Routed UDP harness | `test/run_smoke_udp_fastpath.sh` |
| Routed HTTP harness | `test/run_http_soak_fastpath.sh` |
| Cut-through TCP harnesses | `test/run_smoke_fastpath.sh`, `test/run_concurrency_fastpath.sh` |
| Test interpretation | [test_topology.md](test_topology.md) |
