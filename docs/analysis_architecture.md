# Architecture decision record

Last updated: 2026-07-23.

This record captures the decisions behind **Approach #4**, the native
Frida-Gum fastpath implemented by this repository.

## Context

The target experience is:

```bash
LD_PRELOAD=libvclgo_gum_vcl.so ./existing-go-application
```

with no source changes, while preserving Go scheduling, netpoll, deadlines,
stack tracing, and error behavior under 100+ goroutines and multi-worker VPP.

## Decision summary

| ID | Decision | Status |
|---|---|---|
| D1 | Use `LD_PRELOAD` only as constructor delivery | Accepted |
| D2 | Patch raw syscall sites with native Frida-Gum, not Go function callbacks | Accepted |
| D3 | Convert Linux syscall ABI ↔ SysV explicitly | Accepted |
| D4 | Switch to a large pthread-local dispatcher stack | Accepted |
| D5 | Execute VLS only on permanent owner pthreads | Accepted |
| D6 | Represent sessions with real socket-pair surrogate fds | Accepted |
| D7 | Use exact registry ownership and reference-counted lifetime | Accepted |
| D8 | Keep VLS operations nonblocking and let Go netpoll wait | Accepted |
| D9 | Keep accepted children on their listener owner | Accepted |
| D10 | Support connected and unconnected UDP explicitly | Accepted/tested |
| D11 | Use one authoritative app detach at terminal exit | Accepted/tested |
| D12 | Separate cut-through diagnostics from routed acceptance | Accepted |
| D13 | Keep wildcard UDP route-source caching owner-local | Accepted/tested routed |

## D1. Preload is delivery, not libc interposition

Go normally emits raw `SYSCALL` instructions. Preloading a library is useful
because its ELF constructor runs before normal Go application work, but
overriding libc `socket` or `read` symbols is insufficient.

## D2. Native syscall-site patching

The constructor uses Frida-Gum and Capstone as C libraries to find direct
syscall sites and generic wrappers and splice them to native trampolines.

The selected mechanism must reach raw Go `SYSCALL` instructions, preserve
Go-visible return PCs and ABI behavior, and require no application source or
runtime fork. Native near-text patches satisfy those requirements.

## D3. Explicit ABI conversion

The raw syscall boundary uses Linux x86-64 register conventions; the C
dispatcher uses SysV. The shim marshals arguments deliberately, including
the fourth syscall argument's `r10` placement, and returns kernel-style
negative errno. The original Go wrapper performs its expected final
translation.

No Frida CPU-context object writes live Go registers.

## D4. Dispatcher stack switch

Native C/VCL call graphs cannot safely consume a small growable goroutine
stack because C frames do not have Go's `morestack` prologue or stack maps.
The shim switches to a 512 KiB pthread-local stack before entering C and
restores the goroutine stack only for return.

The wrapper trampoline leaves no anonymous return PC on the goroutine stack,
preserving Go unwinder/GC invariants.

## D5. Permanent VCL owners

VCL worker identity is pthread-local; goroutine identity is not. Each session
therefore records one immutable owner pthread. All raw VLS operations route
to it. Multiple owners register through VLS mode 2 with
`multi-thread-workers`.

## D6. Real readiness surrogates

Go's runtime requires a genuine epollable kernel fd. Each VCL session uses a
nonblocking socket pair for readiness only. VCL payload remains in VCL FIFOs;
the surrogate carries readiness transitions, not application data.

## D7. Exact ownership and lifetime

High-fd range membership is only an allocation policy. An exact hash registry
proves ownership. Lookups take references; close removes the entry and is a
single-winner owner operation; allocation survives outstanding synchronous
requests.

## D8. Nonblocking VLS

Owners perform one immediate VLS operation. `EAGAIN` arms owner-local VLS
epoll and returns to Go, which parks on the surrogate and enforces deadlines
with its normal timers.

## D9. Accepted sessions stay on listener owner

The tested VPP/VLS cannot migrate an accepted session after READY without
asserting. Accepted children inherit the listener owner. This is safe but can
concentrate server work, so listener sharding is an explicit future
performance decision.

## D10. UDP is a first-class path

Both `SOCK_STREAM` and `SOCK_DGRAM` INET sockets route to VCL. UDP has
explicit ephemeral-bind allocation, connected-peer state, `sendto`/
`recvfrom`, and POSIX-shaped name/error handling. Routed connected and
unconnected tests passed.

## D11. Terminal detach

Ordinary close performs `vls_close` for one session. Process exit instead:

1. quiesces owners;
2. abandons native registry/surrogate state;
3. parks nonbootstrap owners;
4. calls `vppcom_app_destroy()` once on bootstrap;
5. parks bootstrap until raw `exit_group`.

This avoids an asynchronous per-session disconnect flood racing the
authoritative application detach. Startup failure still uses explicit
close/unregister/join cleanup.

## D12. Test topology is part of correctness

Same-VPP local scope selects cut-through and bypasses the TCP/UDP packet
graph. Routed acceptance therefore uses two VPP processes, global-only VCL
configs, and memif. Results always identify which topology was used.

App-local cut-through is the intended production topology. Consequently the
routed matrix is supporting evidence, while a separate cut-through matrix
and live `[CT:*]` assertion are required promotion gates.

## D13. Wildcard UDP route sources are owner-local

VCL does not source-select `sendto` after a wildcard datagram socket is
already in LISTEN state. One temporary connected UDP probe per owner/route
discovers the source IP; an eight-entry owner-local cache shares that result
across sockets while each session retains its own bound port. This avoids
cross-thread VCL state and the high-concurrency stall caused by probing once
per socket.

## Consequences

Benefits:

- entirely in-process dispatch after the one-time constructor patch;
- no external agent or supervisory process;
- no VLS calls on Go Ms or goroutine stacks;
- ordinary Go netpoll/deadline behavior;
- shared TCP/UDP dispatcher for unmodified applications.

Costs and limitations:

- in-memory executable patching and Go-version sensitivity;
- 512 KiB dispatcher stack per source pthread that enters the fastpath;
- owner queue handoff per VCL operation;
- listener-owner concentration;
- incomplete long-tail socket ABI;
- terminal-only teardown;
- target container must permit patch installation.

## Validation implied by these decisions

Required test classes are:

1. kernel passthrough;
2. cut-through payload, deadline, UDP, and higher-protocol regression;
3. routed TCP, UDP, HTTP, TLS, HTTP/2, and gRPC supporting evidence;
4. ABI/error/negative-path checks;
5. close and terminal detach with zero VPP residue;
6. async preemption and Go stack trace safety;
7. owner and VPP worker distribution;
8. Go-version/container compatibility;
9. error and VPP-restart fault injection;
10. explicit failure for unsupported operations.

Current results and remaining gates are in [status.md](status.md) and
[plan.md](plan.md).
