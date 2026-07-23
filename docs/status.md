# Current status

Last verified: 2026-07-23.

## Readiness decision

**Not production-ready.**

The native Frida-Gum fastpath is a strong laboratory implementation for
unmodified Go applications. The complete routed two-VPP matrix now passes
IPv6 TCP/UDP, TLS/HTTP1, TLS/HTTP2, cancellation, gRPC, TCP error semantics,
and supported IPv4 UDP ICMP-error delivery at 100-way concurrency.

The intended production topology is now explicitly **same-VPP app-local VCL
cut-through**. Only the TCP smoke and TCP concurrency/deadline harnesses have
recorded cut-through passes. UDP, HTTP/1.1, TLS, HTTP/2, cancellation, and
gRPC were validated over routed memif, not cut-through, and therefore do not
close the production gate. A previously observed heavy HTTP cut-through
churn failure in this VPP branch remains open. Transactional patch handling,
pointer containment, socket compatibility, and endurance/fault/version
coverage also block production promotion.

## Verified build

| Component | Verified value |
|---|---|
| Repository branch | `main` |
| Source tested | Current `main` worktree based on `baf7d4f060fedca7eb76f453e95f088e63fda60c` |
| Go | `go1.26.1 linux/amd64` |
| Kernel | `6.8.0-100-generic` |
| VPP | `v26.10-rc0~231-g0a143dac6` |
| VCL owner pthreads | 4 per Go process |
| VPP dataplane workers | 2 per VPP instance |
| Routed link | memif, `10.77.0.1/24`/`2001:db8:77::1/64` ↔ `10.77.0.2/24`/`2001:db8:77::2/64` |

The test VPPs used isolated runtime directories, API prefixes, CLI sockets,
and application sockets. Both were stopped after validation.

## Current implementation

~~~text
LD_PRELOAD libvclgo_gum_vcl.so
  -> discover Go syscall sites and wrappers with Frida-Gum + Capstone
  -> emit near thunks and a shared ABI shim
  -> patch the main executable's in-memory .text
  -> switch to a per-OS-thread 512 KiB dispatcher stack
  -> route owned socket operations through the POSIX-shaped dispatcher
  -> execute every vls_* operation on the session's permanent owner pthread
  -> reflect VLS readiness through a real AF_UNIX socketpair
  -> let Go's normal epoll/netpoll and deadline machinery resume the goroutine
~~~

There is no runtime phase selector. Loading
`preload/fastpath/build/libvclgo_gum_vcl.so` selects this implementation.

## Implemented scope

| Capability | Implementation state | Validation state |
|---|---|---|
| Unmodified dynamic Go executable | Implemented | Current example binaries |
| `AF_INET` TCP | Implemented | Cut-through echo and routed HTTP |
| `AF_INET6` TCP | Implemented | Routed 100-connection echo and focused error probes pass |
| `AF_INET` UDP | Implemented | Routed connected and unconnected |
| `AF_INET6` UDP | Implemented | Routed connected and wildcard-unconnected 100 × 8 pass |
| Go epoll/netpoll | Real socketpair surrogate | Payload and deadline gates pass |
| Multiple VCL owners | 1–64 owners | Four owners used in every live gate |
| Multi-worker VPP/VLS | VLS mode 2 | Two workers per VPP used |
| HTTP/1.1 | TCP transport path | Routed keep-alive and fresh-connection gates pass |
| TLS | Ephemeral ECDSA test certificate; TLS 1.2 minimum | Routed IPv6 HTTP/1.1 and HTTP/2 each passed 3,200/3,200 |
| HTTP/2 | ALPN-enabled `net/http`; exact protocol assertion | Routed IPv6 3,200/3,200 plus 100/100 cancellations pass |
| gRPC | Standard health service over one multiplexed HTTP/2 connection | Routed IPv6 3,200/3,200 health RPCs pass |
| Kernel/raw fallback | All six Linux arguments forwarded | Nonzero-a5 `mmap` passes with active VCL and with `VCL_CONFIG` unset |
| Regular-file `sendfile` to VCL TCP | Translated with exact offset accounting | 131,109-byte echo parity passes |
| `close_range` | Close and `CLOEXEC`; active-VCL `UNSHARE` rejection | All three modes pass |
| Process exit | One authoritative VCL detach | Zero routed residue observed |
| Descriptor duplication | Explicitly unsupported | Returns `EOPNOTSUPP` |

## Verification results

### Build and static checks

| Check | Result | Qualification |
|---|---|---|
| `make build-fastpath` | Passed | Rebuilt dispatcher, preload, and examples |
| `go test ./...` | Passed | All packages report `[no test files]`; compile-only evidence |
| `go vet ./...` | Passed | No findings |
| `bash -n test/*.sh` | Passed | Syntax only |
| `markdownlint README.md docs/**/*.md preload/fastpath/README.md` | Passed | Current and archived Markdown |
| `git diff --check` | Passed | Whitespace check |

### Live network tests

| Test | Topology | Load | Result |
|---|---|---:|---|
| TCP smoke | One VPP, local scope, cut-through | 4 × 8 × 1024 B | 32,768 B each direction, zero errors |
| Raw syscall a5 | Active VCL and pure passthrough | `mmap`, offset one page | Correct second-page bytes in both modes |
| VCL-output `sendfile` | One VPP, local scope, cut-through | 131,109 B | Exact echo and final offset |
| `close_range` | One VPP, local scope, cut-through | `UNSHARE`, `CLOEXEC`, close | Correct reject/retain/close behavior |
| TCP payload | One VPP, local scope, cut-through | 128 × 32 × 4096 B | 16 MiB each direction, zero errors |
| TCP deadlines | One VPP, local scope, cut-through | 100 idle reads, 250 ms | All deadlines passed |
| Connected UDP | Two VPPs, global scope, memif | 128 × 8 × 512 B | 524,288 B each direction, zero errors |
| Unconnected UDP | Two VPPs, global scope, memif | 128 × 8 × 512 B | 524,288 B each direction, zero errors |
| HTTP keep-alive | Two VPPs, global scope, memif | 5 × 100 × 100 | 50,000/50,000 OK |
| HTTP no keep-alive | Two VPPs, global scope, memif | 5 × 100 × 100 | 50,000/50,000 OK |
| HTTP keep-alive, 128-way | Two VPPs, global scope, memif | 128 × 100 | 12,800/12,800 OK |
| HTTP no keep-alive, 128-way | Two VPPs, global scope, memif | 128 × 100 | 12,800/12,800 OK |

The HTTP runs used `WARMUP_REQS=0` and `-max-retries 0`. Across both
modes and both concurrency variants, 125,600 requests completed with zero
client failures.

### Completed routed IPv6 protocol/error matrix

This is routed memif evidence. It does **not** exercise VPP app-local
cut-through sessions.

| Test | Topology/load | Result |
|---|---|---|
| IPv6 TCP echo | Two VPPs, memif, 100 × 8 × 1024 B | **Pass:** 819,200 B each direction, zero errors |
| TCP half-close | IPv6 routed, `CloseWrite` → echo → EOF | **Pass** |
| TCP connection refused | IPv6 routed unused port | **Pass:** exact `ECONNREFUSED`, no timeout substitution |
| TCP connection reset | IPv6 routed; peer closes with unread 256-KiB receive data | **Pass:** exact `ECONNRESET`, no EOF substitution |
| IPv6 connected UDP | Two VPPs, 100 × 8 × 1024 B | **Pass:** 819,200 B each direction, zero errors |
| IPv6 unconnected UDP with `[::]:0` | Two VPPs, 100 × 8 × 1024 B | **Pass:** 819,200 B each direction, zero errors |
| UDP ICMP/error delivery | Connected IPv4 UDP to unused routed port | **Pass:** exact `ECONNREFUSED`, no timeout substitution |
| IPv6 UDP ICMP delivery | Connected UDP to unused IPv6 port | **Upstream VPP limitation:** this revision has no IPv6 implementation in `udp_connection_handle_icmp()` |
| TLS + HTTP/1.1 | IPv6 routed, 100 × 32 | **Pass:** 3,200/3,200; exact HTTP/1.1 assertion |
| TLS + HTTP/2 | IPv6 routed, 100 × 32 | **Pass:** 3,200/3,200; exact HTTP/2.0/ALPN assertion |
| HTTP/2 request cancellation | 100 concurrent delayed requests | **Pass:** 100/100 returned `context.Canceled` |
| gRPC health RPCs | IPv6 routed, 100 goroutines × 32 RPCs | **Pass:** 3,200/3,200 over HTTP/2 |
| Complete composed matrix | `run_protocol_matrix_fastpath.sh` | **Pass** |

The original TLS run observed 15 legitimate TCP `TIME_WAIT` entries at the
old one-second residue check. The updated HTTP harness polls for up to 30
seconds; it was rerun for HTTP/1.1, HTTP/2, and cancellation and all three
completed their residue gate successfully.

Across the harness-enforced HTTP cleanup gates and focused routed post-run
checks:

- both VPPs reported zero registered applications;
- main thread and both worker threads reported zero sessions;
- logs contained no panic, fatal error, SIGSEGV, assertion, Go unwinder
  failure, VPP message-order failure, or HTTP framing warning.

## What these results prove

- The current Go 1.26.1 binary was recognized and patched.
- Logs reported `M2:36/36` immediate sites and `wrappers:3/3`.
- Syscall arguments and results survived the current Go/Linux/SysV ABI bridge.
- Raw fallback delivered a nonzero sixth argument to Linux `%r9`.
- `sendfile` bytes/offsets and `close_range` registry/session semantics passed
  focused live regressions.
- Four permanent VCL owners registered successfully in VLS mode 2.
- 100+ goroutines can share the fixed owner pool without goroutine affinity.
- VLS readiness can drive Go netpoll and deadlines through surrogate fds.
- Routed IPv4 and IPv6 TCP/UDP plus HTTP/TLS/HTTP2/gRPC crossed the two-VPP
  memif data plane.
- Wildcard-bound unconnected IPv6 UDP selected the routed source through an
  owner-local cache and preserved per-socket source ports at 100-way load.
- Supported IPv4 VPP ICMP reset state reached Go as exact connected-UDP
  `ECONNREFUSED`.
- Tested shutdown paths left no VPP application or session residue.

They do not prove app-local cut-through behavior for UDP or higher protocols,
uniform owner or VPP-worker load distribution, unlisted socket APIs,
compatibility with another Go/VPP build, or long-duration stability.

## Production blockers

### P0 — correctness

1. **Startup accepts some partial patch sets.**
   Individual patch failures are counted, but startup continues; unresolved
   generic wrappers are skipped; there is no rollback. Production behavior
   must be fail-closed or use an explicit, tested all-kernel fallback. The
   former silent 256-site truncation is fixed: overflow now aborts before VCL
   initialization.

2. **No deterministic unit/ABI test suite exists.**
   Required coverage includes register/result conversion, negative errno,
   direct-site return PCs, wrapper prologue rejection, registry references,
   close/read races, readiness transitions, UDP sockaddr handling, and
   partial initialization. The live a5/sendfile/close-range probes are
   regression evidence, not a substitute for isolated unit/fault tests.

3. **Unsupported owned-fd syscalls may execute against the surrogate fd.**
   `sendfile` and `close_range` are now explicit, but the default path still
   cannot silently treat operations such as `splice` or an unhandled `ioctl`
   as if the kernel socketpair were the VCL transport. Every owned-fd syscall
   needs explicit translate, reject, or proven-surrogate semantics.

4. **Borrowed Go buffer pointers lack a formal runtime-safety proof.**
   The owner pthread dereferences caller buffers while the submitting Go M
   waits synchronously. The request lifetime is bounded, but this path does
   not use cgo pointer instrumentation. Demonstrate reachability and
   non-movement across GC/async preemption, or introduce an explicit
   pin/copy contract, then add forced-GC and signal stress tests.

5. **Immediate syscall sites lack a caller-saved-register proof.**
   A real Linux `SYSCALL` preserves more argument registers than a SysV C
   call is required to preserve. The generic wrapper's result block is
   understood, but every immediate-site continuation needs liveness
   validation or explicit save/restore across dispatch.

6. **Known HTTP churn can crash the intended cut-through topology.**
   Prior same-VPP app-local connection churn failed in the tested VPP
   branch's cut-through accept/cleanup path. This must be reproduced,
   isolated, and fixed before production; a routed HTTP pass cannot close it.

### P1 — scale and compatibility

1. **Invalid-pointer `EFAULT` containment is incomplete.**
   The C dispatcher/owners directly dereference non-null application buffers,
   iovecs, message headers, sockaddrs, socklen pointers, and `sendfile`
   offsets. An invalid address can SIGSEGV a dispatcher pthread instead of
   returning `EFAULT`. Add safe copy-in/copy-out or bounded fault containment.

2. **One listener is one owner bottleneck.**
   Accepted sessions inherit the listener owner. The current tests prove
   correctness at 128 connections, not balanced use of all owners. Add
   listener sharding or supported reuse-port semantics and measure queue
   depth, owner CPU, and latency.

3. **The production cut-through matrix is largely unexecuted.**
   Only app-local TCP smoke plus 128-connection payload and 100-deadline
   tests have recorded passes. Routed memif results are supporting evidence,
   not substitutes. Run app-local UDP, HTTP/1.1, TLS, HTTP/2, cancellation,
   gRPC, half-close/refused/reset, residue, and repeated churn gates while
   asserting VPP reports `[CT:*]` sessions.

4. **Compiler and executable compatibility is not qualified.**
   Run supported Go versions, PIE/non-PIE, stripped binaries, cgo and
   non-cgo builds, race builds where possible, and rejected-prologue cases.

5. **Long-tail protocol/error matrices are incomplete.**
   The routed composed matrix is green, but WebSocket, streaming/large bodies,
   slow peers, UDP truncation, multicast, ancillary/control messages, and
   IPv6 ICMP errors are absent or unsupported. The tested VPP must implement
   IPv6 UDP ICMP handling before that result can be claimed.

6. **Endurance and recovery evidence is missing.**
   Run multi-hour 100–1,000-goroutine soaks with high `GOMAXPROCS`,
   asynchronous preemption, SIGPROF, VPP restart, app-socket loss, forced
   queue pressure, allocation failures, and repeated process startup/exit.

7. **Deployment executable-memory policy is unqualified.**
   The constructor allocates RW thunk memory, changes it to RX, and asks
   Frida-Gum to patch executable `.text` through temporary writable access.
   Validate those `mmap`/`mprotect` operations in the exact container
   seccomp/AppArmor/SELinux profile, together with capabilities and shared
   memory permissions. A denying profile prevents startup; it is not a
   latent data-plane corruption mode.

### P2 — operations and security

1. **Observability is insufficient.**
    Export patch coverage, routed/raw syscall counts, owner queue depth,
    session distribution, readiness rearm, watchdog, and teardown counters.

2. **Process/API exclusions need enforcement.**
    Forked-child VCL inheritance and fd aliases (`dup`, `TCPConn.File`) are
    unsupported. They are documented and aliases fail with `EOPNOTSUPP`, but
    fork use is not proactively detected or terminated. Ordinary
    `net/http.Hijacker` does not itself require `TCPConn.File`; applications
    that explicitly request a file descriptor remain outside scope.

3. **Operational hardening and automated clean-topology CI are missing.**
    The two-VPP topology is currently assembled externally. Production
    promotion needs repeatable provisioning, residue checks, log scanning,
    artifact capture, core-dump policy, library/preload integrity controls,
    and versioned pass/fail reports.

## Promotion rule

Production-ready means all P0 items are closed, the intended workload's P1
matrix passes repeatedly, no unsupported API is used silently, and a
multi-hour deployment-representative soak completes without process crash,
VPP crash, corruption signature, data mismatch, deadline violation, leaked
application, or leaked session.

Until then, describe the project as:

> Functional Approach #4 laboratory prototype with a green routed IPv4/IPv6
> protocol matrix and limited app-local cut-through TCP evidence; not yet
> qualified for the intended cut-through production topology.

## Sources of truth

| Concern | File |
|---|---|
| Text discovery, byte emission, patching, ABI shim | `preload/fastpath/gum_vcl.c` |
| POSIX-shaped public API | `dispatcher/src/api_native.c` |
| Owner pool and all VLS operations | `dispatcher/src/pool_native.c` |
| Exact fd registry and readiness surrogate | `dispatcher/src/registry_native.c` |
| VCL application lifecycle | `dispatcher/src/lifecycle_native.c` |
| Machine-code examples | [text_patching.md](text_patching.md) |
| Test interpretation | [test_topology.md](test_topology.md) |
| Open-risk checklist | [analysis_bugs.md](analysis_bugs.md) |
