# Current status

Last verified: 2026-07-22.

## Readiness decision

**Not production-ready.**

The native Frida-Gum fastpath is a strong laboratory implementation for
unmodified Go applications using routed IPv4 TCP, UDP, and HTTP/1.1 at
100–128-way concurrency. The complete repository matrix passes on the
current `main` branch, but correctness gaps in raw syscall fallback and
partial-patch handling, incomplete socket compatibility, and missing
endurance/fault/version coverage block production promotion.

## Verified build

| Component | Verified value |
|---|---|
| Repository branch | `main` |
| Repository commit tested | `d0cbd78c394db54cfae9a586058d3bc420320e58` |
| Go | `go1.26.1 linux/amd64` |
| Kernel | `6.8.0-100-generic` |
| VPP | `v26.10-rc0~231-g0a143dac6` |
| VCL owner pthreads | 4 per Go process |
| VPP dataplane workers | 2 per VPP instance |
| Routed link | memif, `10.77.0.1/24` ↔ `10.77.0.2/24` |

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
| `AF_INET6` TCP | Code path implemented | Routed acceptance missing |
| `AF_INET` UDP | Implemented | Routed connected and unconnected |
| `AF_INET6` UDP | Code path implemented | Routed acceptance missing |
| Go epoll/netpoll | Real socketpair surrogate | Payload and deadline gates pass |
| Multiple VCL owners | 1–64 owners | Four owners used in every live gate |
| Multi-worker VPP/VLS | VLS mode 2 | Two workers per VPP used |
| HTTP/1.1 | TCP transport path | Routed keep-alive and fresh-connection gates pass |
| Kernel passthrough | Intended when `VCL_CONFIG` is unset | Six-argument fallback defect remains |
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
| `git diff --check` | Passed before documentation edits | Whitespace check |

### Live network tests

| Test | Topology | Load | Result |
|---|---|---:|---|
| TCP smoke | One VPP, local scope, cut-through | 4 × 8 × 1024 B | 32,768 B each direction, zero errors |
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

After the routed matrix:

- both VPPs reported zero registered applications;
- main thread and both worker threads reported zero sessions;
- logs contained no panic, fatal error, SIGSEGV, assertion, Go unwinder
  failure, VPP message-order failure, or HTTP framing warning.

## What these results prove

- The current Go 1.26.1 binary was recognized and patched.
- Logs reported `M2:36/36` immediate sites and `wrappers:3/3`.
- Syscall arguments and results survived the current Go/Linux/SysV ABI bridge.
- Four permanent VCL owners registered successfully in VLS mode 2.
- 100+ goroutines can share the fixed owner pool without goroutine affinity.
- VLS readiness can drive Go netpoll and deadlines through surrogate fds.
- Routed IPv4 UDP and HTTP/TCP crossed the two-VPP memif data plane.
- Tested shutdown paths left no VPP application or session residue.

They do not prove uniform owner or VPP-worker load distribution, IPv6,
unlisted socket APIs, compatibility with another Go/VPP build, or
long-duration stability.

## Production blockers

### P0 — correctness

1. **Raw fallback carries only five syscall arguments.**
   The shim delivers a0–a5 to `vclgo_dispatch_impl`, but
   `raw_syscall5` does not explicitly load a5 into Linux `%r9`.
   A patched six-argument syscall such as `mmap` can therefore receive an
   incorrect final argument on the raw path. Replace it with a true
   six-argument helper and add nonzero-a5 tests for every fallback branch.

2. **Startup accepts partial patch sets.**
   Individual patch failures are counted, but startup continues; unresolved
   generic wrappers are skipped; there is no rollback. Production behavior
   must be fail-closed or use an explicit, tested all-kernel fallback.

3. **No deterministic unit/ABI test suite exists.**
   Required coverage includes register/result conversion, negative errno,
   six-argument syscalls, direct-site return PCs, wrapper prologue rejection,
   registry references, close/read races, readiness transitions, UDP
   sockaddr handling, and partial initialization.

4. **Unsupported owned-fd syscalls may execute against the surrogate fd.**
   The default path cannot silently treat operations such as `sendfile`,
   `splice`, or an unhandled `ioctl` as if the kernel socketpair were the
   VCL transport. Every owned-fd syscall needs explicit translate, reject, or
   proven-surrogate semantics.

5. **Borrowed Go buffer pointers lack a formal runtime-safety proof.**
   The owner pthread dereferences caller buffers while the submitting Go M
   waits synchronously. The request lifetime is bounded, but this path does
   not use cgo pointer instrumentation. Demonstrate reachability and
   non-movement across GC/async preemption, or introduce an explicit
   pin/copy contract, then add forced-GC and signal stress tests.

6. **Immediate syscall sites lack a caller-saved-register proof.**
   A real Linux `SYSCALL` preserves more argument registers than a SysV C
   call is required to preserve. The generic wrapper's result block is
   understood, but every immediate-site continuation needs liveness
   validation or explicit save/restore across dispatch.

### P1 — scale and compatibility

1. **One listener is one owner bottleneck.**
   Accepted sessions inherit the listener owner. The current tests prove
   correctness at 128 connections, not balanced use of all owners. Add
   listener sharding or supported reuse-port semantics and measure queue
   depth, owner CPU, and latency.

2. **Same-VPP HTTP cut-through churn remains unsafe on the tested VPP.**
   High connection churn can fail in VPP cut-through accept/cleanup code.
   Routed HTTP is healthy, but local cut-through cannot be promoted until the
   VPP failure is isolated and fixed or local scope is explicitly excluded.

3. **Compiler and executable compatibility is not qualified.**
   Run supported Go versions, PIE/non-PIE, stripped binaries, cgo and
   non-cgo builds, race builds where possible, and rejected-prologue cases.

4. **Protocol/error matrices are incomplete.**
   Add routed raw TCP, IPv6 TCP/UDP, TLS, HTTP/2, gRPC, WebSocket, streaming
   bodies, connection refused/reset, half-close, cancellation, ICMP/error
   delivery, UDP truncation, and ancillary/control-message tests.

5. **Endurance and recovery evidence is missing.**
   Run multi-hour 100–1,000-goroutine soaks with high `GOMAXPROCS`,
   asynchronous preemption, SIGPROF, VPP restart, app-socket loss, forced
   queue pressure, allocation failures, and repeated process startup/exit.

### P2 — operations and security

1. **Observability is insufficient.**
    Export patch coverage, routed/raw syscall counts, owner queue depth,
    session distribution, readiness rearm, watchdog, and teardown counters.

2. **Deployment policy is unqualified.**
    Validate the exact container image, executable-memory and
    `mprotect` policy, LSM profile, capabilities, core-dump handling,
    library integrity, and preload supply chain.

3. **Automated clean-topology CI is missing.**
    The two-VPP topology is currently assembled externally. Production
    promotion needs repeatable provisioning, residue checks, log scanning,
    artifact capture, and versioned pass/fail reports.

## Promotion rule

Production-ready means all P0 items are closed, the intended workload's P1
matrix passes repeatedly, no unsupported API is used silently, and a
multi-hour deployment-representative soak completes without process crash,
VPP crash, corruption signature, data mismatch, deadline violation, leaked
application, or leaked session.

Until then, describe the project as:

> Functional Approach #4 laboratory prototype with routed IPv4
> TCP/UDP/HTTP evidence at 100–128-way concurrency.

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
