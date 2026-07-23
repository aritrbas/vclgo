# Bug and risk ledger

Last updated: 2026-07-22.

This ledger is current for the **Approach #4 Frida-Gum fastpath**.

## Resolved Approach #4 defects

| ID | Severity | Defect | Resolution and evidence |
|---|---|---|---|
| F4-01 | S0 | Fastpath server child could lose `LD_PRELOAD` across the harness subshell | Exported all preload/config inputs and require `vclgo_init ... passthrough=0` in server logs |
| F4-02 | S0 | Non-Go helpers could initialize VCL before execing the Go target | Constructor classifies the target before VCL init; `timeout` and shell helpers no longer register |
| F4-03 | S0 | Native dispatch exhausted a small goroutine stack | Naked shim switches to a per-pthread 512 KiB stack before C/VCL work |
| F4-04 | S0 | A trampoline return PC could be visible to Go's unwinder | Generic-wrapper path uses `push post; jmp shim`; no anonymous trampoline PC remains on the goroutine stack |
| F4-05 | S0 | VLS state could follow a goroutine across Go Ms | Every raw VLS handle is permanently owned by one registered pthread |
| F4-06 | S0 | Fake fd could not participate in Go epoll/netpoll | Real nonblocking socket-pair surrogate represents each VCL session |
| F4-07 | S1 | Accepted READY sessions were migrated and asserted in VPP | Accepted child inherits listener owner |
| F4-08 | S1 | VCL UDP bind with port 0 did not produce usable ephemeral binding | Owner allocates 32768–60999 with PID-seeded atomic selection and bounded `EADDRINUSE` retries |
| F4-09 | S1 | Connected UDP under nonblocking VLS did not establish/cache peer semantics | Owner temporarily clears nonblocking for `vls_connect`, restores it, and caches peer |
| F4-10 | S1 | Connected `write`, null-destination `sendto`, and `getpeername` disagreed | All use the cached connected peer with POSIX-shaped errors |
| F4-11 | S0 | Exit closed every live VLS session immediately before application detach, racing/flooding cut-through cleanup | Terminal exit abandons native records/surrogates and performs one bootstrap-owned app detach |
| F4-12 | S0 | Owner TLS destructors could run after VCL process state was destroyed | All detach-only owners park until raw `exit_group` |
| F4-13 | S1 | Same-VPP tests were described as TCP/UDP dataplane tests | Topology contract now separates local cut-through from two-VPP routed acceptance |
| F4-14 | S0 | Raw fallback accepted a5 but did not bind it to Linux `%r9` | Replaced `raw_syscall5` with `raw_syscall6`; nonzero-offset `mmap` passes with active VCL and in pure passthrough mode |
| F4-15 | S1 | `close_range` could close surrogates without closing registry/VLS sessions | Range dispatch closes exact owners first, preserves sessions for `CLOEXEC`, and rejects `UNSHARE` while VCL is active; live regression passes |
| F4-16 | S1 | `sendfile` on a VCL-owned output fell through to the surrogate | Added regular-kernel-file-to-VCL translation with exact partial-write offset accounting; 131,109-byte echo parity passes |
| F4-17 | S1 | More than 256 immediate sites were silently mixed into the generic skipped count | Separate `non-immediate`/`overflow` counters; any overflow refuses all patching before VCL initialization |
| F4-18 | S2 | Syscall6 trampoline bytes were dumped on every startup | Dump is now gated by `VCLGO_FASTPATH_TRACE` |

## Audit of the reported bug list

| Reported item | Verdict for current `main` | Evidence / action |
|---|---|---|
| `recvfrom` drops a5 | **Not a bug; report was stale** | The shim spills `%r9`, pushes a5 as SysV argument 7, the stack-switch stub forwards it, and `vclgo_recvfrom` receives `(socklen_t *)a5`. The routed unconnected-UDP client also verifies the returned peer address at 128-way concurrency. |
| `close_range` is unhandled | **Confirmed and fixed** | It was absent from the fastpath and could strand an exact registry/VLS owner after the kernel closed its surrogate. See F4-15. |
| `sendfile` is unhandled | **Confirmed and fixed** | It was absent. A raw call was not guaranteed to return `EBADF`; it could operate on the AF_UNIX surrogate, which is worse. See F4-16. |
| Syscall6 `jmp rel32` is off by one | **Not a runtime bug** | The old expression used the opcode address plus five and was mathematically correct. It was rewritten around an explicit `jmp_at` pointer to remove the maintenance ambiguity. |
| 256-site cap silently truncates | **Confirmed and fixed fail-closed** | Capacity overflow is now distinct from a non-immediate pattern and aborts before VCL initialization. The finite compatibility limit remains documented. |
| Teardown runs twice unsafely | **Not a bug** | `vclgo_teardown` is idempotent: one caller wins `ACTIVE -> STOPPING`; all others wait for or observe `STOPPED`. Also, raw `exit_group` does not run ELF destructors. |

## Audit of the reported production gaps

| Reported gap | Verdict |
|---|---|
| Data plane / G-D1 through G-D6 never passed | **Stale.** Both endpoints receive `LD_PRELOAD`; cut-through TCP payload/deadlines and routed two-VPP UDP/HTTP gates passed at the loads in [status.md](status.md). |
| Container executable-memory policy | **Valid and open (O4-04).** RW allocation, RW→RX `mprotect`, and controlled `.text` patching must be allowed by the target seccomp/LSM profile. |
| Launcher cannot discover the fastpath library | **Not applicable.** Current Approach #4 uses direct `LD_PRELOAD`; there is no shipping launcher or `discover.go`. |
| Invalid-pointer `EFAULT` containment | **Valid and open (O4-18).** Selected null checks do not contain arbitrary invalid non-null addresses. |
| Unconditional trampoline dump | **Confirmed and fixed (F4-18).** |
| Fork/exec inheritance | **Valid scope gap (O4-19).** Forked-child VCL state is unsupported and not proactively enforced. `exec` itself reruns the preload constructor. |
| `dup` / `TCPConn.File` | **Valid explicit exclusion (O4-09).** These return `EOPNOTSUPP`. The claim that ordinary `net/http.Hijacker` inherently calls `File` is false; only application code that explicitly requests an OS file descriptor hits this boundary. |

## Current open risks

| ID | Severity | Risk | Current position |
|---|---|---|---|
| O4-01 | S0 | Heavy same-VPP HTTP connection churn crashes tested VPP cut-through code | Open in VPP; routed HTTP is the Approach #4 TCP gate |
| O4-02 | S1 | One listener concentrates accepted sessions on one VCL owner | Correct but may bottleneck; test multiple listeners if required |
| O4-03 | S1 | Go compiler changes produce an unrecognized wrapper prologue | Skip/log behavior exists; validate it with a Go-version matrix |
| O4-04 | S1 | Target container denies executable mapping/text patching | Validate exact LSM/seccomp/container profile |
| O4-05 | S1 | Long-duration preemption exposes unwinder/stack regression | Run multi-hour `SIGPROF`/high-`GOMAXPROCS` soak |
| O4-06 | S1 | TLS/HTTP2/gRPC differs from tested HTTP/1 path | Dedicated protocol soaks remain open |
| O4-07 | S1 | Reset/refused/half-close/VPP-restart semantics are incomplete | Add fault and error matrix |
| O4-08 | S1 | Remaining unsupported syscall reaches the surrogate kernel fd | `sendfile`/`close_range` are explicit; classify or reject `splice`, uncommon `ioctl`, OOB/control operations, and the rest |
| O4-09 | S1 | Descriptor alias semantics are absent | Keep `dup`/`TCPConn.File` unsupported or implement open-description lifetime |
| O4-10 | S2 | 100–1,000-goroutine sustained load saturates one owner/queue | Measure queue depth, owner utilization, and VPP worker distribution |
| O4-11 | S1 | Active teardown/reinit accesses parked/destroyed VCL state | Contract remains terminal process exit only |
| O4-13 | S0 | Constructor can continue after a required wrapper/site is skipped or a patch write fails | Production blocker: preflight the complete patch set, install atomically or roll back, and fail closed |
| O4-14 | S1 | Startup failure after VCL initialization may precede `g_did_patch` and miss normal destructor cleanup | Exercise every constructor failure edge and make cleanup state-driven |
| O4-15 | S1 | `go test ./...` has no Go test files | Add unit tests for classification, result mapping, registry lifetime, sockaddr conversion, and failure injection |
| O4-16 | S0 | Owner pthread dereferences a borrowed Go buffer while the source M waits outside ordinary cgo instrumentation | Prove GC reachability/non-movement or add a pin/copy contract; force GC and async preemption during I/O |
| O4-17 | S0 | Immediate-site dispatch may clobber SysV caller-saved registers that a real Linux syscall would preserve | Prove continuation liveness for every supported Go build or explicitly save/restore the required registers |
| O4-18 | S1 | Arbitrary invalid user pointer can fault a dispatcher/owner pthread instead of returning `EFAULT` | Add safe copy-in/copy-out or bounded fault containment and negative-pointer tests |
| O4-19 | S2 | A forked child inherits process-wide VCL records/surrogates without a supported ownership contract | Detect/reject fork use or implement and test an at-fork child reset contract |

## Validation checkpoint

| Area | Topology | Result |
|---|---|---|
| TCP payload/deadlines | One VPP local cut-through | 128 payload connections and 100 deadlines passed |
| Raw a5 / `sendfile` / `close_range` | One VPP local cut-through | Nonzero-offset `mmap`, exact 131,109-byte echo, and all range modes passed |
| UDP connected | Two VPPs, memif, global scope | 128 × 8 × 512 B passed |
| UDP unconnected | Two VPPs, memif, global scope | 128 × 8 × 512 B passed |
| HTTP keepalive | Two VPPs, memif, global scope | 50,000/50,000 plus 12,800/12,800 passed |
| HTTP no keepalive | Two VPPs, memif, global scope | 50,000/50,000 plus 12,800/12,800 passed |
| Post-exit residue | Both routed VPPs | Zero applications/sessions after tested runs |
| Build/static checks | No VPP | Build, `go test ./...`, and `go vet ./...` passed; Go reported every package as `[no test files]` |

For the exact meaning of each topology, see
[test_topology.md](test_topology.md).

## Cut-through failure record

The tested VPP branch can fail under rapid same-VPP local HTTP connection
churn with signatures including:

- `svm_msg_q_free_msg: message out of order`;
- a null/stale transport in `ct_accept_rpc_wrk_handler`;
- a failure in `ct_session_close`.

Simple local cut-through TCP payload and deadline tests pass. The failure is
not evidence of register, Go stack, or heap corruption in the fastpath, and
routed HTTP does not reproduce it. It remains an open VPP cut-through defect
until isolated and fixed there.

## Memory-corruption stop conditions

Stop testing and preserve the core if any of these occurs:

- `unexpected return pc`;
- `traceback did not unwind completely`;
- an instruction pointer in a trampoline mapping during Go traceback;
- a raw VLS call on a Go runtime M instead of an owner;
- a use-after-free in a session or request;
- a VCL TLS destructor running after application detach.

Collect the binary build ID, Go version, VPP/VCL revision, preload hash,
`VCLGO_LOG=3` trace ring, complete core/backtrace, and both VPP
application/session dumps.

## Promotion checklist

- [x] Frida-Gum fastpath at both endpoints.
- [x] 100+ concurrent TCP-shaped sessions.
- [x] Routed connected and unconnected UDP.
- [x] Routed HTTP keepalive and fresh-connection modes.
- [x] Multi-owner VCL and multi-worker VPP configuration.
- [x] Zero VPP residue after recorded routed runs.
- [x] Correct raw-kernel forwarding of syscall argument 6, with nonzero-a5 regression.
- [ ] Atomic all-or-nothing installation of required patches.
- [ ] Actual unit tests (current Go packages contain none).
- [ ] Formal and stress-tested Go-buffer lifetime/pinning contract.
- [ ] Invalid-pointer containment with kernel-shaped `EFAULT` results.
- [ ] Routed raw-TCP echo gate.
- [ ] TLS/HTTP2/gRPC matrix.
- [ ] Go-version and target-container matrix.
- [ ] Multi-hour preemption and 100–1,000-goroutine soak.
- [ ] Fault/error matrix.
- [ ] Listener/owner saturation evidence.
- [ ] Automated clean-topology regression.

The authoritative release view is [status.md](status.md).
