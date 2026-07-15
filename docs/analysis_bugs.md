# Bug and risk ledger

Last updated: 2026-07-22.

This ledger is current for **Approach #4 / Approach D**, the Frida-Gum
fastpath. Approach #2 defects are historical and linked at the end. Seccomp
signal-notification defects belong to Approach #3 and are not current
fastpath mechanisms.

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
| O4-08 | S1 | Unsupported syscall reaches the surrogate kernel fd | Expand explicit translate/reject coverage |
| O4-09 | S1 | Descriptor alias semantics are absent | Keep `dup`/`TCPConn.File` unsupported or implement open-description lifetime |
| O4-10 | S2 | 100–1,000-goroutine sustained load saturates one owner/queue | Measure queue depth, owner utilization, and VPP worker distribution |
| O4-11 | S1 | Active teardown/reinit accesses parked/destroyed VCL state | Contract remains terminal process exit only |
| O4-12 | S1 | Raw fallback helper carries five arguments | Audit six-argument syscalls on non-owned/passthrough descriptors |

## Validation checkpoint

| Area | Topology | Result |
|---|---|---|
| TCP payload/deadlines | One VPP local cut-through | 128 payload connections and 100 deadlines passed |
| UDP connected | Two VPPs, memif, global scope | 128 × 8 × 512 B passed |
| UDP unconnected | Two VPPs, memif, global scope | 128 × 8 × 512 B passed |
| HTTP keepalive | Two VPPs, memif, global scope | 50,000/50,000 plus 12,800/12,800 passed |
| HTTP no keepalive | Two VPPs, memif, global scope | 50,000/50,000 plus 12,800/12,800 passed |
| Post-exit residue | Both routed VPPs | Zero applications/sessions after tested runs |
| Build/unit/static checks | No VPP | Build, `go test ./...`, and `go vet ./...` passed |

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
- [ ] Routed raw-TCP echo gate.
- [ ] TLS/HTTP2/gRPC matrix.
- [ ] Go-version and target-container matrix.
- [ ] Multi-hour preemption and 100–1,000-goroutine soak.
- [ ] Fault/error matrix.
- [ ] Listener/owner saturation evidence.
- [ ] Automated clean-topology regression.

## Historical mapping

- [why_frida_dropped.md](why_frida_dropped.md) explains the structural
  failures of Approach #2, Frida Interceptor/JavaScript.
- [phase1_frida.md](phase1_frida.md) preserves its defect-level audit trail.
- [architecture.md](architecture.md) and
  [architecture_diagrams.md](architecture_diagrams.md) document Approach #3,
  the seccomp backend.
- [status.md](status.md) is authoritative for current Approach #4 evidence.
