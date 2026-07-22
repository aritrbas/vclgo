# vclgo documentation

Last synchronized with the repository: 2026-07-22.

vclgo ships a single backend: **Approach #4 / Approach D**, the Frida-Gum
native fastpath in `preload/fastpath/`. Approach numbers are:

| Number | Letter | Design | Status |
|---:|:---:|---|---|
| 1 | A | vclnet source-level integration | Viable when source changes are allowed (separate repo) |
| 2 | B | Frida `Interceptor.attach` + JavaScript | Retired; code deleted (docs retained) |
| 3 | C | seccomp user notification preload | Retired; code deleted (docs retained) |
| 4 | D | Frida-Gum native syscall-site fastpath | **Only shipping backend** |

Approach #4 uses Frida-Gum as a statically linked C patching library. It does
not use the Frida agent, JavaScript, `Interceptor.attach`, seccomp, or eBPF.

## Read this first

| Document | Purpose | Authority |
|---|---|---|
| [Current status](status.md) | Exact tested evidence, limitations, and readiness statement | Current |
| [Test topology](test_topology.md) | Which tests are routed and which are VPP cut-through | Current |
| [Fastpath architecture](architecture_fastpath.md) | Byte-level syscall interception and ABI design | Current |
| [Fastpath diagram atlas](architecture_diagrams_fastpath.md) | Register, stack, memory, fd, owner, and lifecycle diagrams | Current |
| [Goroutine/pthread model](model_goroutine_pthread.md) | Mapping among goroutines, Go Ms, VCL owners, and VPP workers | Current |
| [Plan](plan.md) | Completed work and remaining gates | Current |
| [Adoption guide](adoption_guide.md) | Build, configure, validate, and roll back | Current |
| [Approach comparison](comparison_approaches.md) | Why Approach #4 was selected | Current |
| [Bug and risk ledger](analysis_bugs.md) | Fixed Approach #4 defects and remaining risks | Current |
| [Concurrency analysis](analysis_goroutine_pthread.md) | Detailed scheduling and ownership reasoning | Current |
| [Architecture decisions](analysis_architecture.md) | Current Approach #4 decisions and alternatives | Current |

## Reference and historical documents

| Document | Scope |
|---|---|
| [Seccomp architecture](architecture.md) | Approach #3 only; code deleted from tree, kept as design reference |
| [Seccomp diagrams](architecture_diagrams.md) | Approach #3 only; code deleted from tree, kept as design reference |
| [Why Frida Interceptor was dropped](why_frida_dropped.md) | Explains why Approach #2 failed and why that does not condemn Frida-Gum |
| [Phase-1 retirement audit](phase1_frida.md) | Historical defect record for Approach #2 |

## Approach #4 in one paragraph

`libvclgo_gum_vcl.so` is loaded by `LD_PRELOAD`. Its constructor uses
Frida-Gum/Capstone to find the Go executable's raw `SYSCALL` sites and
splices them to native trampolines. A shared shim converts the Linux syscall
register ABI to SysV, switches off the goroutine stack, and calls the
POSIX-shaped dispatcher. The dispatcher assigns VCL sessions to permanent
owner pthreads and represents them to Go with real socket-pair fds, preserving
Go netpoll and deadline behavior.

## Documentation policy

- [status.md](status.md) is authoritative for what has actually passed.
- [test_topology.md](test_topology.md) is authoritative for what a test pass
  proves. A local-scope same-VPP result must be called cut-through, not TCP or
  UDP dataplane validation.
- Historical failures must identify Approach #2 explicitly. “Frida failed”
  without distinguishing Interceptor from native Frida-Gum is inaccurate.
- Phase names describe project history; runtime selection is by preload
  library, not by a phase switch.
- Test claims state topology, load, result, and remaining gaps.
