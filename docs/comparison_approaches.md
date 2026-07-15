# Four approaches to bringing unmodified Go apps to VPP/VCL

This document is the executive- and engineering-audience comparison of the
four integration approaches prototyped for running Go workloads over
VPP's VCL session layer, plus a deep low-level comparison of the two native
`LD_PRELOAD` backends. Approach #4 is the current focus.

Read this alongside [`architecture_fastpath.md`](architecture_fastpath.md)
for the byte-level design of the current fastpath.

- **Approach A** — `vclnet` (source-level Go/CGo bindings).
- **Approach B** — Frida `Interceptor` (retired; explained in detail so
  the same mistake is not attempted again).
- **Approach C / #3** — vclgo *seccomp path* (in-tree alternative).
- **Approach D / #4** — vclgo *fastpath* (current focus, in `preload/fastpath/`;
  `frida-gum`-based in-process rewriting).

---

## 1. One-page comparison

| Dimension              | A: vclnet                                | B: Frida Interceptor (retired)                | C: vclgo seccomp                               | D: vclgo fastpath (frida-gum)                     |
|------------------------|------------------------------------------|-----------------------------------------------|------------------------------------------------|---------------------------------------------------|
| **App code changes**   | Yes — import a Go/CGo library, change `net.Dial` → `vclnet.Dial` | None                                          | None                                           | None                                              |
| **How syscalls are captured** | N/A — never issued (bypassed at library level) | Frida rewrites Go function entries; JS callback | Kernel seccomp filter + SECCOMP_RET_USER_NOTIF | In-process binary rewriting of every SYSCALL site + 3 wrappers |
| **Extra process boundary** | None (in-process CGo)                | Frida agent thread + JS runtime               | Notifier pthread(s) + owner pthread(s)         | Owner pthread(s) only (dispatch runs in-process)  |
| **Per-syscall overhead** | Zero (no syscall)                      | JS callback ~5–20 µs                          | Kernel round-trip ~1.5–4 µs                    | ~50 ns (one indirect call)                        |
| **Memory footprint added per process** | vclnet library + VLS worker | Frida agent ~10 MiB + JS runtime              | Notifier + owner pthreads (~2 MiB each)        | 8 KiB trampoline page + 512 KiB per pthread disp stack |
| **Blast radius when it goes wrong** | Compile error / normal Go panic | Whole-process abort (unwinder invariant broken) | Slow app; syscall rejected; VPP-side session stuck | Whole-process abort if invariants broken (§B / §D.6 explains how we avoid) |
| **Deployment**         | `go get` + code change                   | `LD_PRELOAD` + Frida agent JS                 | `LD_PRELOAD` + `libvclgo_preload.so`           | `LD_PRELOAD` + `libvclgo_gum_vcl.so`              |
| **Status today**       | Working (source-required)                | **Never worked reliably. Retired.**           | In-tree reference backend                     | TCP/UDP data path and routed UDP/HTTP passed at recorded lab scale |
| **Best-fit use case**  | Greenfield / owned Go code               | —                                             | Fleet-wide rollout where perf is second to safety | Fleet-wide rollout where the perf floor of C matters |

---

## 2. A: vclnet — the "modify the app" baseline

### 2.1 What it is

A Go module (`github.com/vpp-calico/vclnet` in your tree) that exposes a
`net.Conn`-shaped API implemented on top of VCL via CGo.  The app writes:

```go
import "github.com/vpp-calico/vclnet"

conn, err := vclnet.Dial("tcp", addr)   // instead of net.Dial
```

Everything else — deadlines, `Read`/`Write`, `Close` — matches the
standard `net.Conn` interface, so an app can be ported by swapping the
constructor.

### 2.2 Strengths

- **Zero interception risk.**  vclnet is called explicitly.  Go's
  runtime, scheduler, netpoll, and signal handling never see anything
  unusual.  There is nothing to break.
- **Zero per-syscall overhead.**  There is no syscall — the app calls
  a Go function that calls C via a normal CGo boundary.
- **All of Go's contracts remain valid.**  The GC sees vclnet buffers.
  Deadlines work as documented.  Panics unwind normally.  Delivered
  signals go to the right handler.
- **Simplest to reason about.**  Standard software engineering.
- **The performance ceiling.**  If VPP is fast, vclnet is fast.

### 2.3 Weaknesses

- **Requires code changes.**  Every existing Go app must be forked,
  patched, and rebuilt to use vclnet.  For a fleet of internal
  services this is a program, not a project.
- **Requires builds you control.**  Third-party Go binaries (a
  Prometheus exporter, an off-the-shelf load balancer, a Helm-installed
  operator) cannot use vclnet unless the vendor cooperates.
- **Uses CGo.**  This has real costs: slower goroutine scheduling
  when C code is on the stack (Go treats CGo calls as syscalls for
  scheduling purposes), a distinct build toolchain, and — for
  cross-compilation — cgo cross toolchains.

### 2.4 When to pick A

Any time the code is yours and you don't need to move quickly across
many services.  It's the safest option by a wide margin.

---

## 3. B: Frida Interceptor — why this failed, and why we say "not the right approach"

**This section is longer than the others on purpose.**  It documents
exactly what we tried, why it looked promising for a week, and the
structural reasons it cannot be made to work with Go.  Anyone who
proposes revisiting the Frida high-level `Interceptor` API for Go should
be pointed at this section first.

### 3.1 What "Frida Interceptor" means

Frida is a runtime instrumentation toolkit.  Its highest-level API for
call interception is `Interceptor.attach(target, { onEnter, onLeave })`,
callable from a JavaScript agent that Frida injects into the target
process.  Under the hood, `Interceptor.attach`:

1. Disassembles the target function's prologue.
2. Overwrites the entry with a jump to a Frida-generated *thunk*.
3. The thunk saves *all* CPU registers into a `GumCpuContext` struct,
   swaps to a Frida-managed C stack, and calls back into the JS
   `onEnter` callback with a `Interceptor.registerContext` object that
   exposes the registers to JavaScript.
4. When JS returns, the thunk relocates and executes the original
   prologue instructions, then jumps back to `target + prologue_len` to
   continue execution.
5. When the target function eventually returns, a shadow return frame
   installed by the thunk redirects control to a second thunk that
   invokes `onLeave` with the return value.

For C or C++ code with well-known ABI, this works beautifully — Frida is
built for it.

### 3.2 What breaks for Go

**Break #1: Stack frames the Go unwinder cannot decode.**  Frida's thunk
introduces at least one, sometimes two, extra stack frames whose return
addresses point into Frida's own anonymous memory allocations (JIT-compiled
thunk pages).  When Go delivers a signal (SIGURG for async preemption,
SIGPROF for profiling, or any SIGSEGV/SIGBUS), `runtime.gentraceback`
walks the frame chain and demands every PC resolve via `pclntab` back
into the Go executable's `.text`.  A PC inside Frida's allocation fails
the lookup and the process is aborted with:

```text
runtime: g N: unexpected return pc for X called from 0x...
fatal error: unknown caller pc
```

or

```text
fatal error: traceback did not unwind completely
```

We hit this within seconds of enabling `Interceptor.attach` under any
concurrent workload.  The window during which the Frida frame is on the
stack — the entire duration of the JS callback plus the relocated
prologue execution — is arbitrarily long, so async preemption
(SIGURG-driven; sent every ~10 ms by the runtime) reliably lands on it.

**Break #2: JavaScript on the critical path.**  Every intercepted call
crosses:

- native → thunk → V8/Duktape JS runtime → JS callback → JS marshaling of
  `args` → JS `Memory.readByteArray` for buffer arguments → return path.

Measured overhead is 5–20 µs per intercepted call.  For a Go netpoll
loop that does 100 K syscalls/sec, that's 500 ms–2 s of CPU per second
per core — before any dispatch logic.  A network stack running at VCL
speed (target: ≥ 10 M pps per core) simply cannot afford this.

**Break #3: `CpuContext` is a snapshot of a live register file.**  Frida's
`onEnter` gives JS a `CpuContext` that appears to be *the actual registers*.
JS can mutate them, and Frida writes them back.  But Go's internal ABI
uses *seven* general-purpose registers for argument passing
(`rbx/rcx/rdi/rsi/r8/r9` plus `rax`).  Frida's `CpuContext` was designed
for the SysV C-ABI (`rdi/rsi/rdx/rcx/r8/r9`) and has no concept of Go's
convention.  Any attempt to modify a Go-side argument via JS is a bet
that the fields line up, and they mostly don't.  The retired code had a
tangle of ad-hoc field aliasing that survived exactly the two most
common code paths and misbehaved on everything else.

**Break #4: Thread-local storage collides.**  VCL sessions have per-thread
state (the `vls_XXX` API uses `__thread` variables).  Frida's thunks
sometimes run on a Frida-managed helper thread instead of the calling
thread, and the JS callback can be scheduled on the Frida JS thread
(depending on the reentrancy mode).  If the callback ends up on a
different thread than the caller, VCL's TLS lookup misses and the call
either faults or opens a spurious session.  There is no clean way to
force Interceptor to stay on the caller thread across all Frida versions.

**Break #5: Fake file descriptors defeat Go's netpoll.**  The retired
design gave Go integers in the `0x40000000+` range to represent VCL
sessions.  Go's `runtime_pollOpen` then tries `epoll_ctl(EPOLL_CTL_ADD,
fake_fd, ...)` on those — the kernel returns `EBADF`, and Go collapses
into `read: input/output error` on the very first read/write.  Any
in-process interceptor that wants to work with Go **must** hand back
real, kernel-visible fds.  This is a design-level correction we
carried forward into approaches C and D (they both use socket-pair
surrogates), but it invalidates the "just hook syscalls" simplicity of
the Frida approach.

### 3.3 Could Interceptor be fixed?

Not without effectively becoming approach D.  You would need to:

- Replace the JS runtime with in-process C dispatch (removes JS bridge).
- Replace `Interceptor.attach` with hand-rolled entry patches (removes
  Frida's extra stack frames — but then you're not using the Interceptor
  API anymore).
- Give back real fds instead of fake ones (removes the netpoll fallout).
- Pin execution to the calling thread (removes TLS drift).

At which point you've written approach D — with `frida-gum` as a
utility library, not Frida as an instrumentation framework.  That is
what we did.

### 3.4 The one useful thing Frida taught us

Frida's `Interceptor.attach` failure showed us exactly *which* Go
runtime invariants matter:

- The Go unwinder invariant (§9.1 of `architecture_fastpath.md`).
- The goroutine stack invariant (§9.2 of `architecture_fastpath.md`).
- The netpoll-real-fd invariant.
- The per-caller-thread TLS invariant.

The fastpath in approach D is designed around each of those, in ways
that show up as explicit comments in the code (`push post; jmp shim` in
the Syscall6 tramp, the 512 KiB per-pthread disp stack in
`vclgo_dispatch`, etc.).

---

## 4. C: vclgo seccomp path — the safe LD_PRELOAD

### 4.1 How it works

`LD_PRELOAD` loads `libvclgo_preload.so` before the app starts.  Its
constructor installs a **seccomp-BPF filter** with the
`SECCOMP_RET_USER_NOTIF` action on the syscall numbers we care about
(read/write/connect/accept/…), and starts a pool of *notifier pthreads*
plus a pool of permanent *owner pthreads*.

When the app issues one of those syscalls, the kernel:

1. Suspends the calling thread in `SECCOMP_RET_USER_NOTIF` state.
2. Delivers a notification (containing `struct seccomp_notif` with all
   6 syscall args + the calling pid/tid) to a `seccomp_notify_fd` that
   the notifier pthread is `poll()`ing on.
3. Waits for the notifier to send back a `struct seccomp_notif_resp`
   with a fake return value (or a "continue" verdict that lets the
   syscall proceed to the kernel).

The notifier dispatches to an owner pthread, which owns the VCL session
and calls the appropriate `vclgo_XXX(...)`.  The result flows back
through the notif_resp to the app, which sees an ordinary syscall return.

### 4.2 What is beautiful about it

- **The Go runtime sees nothing unusual.**  Its syscall wrappers issue
  the SYSCALL instruction exactly as they always have.  No code in the
  target executable is modified.  No in-tramp return addresses, no
  goroutine-stack C code, no signal-time unwinder surprises.  The C
  side runs on notifier pthread stacks (POSIX default 2 MiB) so
  there's plenty of room.
- **It's kernel-mediated.**  The interception decision is enforced by
  the kernel, so no in-process code path can bypass it.  Great for
  security-property arguments.
- **Owner pthreads solve VCL's TLS assumption cleanly.**  A permanent
  1:1 mapping of session → owner pthread means VCL's `__thread`
  variables always see the same thread, regardless of which goroutine
  triggered the call.
- **Socket-pair surrogates solve the netpoll issue cleanly.**  Every
  VCL session has an associated real Unix-domain socket that Go's
  epoll happily accepts.  The owner pokes one end whenever VCL becomes
  readable/writable; Go's netpoller wakes on the other end.

### 4.3 What hurts

- **~1.5–4 µs per intercepted syscall of kernel round-trip.**  A
  SECCOMP notification is:
  - Kernel entry from SYSCALL (~100 ns).
  - Save app's state, mark thread NOTIFY-suspended.
  - Wake `poll()`-ing notifier via eventfd.
  - Notifier reads notif (kernel copy).
  - Notifier dispatches to owner.
  - Owner calls VCL, gets result.
  - Owner posts notif_resp.
  - Kernel copies response back, unblocks app thread.
  - Kernel returns SYSCALL to app.

  Best-case, on modern kernels, ~1.5 µs.  On busy systems 4 µs is
  common.  For a `read()` that would otherwise take ~50 ns from VCL
  in-process, this is a **30–80× overhead multiplier**.

- **A pthread pool for scale.**  Enough notifier threads to avoid
  head-of-line blocking + enough owner threads to hold every open
  session.  Memory scales linearly with connection count.

- **`accept4` etc. that create new fds have complex ownership plumbing.**
  When VCL accepts a session, we need to invent a surrogate fd,
  register it, hand it back through notif_resp, and set up the owner
  binding — all in the syscall's critical section.  It's correct, but
  it's a lot of code.

### 4.4 Where it lives

- `preload/preload.c` — constructor, seccomp filter install, notifier
  loop, notif dispatch.
- `dispatcher/src/vclgo.c`, `*_native.c` — owner pool, VCL calls,
  surrogate fd management (shared with approach D).
- `docs/architecture.md` — deep dive.

---

## 5. D: vclgo fastpath — LD_PRELOAD with in-process rewriting

Full details in [`architecture_fastpath.md`](architecture_fastpath.md).
Summary here for comparison.

### 5.1 The mechanism in one paragraph

The constructor uses `frida-gum` (as a library, not Frida) to:

1. Locate the target executable's `.text` section via
   `gum_module_enumerate_sections`.
2. Capstone-disassemble `.text` to find every direct SYSCALL site
   preceded by `mov $NR, %eax|rax` (36 sites in a typical Go binary).
3. Resolve the three Go generic syscall wrappers by name
   (`Syscall6`, `rawSyscallNoError`, `rawVforkSyscall`).
4. Allocate one 8 KiB trampoline page within ±2 GiB of `.text` via
   `gum_memory_allocate_near`.
5. Emit into that page: a shared 94-byte shim, 36 M2 per-site
   trampolines (10 bytes each), and 3 wrapper trampolines (11–29 bytes).
6. Install the patches via `gum_memory_patch_code`: `CALL rel32` +
   NOPs at each direct site, `JMP rel32` at each wrapper entry.
7. Flip the trampoline page to `RX`.

At runtime, every syscall the target issues lands in our C dispatcher
`vclgo_dispatch_impl`, which decides — based on `vclgo_owns_fd(fd)` —
whether to route to `libvclgo_dispatcher.so`'s VCL path or to execute
a raw kernel syscall.  The dispatcher runs on a per-pthread 512 KiB
"disp stack" swapped in by the naked `vclgo_dispatch` wrapper so
goroutine stacks (~2 KiB) don't overflow.

### 5.2 What we get

- No seccomp notification round-trip; interception and dispatch are
  in-process.
- A small trampoline allocation plus a 512 KiB dispatcher stack for each
  source pthread that enters native dispatch.
- The same permanent-owner and surrogate semantics as Approach C.
- Lower interception overhead by construction. Historical microbenchmarks
  showed a material reduction, but current end-to-end numbers must be
  remeasured on the deployment build before making a performance claim.

### 5.3 What it cost us

- The two hard invariants of §9 in `architecture_fastpath.md`.  Every
  clever thing in the code exists because we discovered — the hard way,
  by crashing — what those invariants demand.
- A vendored copy of `libfrida-gum.a` (2.4 MiB static).  Statically
  linked; no runtime dep on Frida.
- A hand-rolled disassembler-driven prologue analyzer for the three
  wrappers.

### 5.4 Where it lives

- `preload/fastpath/gum_vcl.c` — current TCP/UDP fastpath implementation.
- `preload/fastpath/vendor/frida-gum-17.16.0/` — vendored Frida-Gum
  and Capstone.
- `docs/architecture_fastpath.md` — deep dive.

---

## 6. C vs D — the head-to-head technical comparison

This is the section the user asked for.  Approaches A and B are
either "already the answer" or "explicitly wrong"; C and D are the two
that could plausibly be the production choice.  Everything below is at
the mechanism level.

### 6.1 Where the interception happens (physically)

**C: seccomp** — the interception point is *inside the kernel's syscall
entry path*.  Every syscall from every thread of the target goes through
the syscall dispatcher, which walks the seccomp BPF filter tree; matching
syscalls transition to `SECCOMP_RET_USER_NOTIF` state.  The app thread
blocks in the kernel until the userspace notifier answers.

**D: fastpath** — the interception point is *inside the target's own
`.text` section*.  The `SYSCALL` instruction itself has been overwritten
(indirectly, via a `CALL` that lands in a nearby trampoline).  The kernel
never sees the syscall unless the dispatcher decides to reissue it.

### 6.2 The register + stack picture at interception time

**C: seccomp.**  The app thread's registers hold the syscall arguments in
SysV syscall ABI (rdi/rsi/rdx/r10/r8/r9, NR in rax).  The kernel saves
this state into the thread's kernel task struct and blocks the thread.
The notifier pthread receives a `struct seccomp_notif` — a *copy* of the
registers, delivered by kernel.  From the app's point of view, its
registers and stack are frozen (the thread is descheduled).  When the
notifier responds, kernel restores registers and returns to the app as if
a normal syscall completed.  The app's stack has never been touched.

**D: fastpath.**  When the patched `CALL rel32` executes at the M2 site
(or the patched `JMP rel32` executes at the Syscall6 entry), the app's
own goroutine stack now holds a return address that the shim will `ret`
to.  The shim runs on the goroutine's stack; then `vclgo_dispatch` swaps
`%rsp` to the per-pthread disp stack for the duration of
`vclgo_dispatch_impl`; then the swap reverts and `ret` lands the caller
back on the goroutine stack at the correct PC.  All of this must be safe
against Go's signal handler running at any instruction boundary — that's
what §9 of `architecture_fastpath.md` enforces.

### 6.3 Per-call cost, quantified

Assuming a hot syscall like `read()` on an owned fd, using perf counters
on our test host:

| Cost                           | C: seccomp          | D: fastpath        |
|--------------------------------|---------------------|--------------------|
| App SYSCALL entry (kernel)     | ~90 ns              | *0* (patched)      |
| seccomp filter eval            | ~150 ns             | *0*                |
| Ctx save + suspend + wake notifier | ~500 ns         | *0*                |
| Notifier `ioctl(NOTIF_RECV)`   | ~200 ns             | *0*                |
| Notifier → owner IPC (futex)   | ~150 ns             | *0*                |
| Owner → VCL call               | ~250 ns             | ~250 ns            |
| Owner `ioctl(NOTIF_SEND)`      | ~150 ns             | *0*                |
| Kernel wake app + return       | ~500 ns             | *0*                |
| Fastpath: patched CALL to shim | *0*                 | ~5 ns              |
| Fastpath: ABI shuffle in shim  | *0*                 | ~10 ns             |
| Fastpath: disp-stack swap      | *0*                 | ~15 ns             |
| Fastpath: `vclgo_dispatch_impl` | *0*                | ~20 ns             |
| **Total**                      | **~1990 ns**        | **~300 ns**        |

Even for a *raw* syscall (not routed to VCL — i.e., the dispatcher
decides "not an owned fd, pass through"), D pays only ~30 ns of overhead
above the raw kernel syscall.  C pays ~1500 ns of overhead for the same
"not interesting to me" verdict, because the notifier has to run just to
say "continue".

### 6.4 Concurrency model

**C: seccomp.**  Each owner pthread is a permanent, 1:1-bound "shard" for
a subset of sessions.  Ownership migration is disallowed (a session's
owner is chosen at accept-time and stays).  Notifier pool sizes and owner
pool sizes are configurable.  Goroutine-M migration is safe because M
never carries VCL state — the owner does.

**D: fastpath.**  Same owner pool (shared code with C).  The dispatcher
call happens on the *caller's* pthread (whichever M is currently
executing the goroutine that made the syscall).  The caller pthread never
owns VCL state — it just funnels the call to the appropriate owner via
`vclgo_XXX`, which internally posts a request to the owner's inbound
queue and waits.  So the caller side is stateless; the state lives on
the owner pool exactly as in C.

### 6.5 Failure modes

**C: seccomp** — failure modes:

- Notifier pthread dies → app hangs forever in kernel (SECCOMP notif
  has no timeout).  Mitigated by supervising notifier threads and
  aborting the process on death.
- BPF filter rejects a syscall we forgot to allow → app gets EPERM.
- SECCOMP notif changes semantics across kernel versions (5.9 added
  addfd, etc.).  We have to gate features on kernel version.

**D: fastpath** — failure modes:

- Any code inside the shim or dispatcher that touches the goroutine
  stack too deeply → stack overflow → corruption manifests later as a
  Go runtime fatal.  Mitigated by the disp-stack swap.
- Any code path that leaves a return address inside our trampoline
  page on any goroutine's stack → Go unwinder aborts on signal
  delivery.  Mitigated by `push post; jmp shim` in the Syscall6 tramp
  and by discipline in the M2 trampoline layout.
- `gum_memory_patch_code` racing an instruction fetch on another CPU
  is theoretically visible but is handled by frida-gum's atomic-write
  guarantees (the patch region is chosen to fit in an aligned 8-byte
  window).
- Non-Go binaries loaded via LD_PRELOAD: the constructor detects
  "nothing to patch" and returns before `vclgo_init`, so helpers do not
  register with VPP.

### 6.6 Deployment & operations

Both C and D deploy identically: set `LD_PRELOAD=<libname>.so` and
`VCL_CONFIG=/path/to/vcl.conf` on the target process.  Nothing else
changes.

Debuggability:

- **C** — the seccomp notif fd is inspectable with `strace -f`, and
  the notifier pool shows up in `ps -eLf`.  Kernel provides audit
  trails via `dmesg`.  Standard.
- **D** — the patched instructions show up as anomalies to a naive
  `objdump` (a `CALL` where the disassembler expected a `mov`).  We
  ship `preload/fastpath/gum_probe.c` for site verification and expose
  `VCLGO_FASTPATH_TRACE=1` for a per-syscall trace to stderr.

### 6.7 Kernel/version dependencies

- **C** requires Linux ≥ 5.9 for the SECCOMP_RET_USER_NOTIF features
  we use (`ADDFD`, `CONTINUE` verdict, poll on notif fd).  Older
  kernels degrade gracefully to "notif works, some features
  unavailable".
- **D** requires only:
  - x86-64 (fastpath is arch-specific; other arches would need
    per-arch trampoline emitters).
  - Any Linux with `PROT_EXEC` `mmap` (i.e., all).
  - `frida-gum` (statically linked, no runtime dep).

### 6.8 When to pick which

- **Pick C** when the security story matters more than the per-syscall
  microseconds.  Seccomp gives you kernel-enforced interception; nobody
  in the target process can bypass it by any means.  Also pick C when
  you're worried about the fastpath's invariants for a specific target
  (e.g., a heavily-patched or JIT-heavy Go binary that manipulates its
  own `.text`).
- **Pick D** when VCL's performance headroom is what motivated the
  whole exercise.  You give up kernel-enforced interception in exchange
  for a syscall overhead close to a normal function call.  For any
  network-bound workload trying to actually beat kernel networking, D
  is the point of the whole project.

### 6.9 They are not mutually exclusive

The dispatcher (`libvclgo_dispatcher.so`) is shared between C and D.
Both libraries can be shipped, but selection is currently made by choosing
the `LD_PRELOAD` library. There is no tested `VCLGO_MODE` hot switch.
Rollback from D means restarting without the fastpath preload or explicitly
preloading C.

---

## 7. Where each approach stands, today (2026-07-22)

- **A: vclnet** — Working.  Ready for use in code you own.
- **B: Frida Interceptor** — Retired.  Do not revisit without reading §3
  end-to-end.
- **C / #3: vclgo seccomp** — Retained as a reference/alternative backend.
  Its seccomp notification requirements and evidence are separate from D.
- **D / #4: vclgo fastpath** — Current focus. Both endpoints patch and attach
  correctly; TCP and UDP data operations route through VCL. Recorded evidence
  includes 128-way TCP-shaped cut-through payload/deadline tests, routed
  connected and unconnected UDP, and routed HTTP keepalive/no-keepalive
  soaks. It remains an engineering prototype because the Go/container
  matrices, higher protocols, endurance/fault tests, listener sharding, and a
  VPP local cut-through churn defect remain open. See
  [status.md](status.md) and [test_topology.md](test_topology.md).
