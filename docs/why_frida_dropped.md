# Why Frida Interceptor was dropped

**Audience:** engineers and reviewers who ask *"can't we just use Frida?"* This
doc is designed to be shared standalone. It uses concrete failure examples,
memory-layout diagrams, and objdump-style output rather than a wall of prose.

**One-line answer:** because Frida's `Interceptor.attach` treats a Go binary
as if it were a C binary, and Go's runtime is not a C runtime. Every one of
its correctness contracts — the register ABI, the goroutine stack, the
M-to-G scheduler, the netpoll fd-space, the GC stack-map walker — is broken
by the mechanism, not by any specific hook.

The rest of this document walks through each break with a diagram and a
reproducible failure signature.  If you're the person asking "which one
single thing broke?" — none of them were fixable in isolation, which is
exactly the point.

This title refers only to Approach #2, the high-level Interceptor/JavaScript
design. Approach #4 deliberately uses the lower-level Frida-Gum C library and
is the current implementation focus.

For the retirement audit trail with individual defect IDs, see
[`phase1_frida.md`](phase1_frida.md).  For the currently-supported
alternative that gives us the same "no source changes" property, see
[`architecture_fastpath.md`](architecture_fastpath.md).

---

## 0. Terminology reset — three things called "Frida"

Before anything else: there are three distinct products that share the name
"Frida".  Confusing them is why "let's try Frida" reappears in planning
meetings.

| Layer | Name | What it is | Do we use it? |
|-------|------|-----------|----------------|
| 1 | **Frida CLI / `frida-tools`** | The `frida`, `frida-trace`, `frida-ps` command-line tools. Spawn/attach processes, load JS agents. | **No.** Discussed and rejected. |
| 2 | **Frida `Interceptor.attach`** | High-level JavaScript API from a loaded agent: `Interceptor.attach(addr, { onEnter, onLeave })`. Puts a JS callback on function entry/exit. | **No.  This is what this document is about.** |
| 3 | **`frida-gum`** | The underlying C library. Bundles Capstone. Provides memory allocation near a target, atomic RX-page splicing, module/symbol iteration. | **Yes** — as a library, not as a framework. See [`architecture_fastpath.md`](architecture_fastpath.md). |

When this document says "Frida", it means #2: `Interceptor.attach`.

---

## 1. What Frida `Interceptor.attach` actually does

Given a Go binary and an agent script like:

```javascript
Interceptor.attach(Module.findExportByName(null, 'syscall.Syscall6'), {
  onEnter: function (args) {
    // args[0]..args[5] look like registers
    // do stuff
  },
  onLeave: function (retval) {
    // retval looks like the return value
  }
});
```

Frida performs the following at attach time:

1. Disassembles the first N bytes of the target function's prologue
   (usually 5-14 bytes, whatever is needed to fit a 5-byte JMP).
2. Overwrites those bytes with `JMP rel32 <frida_thunk>`.
3. Allocates an executable page for its **thunk**.  The thunk:
   - saves the entire CPU register file into a `GumCpuContext` struct;
   - swaps to a Frida-managed C stack;
   - executes JS `onEnter` via V8/Duktape;
   - copies-and-executes the relocated prologue bytes;
   - patches a "shadow return frame" onto the caller's stack so it can
     intercept `onLeave` later;
   - `JMP`s to `target + prologue_len` to continue execution.
4. On the eventual `RET` from the target function, the shadow return frame
   diverts control back to the thunk, which calls `onLeave` and then
   actually returns to the real caller.

Visually, before and after attach:

```text
    BEFORE attach                              AFTER attach

    Syscall6:                                  Syscall6:
      49 89 f2   mov %rsi,%r10                   e9 XX XX XX XX  jmp thunk
      48 89 fa   mov %rdi,%rdx                   90 90 90 90 90  (padding)
      48 89 ce   mov %rcx,%rsi                   ...             ; body untouched
      48 89 df   mov %rbx,%rdi                   0f 05           syscall
      0f 05      syscall                         48 3d 01 f0 ff ff
      48 3d ...  cmp $-4095,%rax                 76 15           jbe ...
      ...                                        ...
                                                 c3              ret

                                              thunk (in anonymous mmap page):
                                                push all regs                     |
                                                mov %rsp -> frida_stack           |
                                                mov  <ctx>, %rdi                  |  Frida's foreign
                                                call frida_call_JS_onEnter        |  frame — NOT
                                                <execute copied prologue bytes>   |  visible to Go
                                                <install shadow-return trampoline>|  unwinder/GC
                                                jmp Syscall6 + prologue_len       |
```

The two problems are already visible in the diagram, but they take three
distinct forms in practice.  Sections 2–5 walk each one.

---

## 2. Problem #1 — The Go unwinder invariant is violated

**Rule:** during signal handling, `runtime.gentraceback` walks the stack and
demands every PC resolves via the Go `pclntab` back into the target
executable's `.text`.  A PC in *any other* mapping is fatal.

**Frida's thunk breaks this** because throughout the entire duration of the
hook — the JS callback, the register save/restore, the copied prologue
execution — the top of the stack contains return addresses pointing into
**Frida's own anonymous mmap page**, not into Go's `.text`.

### 2.1 What the stack looks like during a hook

```text
STACK during Frida onEnter (grows down)

+--------------------------------------------------+  <- caller's rsp before Syscall6
| return-address-into-Go-code (valid Go PC)        |
+--------------------------------------------------+
| Frida shadow-return trampoline PC (Frida page)   |  <-- BAD: not a Go PC
+--------------------------------------------------+
| Frida saved regs (GumCpuContext)                 |
| ...                                              |
| Frida internal call frames (V8, JIT)             |
| ...                                              |
+--------------------------------------------------+  <- current rsp
```

Everything above `caller's rsp` is a *Go* stack.  Everything below the
"Frida shadow-return trampoline PC" entry is Frida's world.  The Go
unwinder walks upward from `rsp` following `%rbp` chains (or DWARF FDEs
if built with `-gcflags="-N -l"`).  It encounters the Frida-page PC.
Lookup in `pclntab` fails.

### 2.2 What that failure looks like

Standard signal-time abort:

```text
runtime: g 1: unexpected return pc for runtime.sigpanic called from 0x9300000000
stack: frame={sp:0x692b2319cc8, fp:0x692b2319d28} stack=[0x692b2319000,0x692b231a000)
fatal error: fault
[signal SIGSEGV: segmentation violation code=0x1 addr=0x9300000000 pc=0x9300000000]
```

The `pc == addr == 0x9300000000` pattern is the giveaway: Go tried to
*execute* at an address it should never have jumped to.  In our case the
address was well outside the Go `.text` (which ends around `0x600000` in
this binary) — it was in Frida's JIT page.

### 2.3 When does this fire?

Any of the following will do it — and Go emits them constantly:

- **SIGURG** — Go 1.14+ uses SIGURG for async preemption.  Sent every
  ~10 ms per running goroutine.
- **SIGPROF** — profiling.  Sent at 100 Hz by default when `pprof.StartCPUProfile`
  is active.
- **SIGSEGV** — a nested fault from within any C code the JS callback
  invokes (e.g., a VLS call that mishandles a bad fd).

The window during which the Frida frame is live equals the entire
duration of the hook plus the copied prologue.  For a hook that calls
into VLS + VPP (which is exactly what we want to do), that window is
milliseconds.  SIGURG lands there reliably.

### 2.4 Can we fix it?

Options considered and why each fails:

- **"Disable async preemption"** (`GODEBUG=asyncpreemptoff=1`) — masks the
  common trigger but doesn't fix SIGPROF, SIGSEGV, or user-installed
  signals.  Also, disabling preemption regresses every Go feature that
  relies on it.
- **"Register the Frida page with pclntab"** — Go's `pclntab` is
  read-only after the linker generates it.  There is no runtime API to
  add entries.
- **"Skip the shadow return frame; return synchronously"** — this is
  what our fastpath does (approach D), but it requires abandoning
  Interceptor's `onLeave` entirely — at which point you're not using
  Interceptor anymore.

---

## 3. Problem #2 — Register ABI mismatch corrupts Go state

Frida's `GumCpuContext` was designed for SysV C-ABI (`rdi/rsi/rdx/rcx/r8/r9`).
Go's syscall wrappers use Go's **internal ABI** (`rbx/rcx/rdi/rsi/r8/r9`, NR
in `rax`).  These are *not* the same set of registers, and JS agents that
touch `args[0]..args[5]` are always reading and writing under one convention
but observing effects under the other.

### 3.1 Illustration: `syscall.Syscall(SYS_READ, fd, buf, len)` from Go

Go's caller side puts arguments in Go's internal ABI:

```text
rax = 0    (trap number, unused for Syscall6)
rbx = fd   (a1)
rcx = buf  (a2)
rdi = len  (a3)
rsi = 0    (a4, unused)
r8  = 0    (a5)
r9  = 0    (a6)
```

At function entry, Frida's thunk saves the full register file into
`GumCpuContext`, then the JS callback runs.  From JS, the developer
writes:

```javascript
onEnter: function (args) {
  console.log('fd = ' + args[0]);   // wants to read fd
}
```

Frida-gum's docs say `args[0]..args[5]` map to SysV: `rdi, rsi, rdx, rcx,
r8, r9`.  So `args[0]` reads `rdi`.  In our example above `rdi = len`,
not `fd`.  **The JS logs "fd = 4096" when the real fd was 5.**

Now write:

```javascript
onEnter: function (args) {
  args[0] = ptr(NEW_FD);   // wants to replace fd
}
```

Frida writes NEW_FD into `%rdi` (the SysV `arg0` slot).  Go's post-hook
continuation reads `%rbx` (its own `a1` slot).  **The replacement is
silently ignored.**

Now consider a scratch pointer allocated in JS:

```javascript
onEnter: function (args) {
  var scratch = Memory.alloc(64);
  args[2] = scratch;    // Frida writes %rdx <- scratch
  // ... JS returns; thunk continues
}
```

`%rdx` in the Go internal ABI at this call site is a *temporary*, not an
argument.  Go's syscall wrapper writes `%rbx` (its `a1`) into `%rdi` a
few instructions later, but `%rdx` was scheduled by the compiler to hold
a live-out value used deeper in the function.  Now `%rdx` holds a
pointer into Frida's V8 heap (`Memory.alloc` region).  Twelve
instructions later, that value is written to `[rsp+40]` and the address
`+40` becomes a candidate GC root.  On the next GC scan, the collector
attempts to trace it as a Go pointer.  Depending on the bit pattern
either:

- the collector sees "obviously not a pointer" and skips it — leaked V8
  memory pins into Go's marked set;
- the collector sees "looks like a pointer" and dereferences — SIGSEGV
  at a random-looking address.

### 3.2 Observed symptom

Because the corruption is written into a register slot that Go doesn't
consume until *much later*, the crash never happens at the hook.  It
happens milliseconds later, usually in unrelated logging code, with a
`sigpanic` traceback that looks completely disconnected from the network
path:

```text
fatal error: unexpected signal during runtime execution
[signal SIGSEGV: segmentation violation code=0x1 addr=0x7f... pc=0x...]

goroutine 42 gp=0x... m=3 mp=0x... [running]
runtime.gopanic(...)
runtime.printhex(...)      <-- CRASH SITE — nothing to do with our hook
runtime.printcomplex(...)
log.Println(...)
```

The correlation is invisible.  The engineer spends two days chasing a
red herring.

---

## 4. Problem #3 — Goroutine stack overflow (this is the one you almost never catch)

### 4.1 What Go actually gives you as a "stack"

A newly-created goroutine gets a **2 KiB** stack, allocated by Go's
runtime out of its own heap.  It is not a POSIX pthread stack.  Growth
happens through a compiler-inserted prologue check in every non-`nosplit`
Go function:

```asm
; Compiler-emitted prologue for a Go function
    cmp %fs:g_stackguard0, %rsp        ; are we near the bottom of the stack?
    jbe morestack                      ; if so, allocate a bigger stack, copy, resume
    ; ... function body ...
```

Non-Go code — C code, Frida's thunk, JS runtime, VPP call graph — has no
such check.  Whatever stack we're currently on, we consume it.  If we
overflow it, we corrupt whatever is adjacent in memory (Go's own heap,
another goroutine's stack, a stack guard page).

### 4.2 The Frida call graph on top of a Go stack

When a hook fires, we're on the goroutine that made the call.  The stack
looks like this:

```text
STACK (grows down)   <- goroutine stack, total = 2 KiB (or so, at first entry)

+-----------------------------------------+  <- stackbase (high addr, 2 KiB above stackguard)
| Go application frame (main goroutine)   |  ~400 bytes
| Go net.Conn.Read frame                  |  ~200 bytes
| Go syscall.Read frame                   |  ~100 bytes
| Go syscall.Syscall6 frame               |  ~50 bytes
+-----------------------------------------+  <- ~ 1250 bytes remaining
| Frida thunk save-regs                   |  ~200 bytes (GumCpuContext)
| V8/Duktape JS runtime call frame        |  ~500 bytes
| user JS callback locals                 |  variable
+-----------------------------------------+  <- ~ 550 bytes remaining
| Native dispatcher call frame            |
| vppcom_session_connect                  |
|  session_send_ctrl_evt                  |
|   svm_msg_q_add                         |
|    clib_atomic_load_relax               |
|     ... deep VPP internals ...          |
+-----------------------------------------+  <- OVERFLOW — writes past stackguard
| STACKGUARD PAGE (unmapped in some       |
|   builds — SIGSEGV; mapped in Go's      |
|   heap — silent corruption of another   |
|   goroutine's stack, or Go's own free   |
|   list, or its scheduler state)         |
+-----------------------------------------+
```

The **silent corruption case** is the killer.  Go's stack allocator
places goroutine stacks contiguously.  An overflow into the next
goroutine's stack writes plausible-looking pointer bytes into its
saved-register area, and that goroutine wakes up minutes later with
subtly wrong state.  There is no signal, no immediate fault — just
mysterious failures that appear unrelated to the network path.

### 4.3 What "later" looks like in the logs

We captured a specific instance where the C dispatch used ~1400 bytes of
stack.  Our client had ~680 bytes of headroom at the time of the
overflow.  The corruption walked into Go's `cleanupQueue` state.
Approximately 150 syscalls later — well after the connect had returned
and the client had already logged its "connect refused" error — Go's
runtime tried to dequeue a cleanup entry.  The queue's tail pointer was
now a scrambled bit pattern.  Result:

```text
fatal error: traceback did not unwind completely

goroutine 1 gp=0x... m=0 mp=0x... [running]
runtime.throw(...)                           /usr/local/go/src/runtime/panic.go:1229
runtime.(*unwinder).finishInternal(...)      /usr/local/go/src/runtime/traceback.go:567
runtime.(*unwinder).next(...)                /usr/local/go/src/runtime/traceback.go:448
runtime.(*_panic).nextFrame.func1(...)
runtime.(*_panic).nextFrame(...)
runtime.(*_panic).start(...)
runtime.gopanic(...)                         /usr/local/go/src/runtime/panic.go:757
runtime.panicmem(...)
runtime.sigpanic(...)                        /usr/local/go/src/runtime/signal_unix.go:945
runtime.(*cleanupQueue).createGs(...)        <-- crash triggered here
```

The correlation to Frida is invisible unless you happen to know that:

- Frida's thunk consumed ~700 bytes at the top of the hook;
- our goroutine started at 2 KiB;
- Go's `cleanupQueue` is contiguous with goroutine stacks in the heap.

### 4.4 Why does this NOT happen in the seccomp path?

The seccomp path (approach C) suspends the app thread and delivers the
notification to a **notifier pthread**.  Notifier pthreads have full
POSIX 2 MiB stacks.  All the deep C work happens there.  The goroutine
stack is never even touched by C code.

### 4.5 Why does this NOT happen in the fastpath path?

The fastpath (approach D) explicitly detects it.  Our `vclgo_dispatch`
is a naked-asm function that **swaps `%rsp` from the goroutine stack to
a per-pthread 512 KiB dedicated dispatcher stack** before invoking any
real C code, and swaps back afterward.  This is exactly what
`runtime.cgocall` does when Go calls into C via the supported CGo
boundary.  Frida's Interceptor has no such swap — it just consumes
whatever stack it landed on.

There is no way to add this swap to `Interceptor.attach` from a JS
agent, because `%rsp` is not exposed as writable through the
`CpuContext` API (writing to it would corrupt Frida's own call chain
above the thunk).

---

## 5. Problem #4 — Fake fd defeats Go's netpoller

### 5.1 What Frida did

The retired code returned encoded integers in the range `0x40000000+` to
represent VCL sessions.  The hooked `syscall.socket` handler wrote
`0x40000005` into `%rax`; Go's caller received it as an ordinary fd.

### 5.2 Why that breaks

Go's `net.Conn` code path issues, roughly:

```text
fd = socket(AF_INET, SOCK_STREAM, 0)                    // = 0x40000005 (fake)
epfd = <existing kernel epoll fd>
epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev)                 // KERNEL: EBADF
```

The `epoll_ctl` is a *raw kernel syscall* from Go's netpoller.  It is
not going through any wrapper Frida hooked.  The kernel receives an fd
of `0x40000005`, looks it up in the calling process's file descriptor
table, doesn't find one, and returns `EBADF`.  Go's netpoller treats
that as fatal: the network I/O will never wake up.

### 5.3 The observed symptom

```text
2026/07/15 18:46:44 [0] read: read tcp 0.0.0.0:0->127.0.0.1:9876: read: input/output error
```

Every read fails immediately with EIO.  The connection appeared to
"work" — connect returned success, write returned success — because
those went through hooked wrappers.  Read failed because Go read *from
the parked netpoller state*, which the kernel epoll had discarded.

### 5.4 The fix

You cannot fix this without giving Go **real** kernel fds.  Both the
seccomp path and the fastpath do this via `socketpair(AF_UNIX)`
surrogates: the app-visible fd is one end of a real socket pair; the
dispatcher-side poker holds the other end and writes to it whenever VCL
becomes readable/writable.  Go's netpoller epolls on the real fd
happily.  Frida's Interceptor path has no mechanism to construct
surrogates transparently — the JS agent would have to intercept every
netpoll-related syscall too, and the moment you add one you have to add
them all.

---

## 6. Problem #5 — VCL TLS drifts under Go's M-to-G scheduler

VCL uses per-thread state via C's `__thread` (Thread-Local Storage).
Every session registered with VCL is bound to whichever pthread first
touched it.  Later reads/writes to that session **must** occur on the
same pthread, or VCL either silently opens a duplicate session or
segfaults dereferencing a wrong TLS pointer.

### 6.1 What Go does

Go's runtime maintains a pool of OS threads (Ms).  Goroutines migrate
freely between Ms across function-call boundaries — including across
your hook's return.

```text
Goroutine 42 issues Read:
    <M1> -> hook -> vls_read -> VCL sees TLS-for-M1: OK, session found
    Go schedules G42 to sleep on netpoll wakeup
    Netpoll wakes, G42 resumes on <M3> (different pthread!)
    <M3> issues Write:
    <M3> -> hook -> vls_write -> VCL sees TLS-for-M3: no session; either
                                 * creates a new duplicate session
                                 * segfaults reading NULL TLS
```

### 6.2 Why Interceptor can't fix this

Interceptor's callback runs on **whichever M happens to be executing
the goroutine at that moment**.  There is no way from JS to say "pin
this session to a specific pthread and re-dispatch the call to that
pthread".  Even if there were, you'd need a full C thread-pool
implementation with request queueing — at which point, again, you're
not using Interceptor.

### 6.3 What we do instead

Both the seccomp path and the fastpath use a fixed pool of **permanent
"owner" pthreads**.  Every VCL session has exactly one owner, chosen
at accept-time and immutable.  All calls to that session are marshaled
to its owner via a lock-free queue.  This makes the pthread ↔ session
binding permanent regardless of which M is currently executing the
goroutine.

---

## 7. Why "just fix it" is not an option

Each of the five problems has a "fix" that individually looks reasonable.
The trap is that fixing them together produces a system that is no
longer Frida:

| Problem                              | "Fix" from within Interceptor        | Where the fix leads |
|--------------------------------------|--------------------------------------|---------------------|
| Unwinder-invariant break             | Don't use `onLeave`; direct-return   | Removes Interceptor's return-value API |
| Register ABI mismatch                | Don't touch `CpuContext`; use raw asm | Removes Interceptor's argument API |
| Goroutine stack overflow             | Swap `%rsp` to a big stack           | Not possible from JS; must be C |
| Fake-fd + netpoll                    | Give real socket-pair surrogates     | Requires dedicated dispatcher-side pokers (native C only) |
| VCL TLS drift under M migration      | Route to permanent owner pthreads    | Requires C thread pool with queueing |

Combine all five fixes and you have written a **native C dispatcher +
static syscall-site rewriter with hand-rolled trampolines**.  That is
approach D, and we already have it — see
[`architecture_fastpath.md`](architecture_fastpath.md).  Frida-gum (the
C library) is used by that path for the mechanical parts (Capstone
disassembly + safe RX-page splicing), which is exactly what a C library
is for.  Frida the framework (JS agent + Interceptor) is not used.

---

## 8. Symptom cheat sheet — how to recognize each failure in a bug report

If someone hands you a crash log from a Go program running under
Frida `Interceptor.attach`, use this table.

| You see | It is probably |
|---------|----------------|
| `unexpected return pc for ...` | Unwinder invariant (§2) |
| `pc == addr` and address is in an anonymous mapping (typically `>0x7f00_0000_0000`) | Unwinder invariant (§2) OR register corruption (§3) — the `pc == addr` pattern is unwinder |
| `traceback did not unwind completely` | Usually stack overflow (§4); occasionally unwinder |
| Crash in unrelated code (`log.Printf`, `runtime.printhex`, `runtime.mallocgc`) minutes after the hook fired | Register corruption (§3) or delayed stack-overflow damage (§4) |
| `read: input/output error` on every read of an intercepted socket | Fake-fd + netpoll (§5) |
| Reads and writes on the same session sometimes succeed, sometimes fault, correlated with number of goroutines | VCL TLS drift (§6) |
| Session count in VPP grows faster than app connect count | VCL TLS drift creating duplicates (§6) |

---

## 9. Further reading

- [`architecture_fastpath.md`](architecture_fastpath.md) — byte-level
  design of the current in-process rewriter that solves each of §2–§6
  above using `frida-gum` as a plain C library.
- [`architecture.md`](architecture.md) — the seccomp path that solves
  the same problems by moving the work into a kernel-mediated
  notification.
- [`comparison_approaches.md`](comparison_approaches.md) — comparison
  of all four approaches (vclnet source-level, retired Frida
  Interceptor, seccomp, fastpath).
- [`phase1_frida.md`](phase1_frida.md) — the retirement audit trail,
  including individual defect IDs (S1-9, S1-10, S1-14, S1-16) and the
  historical Frida-era build/harness fixes.

---

**Bottom line:** Frida `Interceptor.attach` is a fine tool for
instrumenting native code that follows the platform ABI.  Go is not
that.  Every native-instrumentation approach that wants to work with Go
must be built around Go's runtime contracts, not against them —
which means: no in-tramp return addresses on the goroutine stack, no
foreign frames of unbounded depth on the goroutine stack, no register
mutation without knowing Go's internal ABI at that exact call site,
real kernel fds returned to Go, and permanent per-session pthread
ownership.  Approach C (seccomp) and approach D (fastpath) both satisfy
those requirements.  Frida's Interceptor cannot.
