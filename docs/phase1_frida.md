# Historical Frida phase: failure and retirement record

Status: historical Approach #2. The current focus is Approach #4, the native
Frida-Gum fastpath. Approach #3 is the separate seccomp backend.
Do not use this document as launch instructions.

The Frida phase was valuable because it proved that an unmodified Go process
could be redirected to VCL. It also demonstrated why live Go function
replacement is the wrong correctness boundary for a concurrent runtime.

## 0. Executive summary — why Frida is wrong for Go

If you only read one section, read this one.

Go's runtime, unlike C, does not just "make syscalls". It:

- **Owns the register file** with a private, versioned calling convention
  ([Go internal ABI]) that does not match SysV AMD64. Its syscall wrappers
  save, restore, and reuse registers under compiler-generated stack maps.
- **Owns the goroutine stack**, which starts at 8 KiB and grows only at
  compiler-inserted preemption/check points. It is not a normal C stack.
- **Owns the M↔G scheduler**, which reparks a goroutine on a *different* OS
  thread across syscalls. Any state you keep in `__thread` storage is
  effectively random from the goroutine's point of view.
- **Owns netpoll**, and passes fds directly to `epoll_ctl`. If a syscall
  return value is not a real kernel fd, netpoll breaks silently.
- **Owns the garbage collector**, which walks goroutine stacks using those
  compiler-generated stack maps. It does not know how to walk a foreign
  frame.

Frida's Interceptor API works by rewriting the *first bytes of the target
function* to jump into a trampoline, staging arguments in a JavaScript/V8
context, calling into `NativeFunction` bridges that use SysV, and then
restoring what it *thinks* the original state was.

Every one of the six bullets above is violated by that mechanism:

| Go invariant | Frida violation | Observed failure |
|---|---|---|
| Go ABI register meaning | Interceptor writes `ctx.rax` etc. under SysV rules | Later goroutine reads corrupt value; deferred SIGSEGV |
| 8 KiB goroutine stack | VLS + VPP call depth added on top of goroutine frame | `unexpected fault address 0x93...`, `pc == addr` panic |
| M-mobile goroutines | VCL `__thread` state tied to whichever M ran the hook | Second read on same session on a different M returns wrong session or crashes |
| Kernel-fd contract with netpoll | Returns encoded integer `0x40000000+n` | `epoll_ctl(EBADF)` or silent wakeup loss |
| GC stack-map validity | Foreign frames on goroutine stack | Traceback stops early; conservative-scan bit misinterpretation |
| Wrapper prologue/epilogue | Trampoline skips runtime bookkeeping | `runtime: g N: unexpected return pc for runtime.sigpanic` |

There is no small change to Frida or to the hook JavaScript that removes
these violations, because **the correctness boundary is wrong**. Frida
patches Go code. The right correctness boundary is the *kernel syscall
instruction* — the one place where every Go version, every ABI generation,
and every wrapper style converge. That is what the native seccomp design
uses.

The rest of this document details each violation, records the concrete live-
run failures they produced, and maps each Frida-era pathology to its
resolution in the native backend.

## 0.1 Live-run failure catalog

The theoretical sections below describe *why* Frida cannot work with Go. The
sections here record *what actually broke* during our live bring-up, so a
future reader can distinguish "we didn't try hard enough" from "the
mechanism is unfit". Each entry corresponds to a defect ID in
[analysis_bugs.md](analysis_bugs.md).

### S1-9 — Cross-thread `__thread errno` cache bug

`vclgo_errno_addr()` returns `&t_errno` where `t_errno` is `__thread`. The
Frida interceptor called this once on Frida's init thread and cached the
resulting pointer. Every subsequent hook, running on Go's M threads, wrote
to a *different* address than the one being read. Result: every VCL error
was silently reported as EIO because the reader saw the never-modified
init-thread slot.

Fixed by making `vclgo_set_errno` write to libc `errno` (which *is*
`__thread`-correct on the current thread) and forcing the JS to resolve
`__errno_location` per-invocation. But: the fact that `__thread` semantics
were violated at all is a symptom of the M-mobility problem in section 7.
The native backend never has this issue because the notifier pthread is a
stable OS thread and the owner pthread is permanent.

### S1-10 — `context.rax = ptr(N)` corrupted the Go return slot

Direct mutation of `ctx.rax` in Frida's `onLeave` handler raced with
Frida's own internal return-value staging on some builds. The Go wrapper
then observed a return value that was neither the original nor the
intended replacement.

Fixed in JS by using `retval.replace(ptr(N))`. But: the fact that a hook
had to reason about *which* register slot Frida uses under *which* ABI in
*which* Frida version is exactly the ABI-coupling problem in section 2.
The native backend never touches any Go register, ever.

### S1-11 — VPP loopback interface missing → session layer unroutable

Not strictly a Frida bug, but discovered during Frida-era bring-up:
`start_vpp.sh` never created a `loop0` interface, so VPP's session layer
had no route for `127.0.0.1` and every `connect(127.0.0.1)` timed out.

Fixed by adding loop0 configuration. Filed because it looked, superficially,
like a Frida bug (client hung) but was not.

### S1-12 — Orphaned processes after test runs

Frida-spawned processes did not inherit a stable process-group id, and
signal handling on the launcher side did not know about them. On any test
failure the parent shell exited but VPP, the Frida agent, and the Go
target continued running.

Fixed by requiring `Setpgid: true` in the launcher and `setsid` in shell
harnesses. The native backend has the same process-tree concern and uses
the same solution — this is not a Frida-specific bug, but the Frida
architecture made it more painful because a hung Frida agent will happily
stay attached forever.

### S1-13 — `setsid: run_as_user: No such file or directory`

`run_as_user` is a shell function, not a binary, so `setsid run_as_user
timeout ...` failed. Fixed by `export -f run_as_user` and reordering the
wrapping. Non-Frida bug but affected the harness we were running.

### S1-14 — SIGSEGV at `0x9300000000` / `0x7f4cf415c0a9` on burst traffic

This is the archetypal Frida-with-Go crash. Symptoms:

```text
2026/07/15 18:46:44 [0] read: read tcp 0.0.0.0:0->127.0.0.1:9876: read: input/output error
unexpected fault address 0x9300000000
fatal error: fault
[signal SIGSEGV: segmentation violation code=0x1 addr=0x9300000000 pc=0x9300000000]
```

`pc == addr` is the giveaway: Go tried to execute at an address it should
never have jumped to. The origin was almost never the faulting frame. Most
often it was a stale pointer written into a Go register slot several hooks
earlier — see sections 2, 4, and 5.

We first tried to mitigate this by adding a dedicated C offload worker
pthread (`dispatcher/src/worker.c`) that ran the deep VLS calls off the
goroutine stack. This *reduced* the crash rate. It did not eliminate it,
because the offload worker still had to marshal arguments and results
through Frida's live register context and V8 heap. The class of crashes
persisted.

### S1-15 — VPP `loop0` idempotency false positive

Similar to S1-11: the `vppctl sh int | grep loop0` check succeeded even
when `loop0` was absent, because `vppctl` printed an error message to
stdout that contained the string "loop0". Fixed by making the check
`awk '{print $1}' | grep -qx 'loop0'`. Not a Frida bug.

### S1-16 (unfiled) — Concurrent-connection hang after all above fixes

Even after S1-9 through S1-15 were resolved, running four concurrent
clients showed one succeeding and three timing out at `connect()`. The
symptoms pointed to either a race in the C dispatcher's `vclgo_poller_wait`
or a Frida-side serialization of `Interceptor` callbacks that prevented
concurrent notifications from being delivered in parallel. We instrumented
extensively but did not fully root-cause this before pivoting to the native
design.

The native design has zero shared JS state, notifier pthreads are ordinary
pthreads with independent kernel wait queues, and per-VLS-handle ownership
is enforced by construction. The whole class of "hooks serialize on some
Frida-internal lock" cannot occur.

### Failure class summary

| ID | Symptom class | Root cause in Frida architecture |
|---|---|---|
| S1-9 | Wrong errno visible | `__thread` state read on non-hook thread |
| S1-10 | Wrong return value | Return-value staging race in Frida ABI bridge |
| S1-14 | `pc == addr` SIGSEGV | Foreign frames on Go goroutine stack + register mutation |
| S1-16 | Concurrency hang | Serialization somewhere in the JS or Interceptor path |

Every one of these is fixed *by construction* in the native design, not by
patch. The native design does not touch Go registers, does not put foreign
frames on the goroutine stack, does not run a JS interpreter, and does not
have a per-hook `__thread` cache.

## 1. What the phase attempted

The launcher spawned or attached Frida, loaded JavaScript, found Go syscall
wrappers, and replaced or attached to functions such as socket, connect,
accept, read, and write. A native dispatcher then called VLS.

```mermaid
flowchart LR
    G["Go net package"] --> H["Patched Go wrapper"]
    H --> F["Frida trampoline / JS or NativeFunction"]
    F --> D["C dispatcher"]
    D --> V["VLS/VPP"]
    D --> F
    F --> H
    H --> G
```

This looked attractive because it avoided kernel features and could inspect
function symbols. Under concurrency, the boundaries were not supportable.

## 2. Register manipulation problem

Go's internal calling convention is not a promise that arbitrary native
instrumentation may translate it into the platform SysV C ABI and back.

The hook path had to reason about:

- which registers held Go arguments for that exact Go version/wrapper;
- which registers Frida saved or treated as scratch;
- which registers a `NativeFunction` call clobbered under SysV;
- how error and secondary return values were represented;
- what the original wrapper expected at its continuation;
- how Frida's on-enter/on-leave context writes interacted with generated code.

```text
                   Go ABI state
RAX/RBX/RCX/...  [arguments, temporaries, return convention]
RSP              [Go frame with compiler stack map]
RIP              [wrapper body / continuation]
                         |
                         | instrumentation bridge
                         v
                   SysV C ABI state
RDI/RSI/RDX/...  [C arguments]
caller-saved     [may be overwritten]
RSP              [foreign frames/alignment]
                         |
                         v
              attempted reconstruction of Go state
```

A scratch pointer allocated by Frida could remain in a register or spill slot
that later Go code interpreted differently. The resulting crash often appeared
after the hook returned, so the faulting function was not the corrupting
function.

## 3. Wrapper control-flow problem

Some experiments replaced a wrapper body or forced an early return. A Go
syscall wrapper is more than the Linux instruction:

```text
entry
  -> establish compiler/runtime frame
  -> runtime syscall bookkeeping
  -> marshal syscall registers
  -> SYSCALL
  -> errno/result conversion
  -> runtime exit bookkeeping
  -> epilogue/return
```

Returning from an instrumentation replacement can skip or duplicate pieces of
that sequence. The scheduler, garbage collector, profiler, traceback, and
asynchronous preemption machinery then observe a state the compiler/runtime
never generated.

The native backend stops inside the kernel at `SYSCALL`; every instruction
before and after it remains original.

## 4. Goroutine stack problem

Go starts goroutine stacks small and grows them at compiler-inserted checks in
Go-aware frames. A foreign trampoline and deep VPP call chain do not form a
normal growable Go stack segment.

```text
Historical mixed stack

high address
+------------------------------+
| Go application frame         |
| Go syscall wrapper           |
| Frida replacement/trampoline | no Go stack map
| JS/NativeFunction bridge     | foreign unwind rules
| dispatcher                   |
| vls_read/write               |
| VPP internal call depth      |
+------------------------------+
low address / guard
```

More native stack consumption could overwrite memory or leave the Go unwinder
and GC unable to interpret frames. Offloading selected calls to a C pthread
reduced symptoms but did not repair register/control-flow replacement.

The native design puts all VLS/VPP depth on permanent 2 MiB owner pthread
stacks.

## 5. Heap and pointer problem

Frida JavaScript and V8 introduced another heap with a lifetime model unrelated
to Go.

```text
Frida/V8 heap                      live Go CPU context
+----------------------+           +--------------------------+
| Memory.alloc scratch |---------->| general register/spill   |
+----------------------+           +--------------------------+
       GC/lifetime A                      compiler meaning B
```

A pointer valid to Frida was not automatically a valid long-lived value under
Go's register maps or continuation semantics. Even when the allocation
remained live, Go could later treat the bits as a function/data pointer with a
different meaning.

The native path has no V8 heap and never writes scratch pointers into Go
register context.

## 6. Garbage collector and traceback problem

Go stack maps identify which slots/registers hold Go pointers at compiler-known
safe points. Instrumentation frames and arbitrary context edits are not in
those maps.

Potential results included:

- conservative-looking bits interpreted under the wrong frame;
- traceback stopping or walking with a wrong SP/PC;
- preemption at a continuation whose frame state did not match generated code;
- crashes in later logging, allocation, or return code.

The native path uses the normal syscall safe point. Helper pthread stacks are
ordinary native stacks and are not presented as Go stacks.

## 7. VCL TLS problem

A hook executed on whichever Go M ran the goroutine. VCL worker state is
pthread-local. Registering on first touch did not make a session safe after the
goroutine migrated, and unregistering based on M activity could invalidate
sessions still in use.

```text
G on M1 -> VLS worker TLS 1 -> session
G resumes on M2 -> VLS worker TLS 2 -> same session  (invalid ownership)
```

The native owner model routes both calls to the same permanent pthread,
regardless of M1/M2.

## 8. Fake-fd problem

Frida could return an encoded integer to intercepted read/write calls, but Go
also submits the fd to kernel epoll. Hooking more wrappers did not make the
integer a kernel object.

Consequences included:

- `epoll_ctl(EBADF)`;
- collisions with real fds;
- missed deadlines/wakeups;
- ever-expanding hook coverage;
- incorrect behavior in libraries issuing syscalls through another path.

The native backend returns an actual socket-pair fd, so no Go epoll hook is
needed.

## 9. Blocking and deadlines

Earlier dispatchers blocked C callbacks on VLS readiness or spun in accept.
That consumes a native callback/M and bypasses Go's deadline authority.

The current sequence is:

```text
nonblocking VLS EAGAIN
  -> owner arms VLS epoll
  -> original Go syscall returns EAGAIN
  -> Go netpoll parks goroutine on real fd
```

## 10. Why common repairs were rejected

| Proposed repair | Why it is insufficient |
|---|---|
| Save more registers | Does not define a supported Go continuation/stack-map contract |
| Move JS hot path to CModule | Reduces overhead, not ABI/control-flow risk |
| Hook a broader `Syscall6` | Expands blast radius to runtime-critical syscalls |
| Hook every epoll call | Still leaves a non-kernel fake fd and version coverage gaps |
| Register every Go M with VCL | M lifetime is not session lifetime |
| Use one global mutex | Does not fix VCL TLS identity |
| Increase goroutine stack | Foreign frames/control flow remain unsupported |
| Lock current OS thread | Cannot impose it on all unmodified goroutines/libraries |
| Retry on crashes | Memory corruption is nondeterministic and unacceptable |

## 11. Symptom pattern

The historical failures often showed:

```text
single connection succeeds
small burst succeeds
error/logging/return path executes
later SIGSEGV with PC equal or near a heap-like address
```

The delay is consistent with earlier register/stack corruption being consumed
later. It is not evidence that logging or the final Go function caused the
corruption.

## 12. Native resolution mapping

| Frida-era issue | Native mechanism |
|---|---|
| Function replacement | Native raw-syscall-site interception (Approach #4) or kernel stop (Approach #3) |
| Live register context writes | Explicit ABI shim/original Go wrapper |
| Foreign frames on G stack | Dispatcher stack plus owner pthread VLS stack |
| Frida JS heap scratch | No JavaScript/agent heap |
| M/VCL TLS mismatch | Immutable session owner |
| Fake fd | Real socket-pair surrogate |
| Hooked Go epoll | Unmodified kernel epoll |
| Internal C wait | Go netpoll and timers |
| Symbol/version dependence | Executable text range + syscall numbers |
| Attach-time ordering | ELF constructor before Go runtime threads |

## 13. Legacy backend policy

`VCLGO_BACKEND=frida` remains only for explicit historical diagnostics. A
legacy run must not be used to claim concurrent correctness, performance, or
memory safety of native vclgo.

Current Approach #4 status and open risks are documented in [status.md](status.md) and
[analysis_bugs.md](analysis_bugs.md).
