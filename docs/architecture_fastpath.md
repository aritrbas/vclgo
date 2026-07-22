# vclgo fastpath architecture — in-process syscall rewriting with frida-gum

**Status:** current Approach #4 engineering prototype. TCP and UDP control
and data operations route through VCL. Cut-through TCP concurrency/deadlines
and routed UDP/HTTP have passed at the scale recorded in
[`status.md`](status.md).

**Scope of this doc.**  This is the low-level design of the *fastpath* preload
that lives in [`preload/fastpath/gum_vcl.c`](../preload/fastpath/gum_vcl.c).
It is not the seccomp path (that is described in
[`architecture.md`](architecture.md)).  It covers every byte we emit into the
target process — register conventions, memory layouts, the exact opcodes we
splice, why we splice those and not others, and the two invariants (Go
unwinder + goroutine stack) that constrain every choice.

**See also.**
[`architecture_diagrams_fastpath.md`](architecture_diagrams_fastpath.md) is
the diagram-only companion — flowcharts of the constructor pipeline,
before/after byte layouts of a wide patch at a concrete Go address, the
trampoline page's memory layout, ABI conversion table, and the
socket-pair surrogate mechanism that resolves the VCL pthread problem
(§14 of that doc is the single most important design invariant in the
whole project).

---

## 1. Positioning: is this "zpoline"?  Is it "Frida"?

Both terms come up.  Neither is quite right.

**We are not zpoline.**  Zpoline (Yasukata et al., ATC ’23) replaces every
2-byte `SYSCALL` instruction with the 2-byte `callq *%rax` (`FF D0`).  Because
`%rax` already holds the syscall number on entry, the CALL routes into a
64 KiB trampoline table mapped at virtual address `0..0xFFFF`.  Elegant, but
it requires:

- `vm.mmap_min_addr = 0` (kernel tuning; disabled by default on modern
  distros for good reason — it makes NULL-pointer bugs exploitable);
- exactly 2 bytes of patch slot (no dispatch context around the SYSCALL);
- a trust that `%rax` is always a valid syscall number at every patch site
  (fragile against `mov $-1, %eax; syscall`-style probes).

We chose a different point in the design space: **wide patching**.  Every
Go SYSCALL site is preceded by exactly 5 or 7 bytes of `mov $NR, %eax|%rax`
(§4.1), giving us 7–9 bytes to reuse for a `CALL rel32` (5 bytes) + NOPs.
No kernel tuning, no low-memory table, and the SYSCALL site's own `NR` load
gives us a stable per-site immediate to encode into the trampoline.

**We are frida-gum-based, not Frida.**  Frida is a runtime instrumentation
toolkit exposing three layers:

1. **`frida-core`**: process attach/detach, JavaScript RPC bridge, agent
   loading.  This is what `frida-cli` uses.
2. **`frida-gum-js`**: the JavaScript `Interceptor` / `Stalker` / `Module`
   APIs an agent script calls into.
3. **`frida-gum`**: the underlying C library that does the actual
   disassembly (via bundled Capstone), code allocation
   (`gum_memory_allocate_near`), atomic patch installation
   (`gum_memory_patch_code`), and module iteration
   (`gum_module_enumerate_sections`, `gum_module_find_symbol_by_name`).

Our earlier retired path used **Frida** — the whole stack including
`Interceptor.attach` from JS.  That failed for structural reasons (§8.1).
This path uses **only `frida-gum`** — as a memory-patching library, statically
linked (`libfrida-gum.a`), with zero runtime dependency on the Frida agent,
JavaScript, or `Interceptor`.  Every emitted byte is written by us.  Frida-gum
is used strictly for four things:

- Capstone disassembly (`cs_disasm_iter`, `X86_INS_SYSCALL`);
- Section discovery (`.text` bounds for the target executable);
- Symbol lookup (`gum_module_find_symbol_by_name` — resolves the three
  runtime wrappers by name);
- Cross-thread safe RX-page splicing (`gum_memory_patch_code`, which
  handles the `mprotect RW → memcpy → mprotect RX` dance atomically).

Everything after that — the shim, the per-site trampoline, the Syscall6
tramp, the stack switch — is hand-written x86-64 machine code that we
compose byte-by-byte in the constructor.

---

## 2. Target-program anatomy: what a Go binary looks like to us

Concrete numbers below are from `bin/examples/echo_client` built with
Go 1.26.1.  They are stable across Go versions because the Go standard
library layout is stable.

### 2.1 Two syscall dialects in a Go binary

Every Go binary emits two kinds of SYSCALL sites into `.text`:

**Direct sites (36 in echo_client).** For runtime-internal syscalls with
compile-time-known NR (`futex`, `nanosleep`, `mmap`, `epoll_pwait`,
`clock_gettime`, `exit_group`, …), the Go compiler inlines the pattern:

```asm
  4893c4:  b8 e7 00 00 00        mov    $0xe7, %eax    ; nr = 231 (exit_group)
  4893c9:  0f 05                 syscall
  4893cb:  ...                                          ; result-translation
```

Or the `%rax` variant when the NR is `≥ 0x80000000`:

```asm
  48950a:  48 c7 c0 ba 00 00 00  mov    $0xba, %rax    ; nr = 186 (gettid)
  489511:  0f 05                 syscall
```

We only need to identify one of the two `mov` opcodes (0xB8 for `%eax`,
0x48 0xC7 0xC0 for `%rax`) and the 2-byte SYSCALL that follows.  The
Capstone linear pass in `find_m2_sites` walks `.text` and for each
`X86_INS_SYSCALL` peers at the 5 or 7 bytes preceding it (`gum_vcl.c:730`).

**Generic wrappers (3 in every Go binary).**  For syscalls whose NR is
provided at runtime (`syscall.Syscall`, `syscall.RawSyscall`, and family),
Go funnels through three assembly wrappers:

- `internal/runtime/syscall/linux.Syscall6` @ `0x409540`
- `syscall.rawSyscallNoError.abi0`         @ `0x4997e0`
- `syscall.rawVforkSyscall.abi0`           @ `0x499780`

These have variable and runtime-supplied `NR` in `%rax`, so no wide-patch
site is available above the SYSCALL — the whole point of the wrapper is
that NR moves into `%rax` from a caller-provided stack slot.  We handle
these with a different mechanism (§5).

### 2.2 The Go internal ABI vs. SysV — a two-slide primer

This distinction is central to every register spill in the shim.  Go's
`Syscall6(trap, a1, a2, a3, a4, a5, a6)` uses Go's *internal* register ABI:

| Arg    | trap | a1  | a2  | a3  | a4  | a5  | a6  |
|--------|------|-----|-----|-----|-----|-----|-----|
| Reg    | %rax | %rbx| %rcx| %rdi| %rsi| %r8 | %r9 |

The kernel's SysV syscall ABI is:

| Arg    | NR   | a0  | a1  | a2  | a3  | a4  | a5  |
|--------|------|-----|-----|-----|-----|-----|-----|
| Reg    | %rax | %rdi| %rsi| %rdx| %r10| %r8 | %r9 |

`Syscall6` is literally four `mov` instructions that convert one to the
other, then executes SYSCALL, then translates the result back:

```asm
0000000000409540 <internal/runtime/syscall/linux.Syscall6>:
  409540:  49 89 f2              mov    %rsi, %r10    ; a4 -> syscall a3
  409543:  48 89 fa              mov    %rdi, %rdx    ; a3 -> syscall a2
  409546:  48 89 ce              mov    %rcx, %rsi    ; a2 -> syscall a1
  409549:  48 89 df              mov    %rbx, %rdi    ; a1 -> syscall a0
  40954c:  0f 05                 syscall
  40954e:  48 3d 01 f0 ff ff     cmp    $0xfffffffffffff001, %rax
  409554:  76 15                 jbe    40956b        ; success path
  409556:  48 f7 d8              neg    %rax          ; errno = -rax
  409559:  48 89 c1              mov    %rax, %rcx    ; ret errno
  40955c:  48 c7 c0 ff ff ff ff  mov    $-1, %rax     ; ret r1 = -1
  409563:  48 c7 c3 00 00 00 00  mov    $0, %rbx      ; ret r2 = 0
  40956a:  c3                    ret
  40956b:  48 89 d3              mov    %rdx, %rbx    ; success: r2 = rdx
  40956e:  48 c7 c1 00 00 00 00  mov    $0, %rcx      ; errno = 0
  409575:  c3                    ret
```

The two dispatch paths we insert both aim to feed a C dispatcher a
`(nr, a0..a4)` argument vector in SysV C-ABI, then produce a two-word
result (`rax:rdx`) that flows into `Syscall6+14` (`cmp $-4095, %rax; …`)
so we get the "return errno vs. r2" translation for free.

---

## 3. The overall memory layout we install

At constructor time we allocate exactly **one 2×4 KiB anonymous mapping
"near"** the main executable's `.text` (via
`gum_memory_allocate_near(near=text_midpoint, max_distance=1 GiB)`).  This
guarantees every patch site can reach every trampoline with a signed
`rel32` (`±2 GiB`) displacement.

The page is laid out contiguously:

```text
+----------------------------------------------------------------------+  <- page base
| shared shim         (94 bytes, budget 128)                           |
+----------------------------------------------------------------------+  <- page + 128
| M2 site tramp #0    (10 bytes used, 16-byte slot)                    |
| M2 site tramp #1                                                     |
| ...                                                                  |
| M2 site tramp #35                                                    |
+----------------------------------------------------------------------+  <- page + 128 + 36*16
| Syscall6 dispatch tramp    (29 bytes used, 64-byte slot)             |
| rawSyscallNoError tramp    (11 bytes used, 64-byte slot)             |
| rawVforkSyscall tramp      (13 bytes used, 64-byte slot)             |
+----------------------------------------------------------------------+
| 0xCC padding to end-of-page                                          |
+----------------------------------------------------------------------+
```

Total budget with the current bounds (256 M2 sites + 3 wrappers): 4416
bytes.  We map 2 pages (8 KiB) to leave headroom.  The mapping is
initially `RW`, written by the constructor, then flipped to `RX` via
`gum_mprotect (page, size, GUM_PAGE_RX)` before the first patched
instruction is unlocked.

The dispatcher C symbol `vclgo_dispatch` lives in `libvclgo_gum_vcl.so`,
which is loaded somewhere entirely different in the address space (>1 GiB
from `.text`).  The shim reaches it via `movabs $addr, %r11; call *%r11`
(§6.4).

---

## 4. M2 wide patch — the direct-site path

### 4.1 What we overwrite

For every direct SYSCALL site (36 in echo_client) we splice **7 or 9
bytes** starting at the beginning of the `mov $NR, ...` and ending after
the SYSCALL.  Before:

```text
mov $NR, %eax     ; 5 bytes (0xB8 imm32)
syscall           ; 2 bytes (0x0F 0x05)
```

After (7-byte case):

```text
call rel32(tramp) ; 5 bytes (0xE8 imm32)
nop; nop          ; 2 bytes (0x90 0x90)
```

Nine-byte case (when Go emitted `mov $NR, %rax`):

```text
mov+syscall  ; 9 bytes total (7 + 2) -> call + 4 NOPs
```

The `NR` immediate is *not lost*: the per-site trampoline restores it
before jumping to the shared shim (§4.3).

Encoded byte payload (7-byte example, `gum_vcl.c:777`):

```c
uint8_t bytes[9] = { 0xE8, 0, 0, 0, 0,
                     0x90, 0x90, 0x90, 0x90 };
memcpy (&bytes[1], &rel32, 4);
```

`gum_memory_patch_code (start, len, apply_patch, &pl)` performs the write
inside a signal-safe critical section: it flips the page RW, memcpys the
7/9 bytes, flushes the I-cache, and flips the page back to RX.  All other
threads are running concurrently.  This is safe because CPU x86 guarantees
that a same-address 8-byte-aligned write appears atomic to instruction
fetch, and Capstone verified our patched window sits within a
single 8-byte alignment (which is true because `mov $NR, %eax; SYSCALL`
is < 8 bytes and the ancillary NOPs live in the same slot).

### 4.2 A concrete site

Before, at `0x4893f0` in echo_client's `.text`:

```text
  4893f0:  b8 3c 00 00 00        mov    $0x3c, %eax     ; nr=60 exit
  4893f5:  0f 05                 syscall
```

After patching (with `tramp` at `page + 128 + slot_i * 16`):

```text
  4893f0:  e8 XX XX XX XX        call   tramp_60
  4893f5:  90 90                 nop; nop
```

The 5-byte `mov` + 2-byte SYSCALL becomes 5-byte `CALL` + 2-byte NOPs —
exactly the same footprint, no downstream Go code has to move.

### 4.3 The per-site trampoline (16-byte slot, 10 bytes used)

Each site gets a dedicated slot inside the trampoline page (§3).  Layout
emitted by `emit_m2_site_tramp` (`gum_vcl.c:756`):

```asm
tramp_NR:
    b8 NR NR NR NR          mov   $NR,   %eax        ; restore NR (5B)
    e9 XX XX XX XX          jmp   rel32 shim         ; jump to shared shim (5B)
    ; 6 bytes 0xCC padding to next 16-byte slot
```

Why `jmp shim` and not `call shim`?  If it were `call`, the shim's return
address would point at *this trampoline slot* — an anonymous mapping the
Go unwinder cannot recognize (§9).  With `jmp`, the shim inherits the
return address that the site's original `CALL tramp_NR` pushed.  That
return address is `sitesite + 5` (i.e., pointing at the two `NOPs`) —
which is a valid PC inside the Go `.text` and therefore fully unwind-safe.

The shim eventually `ret`s.  RSP pops the site's return address, and Go
resumes execution at `site + 5` (the NOPs), which harmlessly fall through
to whatever result-translation code the Go compiler had already emitted
after the original `SYSCALL`.  In practice the very next instruction after
each Go direct-site SYSCALL is `cmp $-4095, %rax` or similar, exactly what
we want (the shim's `rax`/`rdx` result matches the kernel's convention).

---

## 5. M2.5 function-entry detour — the generic-wrapper path

The three generic wrappers (§2.1) have `NR` in `%rax` at runtime, so
there is no immediate to encode into a per-site trampoline.  Instead we
overwrite their entry with a `JMP rel32` and put the "conversion +
dispatch" logic in the trampoline slot.

### 5.1 Discovery — what the entry point looks like

Wrappers are resolved by name via `gum_module_find_symbol_by_name(m, ...)`.
Then `scan_prologue` uses Capstone to walk instructions from the entry
until we've consumed **≥ 5 bytes** of *relocatable* instructions (no
relative jumps, no RIP-relative memory operands).  For Syscall6:

```text
409540:  49 89 f2              mov %rsi, %r10   ; 3 bytes -- relocatable
409543:  48 89 fa              mov %rdi, %rdx   ; 3 bytes -- relocatable
                                                ; total 6 bytes: enough
```

Six bytes are copied verbatim into the trampoline; then a `JMP rel32`
follows.

### 5.2 Identity wrappers (2 of 3): passthrough

For `rawSyscallNoError` and `rawVforkSyscall` we install what amounts to
a NOP detour: copy the prologue, `JMP rel32` back to `entry + prologue_len`,
and the wrapper continues normally as though it were never patched
(`emit_identity_wrapper_tramp`, `gum_vcl.c:881`).  We patch these anyway
so we have a uniform "one preloaded binary, all Go syscalls visible"
mechanism for future work (e.g., accounting or per-syscall filtering).

### 5.3 Syscall6 dispatch tramp (29 bytes, `emit_syscall6_tramp`)

This is where the network path lives.  We do **not** simply chain to a
copied prologue like the identity case — instead we reproduce Syscall6's
own ABI-conversion `mov`s inline, push a fake return address, and jump
into the shared shim:

```asm
S6_tramp:
    ; --- Syscall6-style ABI conversion (verbatim from entry) ---
    49 89 f2              mov %rsi, %r10           ; 3B   Go a4 -> SysV a3
    48 89 fa              mov %rdi, %rdx           ; 3B   Go a3 -> SysV a2
    48 89 ce              mov %rcx, %rsi           ; 3B   Go a2 -> SysV a1
    48 89 df              mov %rbx, %rdi           ; 3B   Go a1 -> SysV a0
    ; on entry rax already holds NR; rdi/rsi/rdx/r10/r8/r9 now hold a0..a5

    ; --- Push a fake return address = Syscall6+14 (post-SYSCALL) ---
    49 bb XX XX XX XX     movabs $post, %r11       ; 10B  post = entry+14
             XX XX XX XX
    41 53                 push %r11                ; 2B   fake ret

    ; --- Jump (NOT call) to the shared shim ---
    e9 XX XX XX XX        jmp rel32 shim           ; 5B
                                                   ; total 29 bytes
```

**Why `push post; jmp` instead of `call shim; jmp post`?**  This is the
same unwinder invariant as §4.3, but the failure was harder to spot.  If
we had done `call shim; jmp post`, then throughout the entire duration of
the C dispatch, `rsp` would have a return address = `S6_tramp + 15`
(pointing at our `jmp post` inside the trampoline).  During any signal
delivered while the dispatch was running (SIGURG async preemption,
SIGPROF profiling, or a nested SIGSEGV from within a VLS callback), Go's
`runtime.gentraceback` walks the frame chain and demands every return PC
resolve to a known Go function via the `pclntab`.  A PC inside our
anonymous mapping fails the lookup and aborts the process with
`traceback did not unwind completely`.  Long-blocking VLS calls (`connect`,
`read`, `write` on a routed socket) make that window arbitrarily wide, so
the crash was reliably reproducible.

With `push post; jmp shim`, the ONLY return address the C dispatch sees
above its own `rip` is `post = Syscall6 + 14` — a valid Go PC.  When
`shim` eventually executes its own `ret`, RSP pops `post`, and control
resumes directly at Syscall6's cmp/neg/mov result-translation block:

```asm
40954e:  48 3d 01 f0 ff ff     cmp    $-4095, %rax
409554:  76 15                 jbe    40956b            ; success path
...
```

which then `ret`s to whatever Go function called Syscall6 in the first
place.  Our trampoline is not on the stack when the dispatch runs.

The dispatch returns `__int128` in `rax:rdx` (§6.4), which is exactly the
kernel-style `(result, result2)` pair that the Syscall6 result-translation
code expects (it reads `rdx` on the success path at `0x40956b: mov %rdx,%rbx`
to populate `r2`).

### 5.4 Entry-point patch

`patch_wrapper_entry` overwrites bytes `[entry, entry+prologue_len)` with:

```asm
e9 XX XX XX XX      jmp rel32 tramp    ; 5B
90 90 ...           nop padding to fill the rest of the prologue
```

Because `prologue_len` is chosen to be exactly the number of bytes
we relocated into the trampoline (≥ 5), the patch region is a valid
1-instruction plus NOP tail — no half-instructions are ever visible to a
concurrent decode.

---

## 6. The shared shim

One 94-byte block, entered from **both** the M2 site trampolines (via
`jmp`) and the Syscall6 tramp (via `jmp`).  Its job: convert the SysV
syscall ABI (rdi/rsi/rdx/r10/r8/r9, NR in rax) into the SysV C ABI
(rdi/rsi/rdx/rcx/r8/r9), call `vclgo_dispatch`, and return.  It never
knows nor cares which of the two entry paths brought it here.

### 6.1 Layout (`emit_shim`, `gum_vcl.c:608`)

```asm
shim:
    ; --- Frame setup ---
    55                    push %rbp                  ; save caller's rbp
    48 89 e5              mov  %rsp, %rbp
    48 83 e4 f0           and  $-16, %rsp            ; force 16-byte align
    48 83 ec 40           sub  $0x40, %rsp           ; 64-byte scratch

    ; --- Spill the 6 SysV syscall args to scratch ---
    48 89 3c 24           mov  %rdi, 0(%rsp)         ; a0
    48 89 74 24 08        mov  %rsi, 8(%rsp)         ; a1
    48 89 54 24 10        mov  %rdx, 16(%rsp)        ; a2
    4c 89 54 24 18        mov  %r10, 24(%rsp)        ; a3
    4c 89 44 24 20        mov  %r8,  32(%rsp)        ; a4
    4c 89 4c 24 28        mov  %r9,  40(%rsp)        ; spill a5 for stack arg

    ; --- Marshal SysV C-ABI args for vclgo_dispatch(nr,a0..a5) ---
    48 89 c7              mov  %rax, %rdi            ; nr  -> C arg0
    48 8b 34 24           mov  0(%rsp), %rsi         ; a0  -> C arg1
    48 8b 54 24 08        mov  8(%rsp), %rdx         ; a1  -> C arg2
    48 8b 4c 24 10        mov  16(%rsp), %rcx        ; a2  -> C arg3
    4c 8b 44 24 18        mov  24(%rsp), %r8         ; a3  -> C arg4
    4c 8b 4c 24 20        mov  32(%rsp), %r9         ; a4  -> C arg5
    ff 74 24 28           pushq 40(%rsp)              ; a5  -> C arg6

    ; --- Indirect call (dispatcher lives >1 GiB from .text) ---
    49 bb XX XX XX XX     movabs $&vclgo_dispatch, %r11
             XX XX XX XX
    41 ff d3              call *%r11
    48 83 c4 08           add $8, %rsp                ; discard a5 stack arg

    ; --- Return: rax:rdx already hold the __int128 result ---
    48 89 ec              mov  %rbp, %rsp
    5d                    pop  %rbp
    c3                    ret
```

### 6.2 What "return" means depending on entry path

- **From an M2 site**: the `ret` pops the caller's return address =
  `site + 5` (§4.3), and Go's own post-SYSCALL result-translation code
  runs against `rax:rdx`.
- **From the Syscall6 tramp**: the `ret` pops `post = Syscall6 + 14`
  (§5.3), and Syscall6's own cmp/neg/mov block does the internal-ABI
  conversion.  `rdx` (result2) survives via the `__int128` return.

### 6.3 What we do NOT preserve

The shim does not restore `%rdi/%rsi/%rdx/%r10` after the C call.
Under SysV C-ABI those are caller-saved so the compiler already assumes
they're clobbered by `vclgo_dispatch`, and both entry paths reload their
own state from stack slots before consuming any of those registers.  This
was verified against every Go direct-site pattern in the target binary
(`runtime.futex.abi0`, `runtime.exit.abi0`, `runtime.mmap.abi0`, etc.).

### 6.4 Why `__int128`

The kernel syscall ABI returns *two* words for a small handful of syscalls
(`pipe`, `fork`, etc. — kernel puts fd1 in `rdx`).  Ordinary C-ABI
functions returning `long` only fill `rax`; `rdx` is caller-saved and
unspecified.  Returning `__int128` (or `struct { long lo; long hi; }`)
is the standard trick to preserve both — the compiler places the low
word in `rax` and the high word in `rdx`, matching kernel exit state
exactly.  Syscall6's result-translation block reads both.

---

## 7. Naked `vclgo_dispatch` — the stack switch

`vclgo_dispatch` is a `__attribute__((naked))` function.  The shim calls
it; it does exactly one thing: swap `%rsp` from the caller's stack to a
per-pthread 512 KiB "dispatcher stack", `call vclgo_dispatch_impl`, then
swap back.

### 7.1 Why we need this — the goroutine stack problem

Go goroutines run on **runtime-managed 2 KiB stacks that grow on demand**
via `runtime.morestack`.  Growth is triggered by prologue checks in every
non-`//go:nosplit` Go function.  When we call into C directly, no such
check runs — C thinks it has whatever stack C code always has.

For the seccomp path this was invisible because the whole C stack lived on
a dedicated notifier pthread (2 MiB stack).  For the fastpath the shim
runs *on the goroutine's tiny stack*.  Descending into VLS/VPP —
`vppcom_session_connect` → `session_send_ctrl_evt` → `svm_msg_q_add` →
`clib_atomic_load_relax` → … — trivially blows past a 680-byte headroom
observed under stress.  The corruption manifests ~150 syscalls later as a
Go runtime abort:

```text
fatal error: traceback did not unwind completely
```

The seccomp path is immune because its notifier pthread has a full 2 MiB
POSIX stack.  Our fastpath had to reproduce that isolation.

### 7.2 The switch (`gum_vcl.c:512`)

```asm
vclgo_dispatch:
    ; --- Frame ---
    55                     push %rbp
    48 89 e5               mov  %rsp, %rbp

    ; --- Save 6 SysV C-ABI args across the disp_stack_get() call ---
    41 51                  push %r9
    41 50                  push %r8
    51                     push %rcx
    52                     push %rdx
    56                     push %rsi
    57                     push %rdi
    48 83 ec 08            sub  $8, %rsp             ; realign to 16

    e8 XX XX XX XX         call disp_stack_get       ; -> %rax = disp_top

    48 83 c4 08            add  $8, %rsp
    49 89 c3               mov  %rax, %r11           ; save disp_top

    ; --- Restore args ---
    5f                     pop  %rdi
    5e                     pop  %rsi
    5a                     pop  %rdx
    59                     pop  %rcx
    41 58                  pop  %r8
    41 59                  pop  %r9

    ; --- The actual swap ---
    49 89 e2               mov  %rsp, %r10           ; save goroutine rsp
    4c 89 dc               mov  %r11, %rsp           ; switch to disp stack
    41 52                  push %r10                 ; stash goroutine rsp
    48 83 ec 08            sub  $8, %rsp             ; realign

    e8 XX XX XX XX         call vclgo_dispatch_impl

    48 83 c4 08            add  $8, %rsp
    5c                     pop  %rsp                 ; atomic swap back

    5d                     pop  %rbp
    c3                     ret
```

The `pop %rsp` on the way out is atomic with respect to Go's signal
handler (which reads `%rsp` from `siginfo_t.uc_mcontext.gregs[REG_RSP]`):
either the signal fires *before* the pop, in which case `%rsp` points
into the disp stack (a mapping the Go signal handler can't unwind but
which sigpanic simply refuses to walk), or it fires *after*, in which
case `%rsp` is safely back on the goroutine stack.

### 7.3 The disp stack itself

`g_disp_stack_top` is a `__thread` pointer (initial-exec model, resolved
via `%fs:offset`).  Zero on first entry; `disp_stack_alloc_slow` populates
it with `mmap(512 KiB, MAP_STACK)`.  A `pthread_key_create`-registered
destructor `munmap`s on thread exit.  The slow path uses < 300 bytes of
stack (short mmap + pthread_setspecific), which fits inside the smallest
observed goroutine headroom.

512 KiB is chosen to be:

- Larger than the deepest VPP call graph we've measured (< 32 KiB in
  practice);
- Small enough that a system with thousands of pthreads spends < 2 GiB
  on disp stacks;
- Aligned to `MAP_STACK` semantics so the kernel guard-page treatment
  applies.

---

## 8. `vclgo_dispatch_impl` — the actual routing

`vclgo_dispatch_impl(nr, a0..a5)` runs on the disp stack. It mirrors
the `dispatch_notification()` routing switch of the retired seccomp
preload (removed with the Approach #3 cleanup; visible in git history)
byte-for-byte in semantics — the only difference is how it was reached
(function call vs. seccomp notification).

Routing summary:

| syscall (nr)             | Owned fd path                   | Non-owned path        |
|--------------------------|---------------------------------|-----------------------|
| `__NR_exit_group` (231)  | Call `vclgo_teardown()` then raw syscall | (same) |
| `__NR_socket`   (41)     | Route supported AF_INET/AF_INET6 stream or datagram sockets when not passthrough | Raw syscall |
| `__NR_close`    (3)      | `vclgo_close(fd)`               | Raw syscall           |
| `__NR_read`     (0)      | `vclgo_read(fd, buf, len)`      | Raw syscall           |
| `__NR_write`    (1)      | `vclgo_write(fd, buf, len)`     | Raw syscall           |
| `__NR_readv`    (19)     | Iov-loop over `vclgo_read`      | Raw syscall           |
| `__NR_writev`   (20)     | Iov-loop over `vclgo_write`     | Raw syscall           |
| `__NR_sendto` / `recvfrom` | VCL TCP/UDP data with address semantics | Raw syscall |
| `__NR_sendmsg` / `recvmsg` | Supported iovec/name subset; ancillary data excluded | Raw syscall |
| `__NR_connect`  (42)     | `vclgo_connect(...)`            | Raw syscall           |
| `__NR_accept`   (43)     | `vclgo_accept(...)`             | Raw syscall           |
| `__NR_accept4`  (288)    | `vclgo_accept4(...)`            | Raw syscall           |
| `__NR_bind`     (49)     | `vclgo_bind(...)`               | Raw syscall           |
| `__NR_listen`   (50)     | `vclgo_listen(...)`             | Raw syscall           |
| `__NR_getsockname` (51)  | `vclgo_getsockname(...)`        | Raw syscall           |
| `__NR_getpeername` (52)  | `vclgo_getpeername(...)`        | Raw syscall           |
| `__NR_setsockopt` (54)   | `vclgo_setsockopt(...)`         | Raw syscall           |
| `__NR_getsockopt` (55)   | `vclgo_getsockopt(...)`         | Raw syscall           |
| `__NR_shutdown` (48)     | `vclgo_shutdown(...)`           | Raw syscall           |
| `__NR_fcntl`    (72)     | Reject `F_DUPFD*` on owned fd, else raw | Raw syscall  |
| `__NR_dup*`     (32,33,292) | EOPNOTSUPP on owned fd        | Raw syscall           |
| everything else          | Fall through to raw syscall on owned fd (same as the retired seccomp preload's `default: continued=1`) | Raw syscall |

Ownership is decided by `vclgo_owns_fd(fd)` (`dispatcher/src/vclgo.c`),
which does an O(1) lookup in a hash table indexed by the socket-pair
surrogate fd that VCL handed back at `socket()` time.  Any fd not in the
map is *by construction* not a VCL session.

Raw syscalls are emitted via inline asm (`raw_syscall5`) that carefully
saves/restores `%rdx` as an input/output register — the same trick the
kernel uses to expose result2.

### 8.1 Init and teardown

The library constructor (`vclgo_gum_ctor`, `gum_vcl.c:988`) runs before
`main()`:

1. Honor `VCLGO_DISABLE` (bail out — leaves the app fully native).
2. `gum_init_embedded()` — one-time init of frida-gum's internal state
   (Capstone, allocator, mutex). Must run exactly once per process.
3. `gum_process_get_main_module()` + `gum_module_enumerate_sections` —
   locate `.text` of the target executable.
4. Find direct sites and resolve/classify generic wrappers.
5. If neither class is found, deinitialize Gum and return without touching
   VPP; this prevents non-Go helpers from registering as VCL applications.
6. `vclgo_init("vclgo-fastpath")` bootstraps the app and permanent owners.
7. Cache passthrough state, allocate/emit the trampoline region, mark it RX,
   and install patches with `gum_memory_patch_code`.
8. Log the patch summary and return; `main()` starts.

The normal `exit_group` dispatch calls synchronous terminal teardown before
the raw syscall. The destructor is a backup. Ordinary socket close still
closes one VLS session. Terminal teardown abandons remaining native
records/surrogates, performs one bootstrap-owned application detach, and
parks owner pthreads until `exit_group`.

---

## 9. Two hard invariants that must never break

Every design choice above is subordinate to these two invariants.  When
either is violated, Go's runtime aborts with `unexpected return pc` or
`traceback did not unwind completely`.

### 9.1 The Go unwinder invariant

**No return address pointing into any anonymous mapping we allocate may
ever be live on any goroutine's stack.**

Go's `runtime.gentraceback` walks `%rbp`-chained frames (or DWARF-less
FDE data) on signal delivery.  Every PC it sees must resolve via
`runtime.findfunc` back into the `pclntab` — i.e., must be inside the
Go executable's `.text`.  Any PC in an anonymous mapping fails the
lookup and triggers a fatal.

This invariant is what killed the retired Frida-Interceptor.attach
approach, and also what killed our first attempt at a Syscall6 dispatch
tramp that used `call shim; jmp post`.  The current design (`push post;
jmp shim` for Syscall6, `jmp shim` for M2 sites) guarantees the invariant.

### 9.2 The goroutine-stack invariant

**C code must not consume more stack than is available on the goroutine
we were called from.**

Goroutine stacks start at ~2 KiB and grow only via Go's `morestack`
prologue.  Our C dispatcher can easily use 100 KiB descending into
VLS/VPP.  The naked `vclgo_dispatch` (§7) satisfies this by swapping
`%rsp` to a per-pthread 512 KiB disp stack before any real work.

---

## 10. Current boundaries and open work

- TCP and UDP data paths are implemented. Cut-through TCP
  payload/deadlines and routed UDP/HTTP have passed; a separate routed raw-TCP
  echo gate should still be automated.
- Heavy same-VPP local HTTP churn exposes a cut-through crash in the tested
  VPP branch. It is distinct from routed TCP behavior.
- An unrecognized wrapper prologue is logged and that wrapper is skipped
  instead of aborting. A multi-Go-version matrix is still required to prove
  the degradation behavior.
- `g_disp_*` counters exist but do not have a stable operational export.
- Multi-hour async-preemption, 100–1,000-goroutine, TLS/HTTP2/gRPC, and fault
  soaks have not been captured.
- Direct `LD_PRELOAD` is authoritative; launcher fastpath selection is open.
- The target container's executable-memory policy remains unvalidated.
- The raw kernel fallback helper currently carries five syscall arguments.
  Six-argument non-owned/passthrough syscalls require an explicit audit even
  though owned UDP `sendto`/`recvfrom` use the full six-argument dispatch.
- Accepted sessions remain on one listener owner; add listener sharding only
  if measurements require it.

See [`plan.md`](plan.md) for current gates and
[`test_topology.md`](test_topology.md) for test interpretation.

---

## 11. File map

| File                                              | Purpose |
|---------------------------------------------------|---------|
| `preload/fastpath/gum_vcl.c`                      | Current Approach #4 implementation |
| `preload/fastpath/gum_full.c`                     | M2 + M2.5 identity passthrough only |
| `preload/fastpath/gum_probe.c`                    | Site-scanner / diagnostic tool |
| `preload/fastpath/probe_sites.c`                  | Standalone ELF disassembler for site validation |
| `preload/fastpath/Makefile`                       | Builds all fastpath libs |
| `preload/fastpath/vendor/frida-gum-17.16.0/*`     | Vendored static frida-gum + Capstone |
| `dispatcher/include/vclgo.h`                      | POSIX-shaped `vclgo_XXX` API used by dispatch |
| `dispatcher/src/vclgo.c`, `*_native.c`            | vclgo_* implementations (VCL owner pool, surrogate FDs) |
| `test/run_smoke_fastpath.sh`                      | Same-VPP cut-through smoke |
| `test/run_concurrency_fastpath.sh`                | Same-VPP cut-through payload/deadline stress |
| `test/run_smoke_udp_fastpath.sh`                  | Configurable; routed UDP acceptance with two VPPs |
| `test/run_http_soak_fastpath.sh`                  | Configurable; routed HTTP acceptance with two VPPs |
| `docs/test_topology.md`                           | Authoritative topology contract |
