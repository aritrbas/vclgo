# Go text patching, thunks, ABI bridge, and memory layout

Last verified: 2026-07-22 on Go 1.26.1, Linux/amd64.

This document describes the exact machine-code transformation performed by
`preload/fastpath/gum_vcl.c`. Addresses below come from the freshly built
`bin/examples/echo_client`; addresses and relative displacements are
build-specific, but the instruction shapes and invariants are the contract.

## 1. Constructor pipeline

~~~mermaid
flowchart TD
    C["ELF loader runs preload constructor"] --> G["gum_init_embedded"]
    G --> M["Locate main module and executable .text"]
    M --> D["Capstone-disassemble .text"]
    D --> I["Record immediate-NR SYSCALL sites"]
    M --> W["Resolve and validate generic Go syscall wrappers"]
    I --> N{"Any patchable Go path?"}
    W --> N
    N -- no --> X["Deinitialize Gum; do not register with VPP"]
    N -- yes --> V["Initialize VCL and permanent owner pool"]
    V --> A["Allocate 8 KiB near executable .text as RW"]
    A --> E["Emit shared shim and per-site/wrapper thunks"]
    E --> R["Change thunk mapping from RW to RX"]
    R --> P["Patch Go .text through gum_memory_patch_code"]
    P --> H["Return to Go startup"]
~~~

The current hard limits are:

| Item | Limit |
|---|---:|
| Immediate syscall sites | 256 |
| Shared shim reservation | 128 bytes |
| Immediate-site thunk | 16 bytes |
| Generic-wrapper thunk | 64 bytes |
| Near-allocation distance | 1 GiB from the midpoint of `.text` |
| Thunk allocation | Two native pages, normally 8192 bytes |

The 256-site bound is now fail-closed: discovery reports immediate-pattern
misses separately from capacity overflow, and any overflow aborts before VCL
initialization. No site beyond the table is silently left on the kernel path.

The executable `.text` is never modified on disk. Only the process-private
mapping is patched.

## 2. Installed virtual-memory layout

For the verified Go 1.26.1 echo client, the original ELF has:

~~~text
main executable
  .text        0x00401000 .. 0x00509511   RX
  .rodata      0x0050a000 ..              R
  Go data/BSS  0x0065a000 ..              RW

shared libraries
  libvclgo_gum_vcl.so                     RX/RW mappings
  libvclgo_dispatcher.so                  RX/RW mappings
  libvppcom.so and VPP dependencies

near thunk allocation, chosen at runtime
  page + 0x000 .. 0x07f   shared shim, 94 bytes used
  page + 0x080 ..         16-byte immediate-site thunk slots
  following slots         64-byte generic-wrapper thunk slots
  unused bytes            0xcc
  final protection        RX

per Linux OS thread that enters the dispatcher
  anonymous MAP_STACK mapping             RW, 512 KiB

per VCL session
  native session record                   C heap
  public surrogate fd                     kernel AF_UNIX socket
  private signal fd                       kernel AF_UNIX socket
  VLS handle                              owner-pthread-local VLS state
~~~

The constructor first emits while the near mapping is writable and then calls
`gum_mprotect(..., GUM_PAGE_RX)`. The final thunk mapping is not writable and
executable at the same time.

## 3. Patch family A: immediate syscall sites

The scanner recognizes a `SYSCALL` immediately preceded by either:

~~~asm
mov imm32, %eax
syscall
~~~

or:

~~~asm
mov imm32, %rax
syscall
~~~

The first shape occupies seven bytes. The second occupies nine bytes because
the sign-extending `mov r/m64, imm32` encoding is seven bytes. The encoding
choice is made by the Go assembler; it is not evidence that the syscall
number itself needs 64 bits.

### 3.1 Seven-byte concrete example

Before patching, Go 1.26.1 `runtime.write1.abi0` contains:

~~~text
address   bytes                 instruction
48946e    b8 01 00 00 00        mov $1, %eax
489473    0f 05                 syscall
489475    89 44 24 20           mov %eax, 0x20(%rsp)
~~~

The scanner records:

~~~text
patch_start = 0x48946e
mov_len     = 5
syscall_nr  = 1
patch_len   = mov_len + 2 = 7
~~~

After patching:

~~~text
address   bytes                 instruction
48946e    e8 dd dd dd dd        call immediate_thunk
489473    90 90                 nop; nop
489475    89 44 24 20           original post-syscall instruction
~~~

`dd dd dd dd` is the signed little-endian `rel32` displacement selected at
runtime. The call pushes `0x489473`, which is still a valid Go `.text`
address. When dispatch returns, the CPU executes the two NOP bytes and resumes
at the original post-syscall instruction.

The associated 16-byte thunk is:

~~~text
b8 01 00 00 00                 mov $1, %eax
e9 ss ss ss ss                 jmp shared_shim
cc cc cc cc cc cc              unused slot bytes
~~~

The thunk uses `jmp`, not `call`, so it does not add an anonymous-thunk
return PC to the stack.

### 3.2 Nine-byte concrete example

Before patching, `runtime.nanotime1.abi0` contains:

~~~text
address   bytes                       instruction
4896c5    48 c7 c0 e4 00 00 00        mov $228, %rax
4896cc    0f 05                       syscall
4896ce    eb bd                       jmp 0x48968d
~~~

After patching:

~~~text
4896c5    e8 dd dd dd dd              call immediate_thunk
4896ca    90 90 90 90                 four NOP bytes
4896ce    eb bd                       original continuation
~~~

The thunk normalizes the syscall number to `mov imm32, %eax`, which is
equivalent for the supported Linux syscall-number range.

## 4. Patch family B: generic Go Syscall6 wrapper

Many standard-library network calls do not contain an immediate syscall
number beside their `SYSCALL`. They call
`internal/runtime/syscall/linux.Syscall6` with the number in `%rax`.

### 4.1 Original Go 1.26.1 wrapper

~~~text
409540  49 89 f2                 mov %rsi, %r10
409543  48 89 fa                 mov %rdi, %rdx
409546  48 89 ce                 mov %rcx, %rsi
409549  48 89 df                 mov %rbx, %rdi
40954c  0f 05                    syscall
40954e  48 3d 01 f0 ff ff        cmp $-4095, %rax
409554  76 15                    jbe success
409556  48 f7 d8                 neg %rax
409559  48 89 c1                 mov %rax, %rcx
40955c  48 c7 c0 ff ff ff ff     mov $-1, %rax
409563  48 c7 c3 00 00 00 00     mov $0, %rbx
40956a  c3                       ret
40956b  48 89 d3                 mov %rdx, %rbx
40956e  48 c7 c1 00 00 00 00     mov $0, %rcx
409575  c3                       ret
~~~

On entry, this Go wrapper uses:

| Value | Go ABIInternal register |
|---|---|
| syscall number | `rax` |
| a0 | `rbx` |
| a1 | `rcx` |
| a2 | `rdi` |
| a3 | `rsi` |
| a4 | `r8` |
| a5 | `r9` |

The first four instructions convert those registers to Linux's syscall ABI.

### 4.2 Entry detour

Capstone validates whole instructions until at least five bytes can be
overwritten. For this build, the first two instructions consume six bytes:

~~~text
before
409540  49 89 f2 48 89 fa        two complete MOV instructions

after
409540  e9 dd dd dd dd 90        jmp Syscall6_thunk; nop
409546  48 89 ce ...             bytes remain, but the thunk skips them
~~~

The constructor also locates the end of the original `SYSCALL`:

~~~text
post = wrapper_entry + syscall_off
     = 0x409540 + 14
     = 0x40954e
~~~

The wrapper is rejected if the initial instructions contain a relative
branch, a call/return, an interrupt instruction, or RIP-relative memory.

### 4.3 Syscall6 thunk

The 29-byte thunk recreates all four argument moves, installs a Go `.text`
continuation as a synthetic return address, and jumps to the shared shim:

~~~asm
mov %rsi, %r10                 # a3
mov %rdi, %rdx                 # a2
mov %rcx, %rsi                 # a1
mov %rbx, %rdi                 # a0
movabs $0x40954e, %r11         # original post-SYSCALL Go PC
push %r11
jmp shared_shim
~~~

For the verified binary, its fixed prefix is:

~~~text
49 89 f2 48 89 fa 48 89 ce 48 89 df
49 bb 4e 95 40 00 00 00 00 00
41 53 e9
~~~

The final four bytes following `e9` are the runtime-specific relative
displacement to the shared shim.

The deliberate `push post; jmp shim` sequence means the wrapper thunk itself
never appears as a return address:

~~~text
goroutine stack after push

low addresses
  rsp -> 0x40954e          original Go result-conversion block
         caller return PC  original Go caller
high addresses
~~~

When the shared shim eventually executes `ret`, it returns directly to
`0x40954e`. The original Go code then maps the kernel-shaped result into
Go's `(r1, r2, errno)` result registers.

## 5. Identity wrapper thunks

Two additional wrappers are resolved and entry-detoured:

- `syscall.rawSyscallNoError.abi0`;
- `syscall.rawVforkSyscall.abi0`.

For each, Capstone copies a safe whole-instruction prologue into a 64-byte
slot and appends a relative jump to `entry + prologue_len`. These are
identity detours: they do not enter the VCL dispatcher. Their purpose is to
preserve the expected instruction path while the generic wrapper set is
patched consistently.

## 6. Shared shim: Linux syscall ABI to SysV C ABI

Both patch families reach the shared shim with Linux syscall state:

| Register | Meaning |
|---|---|
| `rax` | syscall number |
| `rdi` | a0 |
| `rsi` | a1 |
| `rdx` | a2 |
| `r10` | a3 |
| `r8` | a4 |
| `r9` | a5 |

The shim creates a small fixed frame and spills the six arguments:

~~~text
after push rbp, align rsp, sub 64

rsp+0x00  a0 from rdi
rsp+0x08  a1 from rsi
rsp+0x10  a2 from rdx
rsp+0x18  a3 from r10
rsp+0x20  a4 from r8
rsp+0x28  a5 from r9
rsp+0x30  unused/alignment
rsp+0x38  unused/alignment
~~~

It then builds the SysV call
`vclgo_dispatch(nr, a0, a1, a2, a3, a4, a5)`:

| C argument | SysV location |
|---|---|
| nr | `rdi` |
| a0 | `rsi` |
| a1 | `rdx` |
| a2 | `rcx` |
| a3 | `r8` |
| a4 | `r9` |
| a5 | first stack argument |

SysV preserves only callee-saved registers. The C call may clobber
`rcx`, `rdi`, `rsi`, `r8`–`r11`, and other caller-saved state.
The generic Syscall6 return block consumes only `rax:rdx` before producing
its Go results. For immediate-number sites, the continuation must likewise
not depend on an argument register that the kernel would normally preserve
but a C call may clobber. The current scanner recognizes instruction shape;
it does not prove post-syscall register liveness. That proof or explicit
save/restore is required for each supported Go version.

The current emitted shim is 94 bytes. It calls the naked
`vclgo_dispatch`, which performs the stack switch before calling the normal
C implementation.

## 7. Dispatcher-stack switch

A goroutine stack grows only at Go-generated stack checks. Native C entered
through a patched instruction has no such check. Deep C, VLS, or VPP frames
must therefore not consume the goroutine stack.

Each Linux OS thread lazily receives a 512 KiB anonymous dispatcher stack:

~~~text
mapping base
  +---------------------------------------------------------------+
  | RW MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK                    |
  |                                                               |
  |                    512 KiB                                    |
  |                                                               |
  +---------------------------------------------------------------+
                                      aligned top - 128 byte cushion
~~~

The naked dispatcher:

1. saves its frame pointer and the six SysV argument registers;
2. obtains the per-thread stack top from TLS, allocating it on first use;
3. restores the argument registers;
4. saves the goroutine-stack `rsp` on the new stack;
5. moves `rsp` to the new stack;
6. pushes a5 and calls `vclgo_dispatch_impl`;
7. restores the old `rsp` with `pop %rsp`;
8. returns `rax:rdx` unchanged.

~~~text
goroutine stack                         dispatcher stack

wrapper caller return PC                high address
Go post-SYSCALL PC                         128-byte cushion
shared-shim frame                          saved goroutine rsp
return-to-shim PC              <switch>    a5
vclgo_dispatch entry frame                 C dispatcher frames
                                            VCL submission/wait frames
                                         low address
~~~

The fixed pre-switch frame is intentionally small. The deep path starts only
after `rsp` points into the dedicated mapping.

## 8. Dispatcher result mapping

The VCL-facing APIs use POSIX convention:

~~~text
success: rv >= 0
failure: rv == -1 and vclgo_errno() contains a positive errno
~~~

`posix_to_kernel` converts this to the convention expected immediately
after a Linux `SYSCALL`:

~~~text
success: rax = rv,     rdx = 0
failure: rax = -errno, rdx = 0
~~~

The C dispatcher returns `__int128`, so SysV places the low half in `rax`
and the high half in `rdx`.

The original Go Syscall6 result block then performs:

~~~text
kernel-style input             Go ABIInternal output

rax >= -4095? no               rax = result
                               rbx = rdx/result2
                               rcx = 0

rax in [-4095, -1]? yes        rcx = -rax (positive errno)
                               rax = -1
                               rbx = 0
~~~

This is why the implementation returns to the original Go wrapper after the
dispatch instead of inventing a second Go-return ABI.

## 9. Owner-request and session memory

The ABI dispatcher does not call VLS on the goroutine's current runtime
thread. A public `vclgo_*` call creates a synchronous request on the
dedicated dispatcher stack:

~~~text
request object
  operation enum
  retained session pointer
  scalar syscall arguments
  caller buffer/address pointers
  result and errno fields
  mutex + condition variable + done flag
  queue link
~~~

~~~mermaid
sequenceDiagram
    participant G as Go goroutine on runtime M
    participant D as Dispatcher stack on same M
    participant Q as Owner queue
    participant O as Permanent VCL owner pthread
    participant V as VLS/VCL

    G->>D: patched syscall
    D->>Q: enqueue synchronous request
    D->>D: wait on request condition
    O->>Q: dequeue request
    O->>V: vls_* using owner-local TLS
    V-->>O: result or VPPCOM_EAGAIN
    O->>O: arm owner VLS epoll when needed
    O-->>D: result + errno; signal condition
    D-->>G: kernel-shaped rax:rdx
~~~

The caller does not destroy the request until the owner sets `done`. The
session registry holds a reference while the request is in flight, and only
the recorded owner may use or close the raw VLS handle.

Each registered session maps:

~~~text
public fd in reserved range 0x000f0000 .. 0x000fffff
        |
        v
registry bucket -> session record
                    fd            public socketpair endpoint
                    signal_fd     private owner endpoint
                    vlsh          raw VLS handle
                    owner         permanent owner index
                    refs          lifetime references
                    closing       close arbitration
                    armed         VLS epoll interest
                    notified      readiness encoded on socketpair
~~~

## 10. Patch safety and failure policy

`gum_memory_patch_code` performs each executable-text update through
Frida-Gum's platform patching mechanism and instruction-cache synchronization.
The implementation validates whole instructions before an entry detour and
checks every relative displacement fits in signed 32 bits.

Current fail-open behavior must be understood:

- an unrecognized wrapper is logged and skipped;
- a failed individual site patch is counted but does not abort startup;
- there is no rollback after a partial patch set;
- failure after VCL initialization but before `g_did_patch` can leave
  initialization cleanup dependent on process termination.

One former partial-patch case is closed: exceeding
`VCLGO_MAX_M2_SITES` reports `overflow=N` and refuses the entire patch before
VCL initialization. The remaining cases above still require transactional
preflight/rollback.

Production promotion requires a fail-closed policy or an explicit,
well-tested compatibility fallback.

## 11. Six-argument raw fallback

The shared shim, owned UDP path, and raw fallback all carry a0 through a5.
`raw_syscall6` explicitly binds the final argument to Linux `%r9`:

~~~text
C input                 Linux SYSCALL input
nr                      rax
a0, a1, a2              rdi, rsi, rdx
a3, a4, a5              r10, r8, r9
~~~

This is important beyond UDP. The scanner patches runtime calls such as
`runtime.sysMmap.abi0`, and `mmap` uses a5 for its file offset. The fastpath
smoke now maps the second page of a two-page file with a nonzero a5 and
verifies its bytes both while VCL is active (the mapping fd is unowned) and
with `VCL_CONFIG` unset in pure passthrough mode. That regression would fail
if `%r9` were omitted.

## 12. Reproducing the examples

~~~bash
make build-fastpath \
  VPP_PREFIX=/home/aritrbas/vpp/vpp/build-root/install-vpp-native/vpp

go version
go tool objdump \
  -s 'internal/runtime/syscall/linux.Syscall6' \
  bin/examples/echo_client

objdump -d bin/examples/echo_client |
  grep -B1 -A2 '0f 05'
~~~

At runtime, the constructor prints discovered counts, wrapper addresses, and
successful patch totals. The emitted Syscall6 bytes are printed only when
`VCLGO_FASTPATH_TRACE` is set. Acceptance logs must show zero overflow and
every discovered site and resolved wrapper patched:

~~~text
[vclgo/gum] M2: disasm=39 patchable=36 non-immediate=3 overflow=0
[vclgo/gum] patched M2:36/36 wrappers:3/3
~~~
