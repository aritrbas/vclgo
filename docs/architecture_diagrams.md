# Architecture diagram atlas

Last synchronized with code and tests: 2026-07-22.

This atlas visualizes the current native Frida-Gum fastpath. The narrative
design is [architecture.md](architecture.md), and exact machine-code examples
are [text_patching.md](text_patching.md).

## 1. End-to-end process topology

~~~mermaid
flowchart LR
    subgraph GP["Go process"]
        G["100+ goroutines"]
        M["Go runtime Ms<br/>ordinary pthreads"]
        X["Patched Go .text"]
        T["Near RX thunks<br/>shared shim"]
        DS["Per-M dispatcher stacks"]
        R["Exact fd registry"]
        F["Real socketpair fds"]

        subgraph OP["Permanent VCL owner pthreads"]
            O0["Owner 0"]
            O1["Owner 1"]
            O2["Owner 2"]
            O3["Owner 3"]
        end
    end

    G --> M --> X --> T --> DS --> R
    R --> O0 & O1 & O2 & O3
    O0 & O1 & O2 & O3 --> F
    F -->|"Linux epoll / Go netpoll"| M
    O0 & O1 & O2 & O3 --> VLS["VLS / VCL worker TLS"]
    VLS --> VPP["VPP main + dataplane/session workers"]
~~~

Goroutines may migrate across Ms. Sessions do not migrate across owners.
VPP worker selection is independent of both.

## 2. Constructor flow

~~~mermaid
flowchart TD
    L["Dynamic loader maps preload"] --> C["Run vclgo_gum_ctor"]
    C --> D{"VCLGO_DISABLE set?"}
    D -- yes --> R0["Return without discovery or VCL"]
    D -- no --> GI["gum_init_embedded"]
    GI --> MM["Find main executable"]
    MM --> TX["Find executable .text bounds"]
    TX --> CS["Capstone linear disassembly"]
    CS --> IS["Record immediate-NR SYSCALL sites"]
    TX --> WS["Resolve 3 Go wrapper symbols"]
    WS --> PV["Validate relocatable entry prologues"]
    IS --> ANY{"At least one valid path?"}
    PV --> ANY
    ANY -- no --> GD["Deinitialize Gum; no VPP registration"]
    ANY -- yes --> VI["vclgo_init"]
    VI --> OWN["Start and register permanent VCL owners"]
    OWN --> NEAR["Allocate two pages near .text as RW"]
    NEAR --> EMIT["Emit shared shim + site/wrapper thunks"]
    EMIT --> RX["Protect thunk mapping RX"]
    RX --> PT["Patch executable .text"]
    PT --> LOG["Log discovered/patched totals"]
    LOG --> DONE["Deinitialize Gum; return to Go startup"]
~~~

Production hardening must make any partial `PT` result fail closed or
select a tested all-kernel fallback.

## 3. Process virtual-memory layout

~~~text
low virtual addresses

0x00400000  +--------------------------------------------------+
            | Go executable ELF                                |
            | .text RX                                         |
            |   patched direct sites                            |
            |   patched Syscall6 wrapper entry                  |
            +--------------------------------------------------+

near .text  +--------------------------------------------------+
            | 8 KiB thunk allocation                           |
            | RW while emitted -> RX before patches run        |
            |   shared shim                                    |
            |   16-byte direct-site thunk slots                |
            |   64-byte wrapper trampoline slots               |
            +--------------------------------------------------+

            +--------------------------------------------------+
            | Go heap, goroutine stacks, runtime metadata       |
            +--------------------------------------------------+

            +--------------------------------------------------+
            | one 512 KiB RW MAP_STACK per entering OS thread   |
            | TLS g_disp_stack_top points near the top           |
            +--------------------------------------------------+

            +--------------------------------------------------+
            | native shared libraries                           |
            | libvclgo_gum_vcl.so                               |
            | libvclgo_dispatcher.so                            |
            | libvppcom.so                                      |
            +--------------------------------------------------+

high virtual addresses
~~~

## 4. Thunk-page allocation

For `N` immediate sites and `W` resolved wrappers:

~~~text
page + 0x000
  +--------------------------------------------------------------+
  | shared shim: 94 bytes used, 128 bytes reserved               |
  +--------------------------------------------------------------+ +0x080
  | immediate site 0: 16-byte slot                               |
  | immediate site 1: 16-byte slot                               |
  | ...                                                          |
  | immediate site N-1                                           |
  +--------------------------------------------------------------+ +0x080+16N
  | wrapper 0: 64-byte slot                                      |
  | wrapper 1: 64-byte slot                                      |
  | ...                                                          |
  | wrapper W-1                                                  |
  +--------------------------------------------------------------+
  | 0xcc padding                                                  |
  +--------------------------------------------------------------+ page+8192

allocation formula:
  required <= 128 + 256*16 + 3*64 = 4416 bytes
  allocated = 2 * native page size = normally 8192 bytes
~~~

Every direct `CALL rel32` and every `JMP rel32` is checked for signed
32-bit reachability. Allocation is requested within 1 GiB of the midpoint of
Go `.text`.

## 5. Direct immediate-site patch

### 5.1 Seven-byte site

~~~text
BEFORE — Go .text

address S
  b8 NN NN NN NN       mov $NR, %eax        5 bytes
  0f 05                syscall              2 bytes
address S+7
  original continuation

AFTER — same addresses, same footprint

address S
  e8 DD DD DD DD       call site_thunk      5 bytes
address S+5
  90 90                nop; nop              2 bytes
address S+7
  original continuation

site_thunk — near RX mapping, 16-byte slot

  b8 NN NN NN NN       mov $NR, %eax
  e9 SS SS SS SS       jmp shared_shim
  cc cc cc cc cc cc    padding
~~~

The call pushes `S+5`, a Go `.text` PC. The thunk adds no return address.
The shim returns to `S+5`, executes the NOPs, and reaches `S+7`.

### 5.2 Nine-byte site

~~~text
BEFORE
  48 c7 c0 NN NN NN NN    mov $NR, %rax     7 bytes
  0f 05                   syscall           2 bytes

AFTER
  e8 DD DD DD DD          call site_thunk   5 bytes
  90 90 90 90             nop x4            4 bytes
~~~

## 6. Generic Syscall6 wrapper patch

### 6.1 Original Go 1.26.1 bytes

~~~text
409540  49 89 f2                 mov %rsi, %r10
409543  48 89 fa                 mov %rdi, %rdx
409546  48 89 ce                 mov %rcx, %rsi
409549  48 89 df                 mov %rbx, %rdi
40954c  0f 05                    syscall
40954e  48 3d 01 f0 ff ff        cmp $-4095, %rax   <- post
~~~

### 6.2 Entry replacement

~~~text
409540  e9 DD DD DD DD           jmp Syscall6_thunk
409545  90                       nop
409546  original bytes remain but are skipped
~~~

Capstone selected a six-byte patch boundary: two complete three-byte
instructions.

### 6.3 Wrapper trampoline

~~~text
Syscall6_thunk, 29 bytes used in a 64-byte slot

  49 89 f2                     mov %rsi, %r10
  48 89 fa                     mov %rdi, %rdx
  48 89 ce                     mov %rcx, %rsi
  48 89 df                     mov %rbx, %rdi
  49 bb 4e 95 40 00 00 00
        00 00                  movabs $0x40954e, %r11
  41 53                        push %r11
  e9 SS SS SS SS               jmp shared_shim
~~~

~~~mermaid
flowchart LR
    E["Syscall6 entry"] --> J["JMP wrapper thunk"]
    J --> C["Recreate Go-to-Linux register moves"]
    C --> P["PUSH original Go post-SYSCALL PC"]
    P --> S["JMP shared shim"]
    S --> D["Native dispatch"]
    D --> RET["shim RET"]
    RET --> POST["Original Go errno/result block"]
    POST --> CALLER["Original Go caller"]
~~~

The wrapper-thunk mapping never becomes a return address. The synthetic
return is the original Go PC `0x40954e`.

## 7. Register conversion

~~~text
Go ABIInternal at Syscall6 entry

  rax = nr
  rbx = a0
  rcx = a1
  rdi = a2
  rsi = a3
  r8  = a4
  r9  = a5

             four MOV instructions
                       |
                       v

Linux syscall ABI at shared-shim entry

  rax = nr
  rdi = a0
  rsi = a1
  rdx = a2
  r10 = a3
  r8  = a4
  r9  = a5

             spill and marshal
                       |
                       v

SysV ABI for vclgo_dispatch(nr,a0,a1,a2,a3,a4,a5)

  rdi = nr
  rsi = a0
  rdx = a1
  rcx = a2
  r8  = a3
  r9  = a4
  [rsp argument slot] = a5
~~~

## 8. Shared-shim stack

~~~text
after PUSH RBP, alignment, and SUB $64

low addresses
  rsp+0x00  a0 spill
  rsp+0x08  a1 spill
  rsp+0x10  a2 spill
  rsp+0x18  a3 spill
  rsp+0x20  a4 spill
  rsp+0x28  a5 spill
  rsp+0x30  unused
  rsp+0x38  unused
  ...
  saved rbp
  Go .text return/continuation PC
high addresses
~~~

Before calling `vclgo_dispatch`, the shim pushes a5 as the seventh SysV
argument. `vclgo_dispatch` returns `__int128` in `rax:rdx`; the shim
restores its frame and returns through the original Go continuation.

## 9. Dispatcher stack switch

~~~mermaid
sequenceDiagram
    participant GS as Goroutine stack
    participant ND as Naked dispatcher
    participant TLS as Per-thread TLS
    participant DS as 512 KiB dispatcher stack
    participant C as vclgo_dispatch_impl

    GS->>ND: call with nr,a0..a5
    ND->>GS: save rbp and SysV argument registers
    ND->>TLS: obtain g_disp_stack_top
    alt first use on this OS thread
        TLS->>DS: mmap 512 KiB MAP_STACK
        DS-->>TLS: aligned top
    end
    ND->>DS: switch rsp; save old goroutine rsp
    ND->>C: call on dispatcher stack
    C-->>ND: rax:rdx
    ND->>GS: pop old rsp; restore rbp
    ND-->>GS: return
~~~

~~~text
Goroutine stack is parked              Active dispatcher stack

Go caller return PC                    +-------------------------+ high
Go post-SYSCALL PC                     | 128-byte cushion        |
shared-shim frame                      | saved goroutine rsp     |
return-to-shim PC                      | a5 SysV stack argument  |
naked-dispatch entry frame             | C dispatcher frames     |
                                       | request wait frames      |
                                       +-------------------------+ low
~~~

The deep VCL path runs only after the stack switch. First-use stack
allocation and a small fixed save frame occur before it, which is why
preemption/unwinder stress remains part of production validation.

## 10. Dispatch decision tree

~~~mermaid
flowchart TD
    E["nr,a0..a5"] --> EXIT{"nr == exit_group?"}
    EXIT -- yes --> TD["terminal VCL teardown"] --> KE["raw exit_group"]
    EXIT -- no --> SOCK{"nr == socket?"}
    SOCK -- yes --> ROUTE{"INET/INET6 and TCP/UDP?"}
    ROUTE -- yes --> VC["create VLS session + surrogate"]
    ROUTE -- no --> KR["raw kernel socket"]
    SOCK -- no --> OWN{"exact registry lookup of fd=a0"}
    OWN -- miss --> RAW["raw kernel syscall"]
    OWN -- hit --> OP{"translated operation?"}
    OP -- yes --> API["POSIX-shaped vclgo_* API"]
    OP -- rejected --> ERR["-EOPNOTSUPP or mapped errno"]
    OP -- no --> SUR["current raw syscall on surrogate<br/>production audit required"]
~~~

## 11. Session and registry memory

~~~text
4096 registry buckets

bucket[index(fd)]
  |
  +--> session record
         fd              public high-range socketpair fd
         signal_fd       owner-only socketpair fd
         vlsh            raw VLS handle
         owner           immutable owner number
         meta            family, datagram, listening, options
         bound_addr      cached local address
         connected_peer cached connected-UDP peer
         refs            atomic lifetime references
         closing         atomic close winner
         armed           owner VLS epoll interest mask
         notified        readiness encoded on surrogate
         trace[16]       readiness/operation diagnostic ring
         hash_next       bucket chain
         owner_next      owner-local session list
~~~

Registry membership is protected by a mutex. Request and close paths retain a
session reference before releasing that mutex.

### 11.1 Corruption-control map

| Corruption hazard | Memory/registers at risk | Current control | Residual proof obligation |
|---|---|---|---|
| Deep native frames on a small goroutine stack | Go stack, adjacent runtime state, unwind metadata | Naked dispatcher switches to a 512 KiB pthread-local stack before the C/VCL call graph | Long preemption/profiling soak |
| Anonymous trampoline PC during signal traceback | Go frame chain and GC/unwinder interpretation | Direct sites keep a Go return PC; Syscall6 uses `push Go-post-PC; jmp shim` | Go-version and signal-stress matrix |
| Go/Linux/SysV register confusion | Syscall arguments and Go return registers | Explicit tables and emitted moves; original Go result block remains authoritative | Unit tests for all six arguments and both return halves |
| Request freed while an owner uses it | Dispatcher-stack request, borrowed Go buffer pointers | Submitter waits for `done`; owner never retains the request after signaling | GC/preemption stress and injected cancellation |
| Session freed during read/write/close race | Heap session record, VLS handle, surrogate fds | Exact registry lookup retains `refs`; close removes first; final reference frees | Deterministic race/fault tests |
| VLS handle used under the wrong pthread TLS | VCL worker-local heap/TLS state | Immutable `session.owner`; every `vls_*` executes on that owner | Owner-affinity assertions and counters |
| Executable mapping left writable | Patched code and thunk bytes | Thunks are emitted RW and changed to RX before `.text` is redirected | Target-policy and mapping audit |
| Partial code patch | Mixed raw/redirected control flow | Counted and logged today | Still a P0 blocker: transactional install/rollback |

## 12. Goroutine, owner, and VPP-worker mapping

~~~mermaid
flowchart LR
    G1["Goroutine 1"] --> M1["Go M1"]
    G2["Goroutine 2"] --> M2["Go M2"]
    G3["Goroutine 3"] --> M1
    M1 & M2 --> REG["fd registry"]

    REG -->|"session A owner=0"| O0["VCL owner 0"]
    REG -->|"session B owner=1"| O1["VCL owner 1"]
    REG -->|"listener L owner=2"| O2["VCL owner 2"]
    O2 -->|"accepted L/1 owner=2"| O2
    O2 -->|"accepted L/2 owner=2"| O2

    O0 & O1 & O2 --> VLS["VLS worker-local state"]
    VLS --> VW0["VPP worker 0"]
    VLS --> VW1["VPP worker 1"]
~~~

There is no one-to-one mapping on either side. A session-to-owner relation is
fixed. VPP's session/transport placement is separate.

## 13. Synchronous owner request

~~~mermaid
sequenceDiagram
    participant G as Go goroutine / dispatcher stack
    participant R as Registry
    participant Q as Owner queue
    participant O as Owner pthread
    participant V as VLS

    G->>R: exact lookup(fd), refs++
    R-->>G: session(owner=i)
    G->>G: initialize native_request_t
    G->>Q: enqueue under queue mutex
    G->>G: condition wait
    O->>Q: dequeue
    O->>V: owner-local vls_* call
    V-->>O: rv or VPPCOM error
    O->>G: set rv/error/done; signal
    G->>R: refs--
    G->>G: destroy request and return
~~~

The request borrows application pointers only for this synchronous lifetime.
It is never retained after completion.

## 14. Surrogate fd and readiness memory

~~~text
socketpair(AF_UNIX, SOCK_STREAM | NONBLOCK | CLOEXEC)

       public endpoint A                    private endpoint B
       fd >= 0x000f0000                     owner only
  +---------------------------+       +---------------------------+
  | RX queue B -> A           |<------| send one byte             |
  | nonempty => EPOLLIN       |       | assert READ ready         |
  |                           |       |                           |
  | TX queue A -> B           |------>| drain bytes               |
  | capacity => EPOLLOUT      |       | assert WRITE ready        |
  +---------------------------+       +---------------------------+
          |
          +--> Linux epoll --> Go runtime netpoll
~~~

Initial state:

~~~text
B -> A receive queue empty       EPOLLIN false
A -> B send queue prefilled      EPOLLOUT false
~~~

VLS readable:

~~~text
owner sends token B -> A
  -> Linux marks A EPOLLIN
  -> Go wakes
  -> patched read(A) calls vls_read
  -> token state resets independently of application data
~~~

VLS writable:

~~~text
owner drains A -> B
  -> Linux gives A send capacity / EPOLLOUT
  -> Go wakes
  -> patched write(A) calls vls_write
  -> owner refills queue to suppress readiness until rearmed
~~~

## 15. Owner event loop

~~~mermaid
flowchart TD
    L["Owner loop"] --> B["Dequeue up to 128 requests"]
    B --> H["Execute nonblocking VLS handlers"]
    H --> EA{"EAGAIN / pending connect?"}
    EA -- yes --> ARM["Add or modify owner VLS epoll interest"]
    EA -- no --> DONE["Complete request"]
    ARM --> DONE
    DONE --> EP["vls_epoll_wait: up to 128 events, 1 ms"]
    EP --> EVT{"Event?"}
    EVT -- yes --> S["Resolve connect result and signal surrogate readiness"]
    EVT -- no --> POLL["Periodic connect-error and watchdog checks"]
    S --> POLL
    POLL --> STOP{"Stopping?"}
    STOP -- no --> L
    STOP -- yes --> Q["Cancel queue, quiesce, terminal detach/park"]
~~~

## 16. TCP connect

~~~mermaid
sequenceDiagram
    participant G as net.Dial goroutine
    participant O as Session owner
    participant V as VLS
    participant S as Surrogate
    participant N as Go netpoll

    G->>O: connect(fd, peer)
    O->>V: vls_connect nonblocking
    alt connected
        V-->>O: 0
        O-->>G: 0
    else pending
        V-->>O: EAGAIN/EINPROGRESS
        O->>V: arm EPOLLOUT
        O-->>G: EINPROGRESS
        G->>N: wait for writable fd
        V-->>O: VLS event or polled error
        O->>S: assert WRITE readiness
        S-->>N: EPOLLOUT
        N-->>G: wake
        G->>O: getsockopt(SO_ERROR)
        O-->>G: connect result
    end
~~~

## 17. TCP listen and accept

~~~mermaid
flowchart TD
    L["listener owner i"] --> A["vls_accept(O_NONBLOCK)"]
    A --> R{"result"}
    R -- child --> C["create child surrogate"]
    C --> SAME["child.owner = i"]
    R -- EAGAIN --> ARM["arm listener EPOLLIN"]
    ARM --> GO["return EAGAIN; Go netpoll waits"]
    EVT["VLS listener readable"] --> SIG["assert surrogate READ"]
    SIG --> GO2["Go retries accept"]
~~~

One listener's children do not round-robin across owners.

## 18. UDP flows

### 18.1 Connected UDP

~~~mermaid
sequenceDiagram
    participant G as net.DialUDP
    participant O as Owner
    participant V as VLS

    G->>O: socket(SOCK_DGRAM)
    G->>O: connect(peer)
    O->>V: get flags
    O->>V: clear O_NONBLOCK
    O->>V: vls_connect(peer)
    O->>V: restore flags
    O->>O: cache peer sockaddr
    G->>O: write(payload)
    O->>V: vls_write / connected send
    G->>O: read(reply)
    O->>V: vls_read / connected receive
~~~

### 18.2 Unconnected UDP

~~~mermaid
sequenceDiagram
    participant G as net.PacketConn
    participant O as Owner
    participant V as VLS

    G->>O: bind(local address, possibly port 0)
    O->>O: choose ephemeral port if requested
    G->>O: sendto(payload, destination)
    O->>V: vls_sendto(payload, converted endpoint)
    G->>O: recvfrom(buffer)
    O->>V: vls_recvfrom(buffer, endpoint output)
    V-->>O: payload + actual sender
    O-->>G: payload + converted sender sockaddr
~~~

Each datagram retains its own boundary and peer address.

## 19. HTTP over TCP

~~~mermaid
flowchart LR
    HC["Go http.Client"] --> TR["http.Transport"]
    TR --> TCP["net.TCPConn"]
    TCP --> FP["Fastpath TCP path"]
    FP --> VPP["Routed VPP TCP"]
    VPP --> HS["Go http.Server"]

    KA["Keep-alive mode"] --> REUSE["Reuse ~CONC persistent TCP sessions"]
    NK["No-keep-alive mode"] --> CHURN["Connect/accept/close for every request"]
~~~

HTTP does not bypass or extend VCL. It is a higher-level workload that
exercises the TCP implementation through Go's standard transport.

## 20. Close race

~~~mermaid
sequenceDiagram
    participant R as Read/write request
    participant C as Close request
    participant REG as Registry/refcount
    participant O as Owner

    R->>REG: lookup; refs++
    C->>REG: atomically set closing; remove entry
    par in-flight operation
        R->>O: operation already retained
        O-->>R: result/error
        R->>REG: refs--
    and close
        C->>O: disarm and vls_close
        O-->>C: close complete
        C->>REG: refs--
    end
    REG->>REG: free only after final reference
~~~

New lookups fail after registry removal; retained operations cannot observe a
freed session record.

## 21. Terminal teardown

~~~mermaid
stateDiagram-v2
    [*] --> UNINIT
    UNINIT --> PASSTHROUGH: VCL_CONFIG absent
    UNINIT --> INITIALIZING: VCL_CONFIG present
    INITIALIZING --> ACTIVE: owners ready
    INITIALIZING --> UNINIT: initialization failed
    ACTIVE --> STOPPING: exit_group / teardown
    STOPPING --> STOPPED: queues canceled and app detached
    PASSTHROUGH --> [*]
    STOPPED --> [*]
~~~

~~~mermaid
flowchart TD
    E["exit_group intercepted"] --> N["Stop new submissions"]
    N --> C["Cancel queued requests"]
    C --> Q["Quiesce owner loops"]
    Q --> A["Abandon remaining native records/surrogates"]
    A --> D["Bootstrap owner: one vppcom_app_destroy"]
    D --> P["Owners park"]
    P --> K["Raw kernel exit_group"]
~~~

## 22. Validation topologies

### 22.1 Same-VPP cut-through

~~~mermaid
flowchart LR
    C["Go client<br/>4 VCL owners"] --> V["One VPP<br/>2 workers"]
    S["Go server<br/>4 VCL owners"] --> V
    C -. "VCL shared-memory local transport<br/>no TCP/UDP packet graph" .-> S
~~~

### 22.2 Routed acceptance

~~~mermaid
flowchart LR
    C["Go client<br/>4 owners"] --> B["VPP B<br/>2 workers<br/>10.77.0.2"]
    B <-->|"memif TCP segments / UDP datagrams"| A["VPP A<br/>2 workers<br/>10.77.0.1"]
    A --> S["Go server<br/>4 owners"]
~~~

See [test_topology.md](test_topology.md) for commands and claim boundaries.

## 23. Failure and production-gap map

| Boundary | Current detection | Required production behavior |
|---|---|---|
| No Go-shaped code | Constructor log and no VCL init | Retain |
| Unsafe wrapper prologue | Log and skip | Fail closed or validated compatibility mode |
| Individual patch failure | Count mismatch in log | Abort/rollback or all-kernel mode |
| Near allocation failure | Constructor returns | Explicit teardown and deterministic fallback |
| VCL owner startup failure | Initialization error | No patches; clear fatal/fallback policy |
| Six-argument raw syscall | Not fully carried | Fix helper and add ABI tests |
| Unknown syscall on owned fd | Raw operation on surrogate | Explicit translate or reject |
| Owner queue saturation | Limited logs/watchdog | Counters, latency, queue depth, alerting |
| Listener concentration | Architectural | Shard/listen strategy and measurements |
| Go wrapper changes | Runtime discovery log | Supported-version matrix and CI |
| Signal/preemption stack regression | Crash signature | Multi-hour stress gate |
| VPP loss/restart | Application error | Defined recovery/failure contract |

## 24. Source map

~~~text
preload/fastpath/gum_vcl.c
  discovery
  direct-site and wrapper patch emitters
  shared ABI shim
  dispatcher stack switch
  syscall routing and kernel-shaped return

dispatcher/src/lifecycle_native.c
  state machine and VCL application lifetime

dispatcher/src/api_native.c
  POSIX-shaped public calls

dispatcher/src/pool_native.c
  permanent owners
  request queues
  every vls_* operation
  VLS epoll
  TCP and UDP semantics

dispatcher/src/registry_native.c
  exact fd map
  refcounts
  socketpair surrogate
  readiness state
~~~
