# vclgo architecture

Last synchronized with code and tests: 2026-07-23.

This document specifies the current native Frida-Gum fastpath from Go
`.text` patching through VCL/VLS and multi-worker VPP. Exact instruction
bytes and stack offsets are in [text_patching.md](text_patching.md); visual
variants of the flows below are in
[architecture_diagrams.md](architecture_diagrams.md).

## 1. Goals and boundaries

The implementation is designed to:

- run an unmodified dynamically linked Linux/amd64 Go executable;
- preserve the standard `net`, `net/http`, epoll/netpoll, and deadline
  behavior visible to the application;
- route `AF_INET` and `AF_INET6` TCP/UDP sockets through VCL/VLS;
- support many goroutines without binding goroutines to Linux threads;
- use several permanent VCL owner pthreads with VLS multi-worker mode;
- work with a multi-worker VPP;
- keep raw VLS handles and VCL thread-local state away from Go runtime
  threads.

It is not a complete Linux socket ABI. Unsupported operations and the
production gates are listed in [status.md](status.md).

## 2. Component model

~~~mermaid
flowchart TB
    subgraph GO["Unmodified Go process"]
        APP["Application<br/>net / net/http"]
        WRAP["Go syscall wrappers"]
        PATCH["Patched executable .text"]
        THUNK["Near RX thunk mapping"]
        STACK["Per-OS-thread dispatcher stack"]
        API["POSIX-shaped vclgo API"]
        REG["Exact fd registry"]
        SUR["AF_UNIX socketpair surrogates"]

        subgraph OWN["Permanent owner pthread pool"]
            O0["Owner 0<br/>VCL worker 0"]
            O1["Owner 1<br/>VCL worker 1"]
            ON["Owner N<br/>VCL worker N"]
        end
    end

    APP --> WRAP --> PATCH --> THUNK --> STACK --> API
    API --> REG
    API --> O0 & O1 & ON
    O0 & O1 & ON --> SUR
    SUR -->|"epoll readiness"| WRAP
    O0 & O1 & ON --> VLS["VLS / VCL"]
    VLS --> VPP["VPP session and dataplane workers"]
~~~

| Component | Implementation | Responsibility |
|---|---|---|
| Preload constructor | `preload/fastpath/gum_vcl.c` | Discover Go syscall paths, allocate thunks, patch `.text`, initialize VCL |
| Shared ABI shim | Emitted by `gum_vcl.c` | Marshal Linux syscall registers to SysV C ABI |
| Dispatcher stack | TLS pointer in `gum_vcl.c` | Keep native C/VCL stack use off the goroutine stack |
| Public socket API | `dispatcher/src/api_native.c` | POSIX return values and ownership gates |
| Owner pool | `dispatcher/src/pool_native.c` | Execute every raw `vls_*` call on the correct pthread |
| Registry/surrogate | `dispatcher/src/registry_native.c` | Map a real fd to one VLS session and encode readiness |
| Lifecycle | `dispatcher/src/lifecycle_native.c` | Passthrough/active state, worker creation, terminal teardown |

## 3. Initialization

The ELF loader invokes the preload constructor before Go `main`.

~~~mermaid
sequenceDiagram
    participant L as ELF loader
    participant P as Fastpath constructor
    participant G as Frida-Gum / Capstone
    participant D as Dispatcher lifecycle
    participant O as Owner pthreads
    participant V as VCL / VPP

    L->>P: constructor
    P->>G: inspect main executable .text
    G-->>P: direct sites + generic wrappers
    alt no Go-shaped patch path
        P-->>L: return without VCL registration
    else patch path exists
        P->>D: vclgo_init
        D->>O: create permanent owners
        O->>V: bootstrap app and register VCL workers
        V-->>O: VLS mode / worker status
        O-->>D: ready
        P->>G: allocate near RW mapping
        P->>P: emit shim and thunks
        P->>G: protect mapping RX and patch .text
        P-->>L: return to Go startup
    end
~~~

Initialization ordering matters:

1. Discovery occurs before VPP registration so a non-Go helper inheriting
   `LD_PRELOAD` does not consume a VPP application slot.
2. All requested owner pthreads must be registered before the pool accepts a
   socket request.
3. The near mapping becomes RX before any patched entry can target it.
4. An immediate-site table overflow aborts before VCL initialization. Patch
   totals are logged, but unresolved wrappers and individual patch-write
   failures are not yet transactional; that remaining partial-patch case is a
   production blocker.

With `VCLGO_WORKERS > 1`, the VCL configuration must enable
`multi-thread-workers`. Owner 0 bootstraps the VCL application; the other
owners register as VCL workers before entering their event loops.

## 4. Interception and ABI path

Go normally performs raw syscalls without calling libc, so symbol
interposition on `read`, `write`, or `connect` is insufficient.
The fastpath patches two classes of executable code:

- immediate-number sites containing `mov $NR, %eax|%rax; syscall`;
- the entry of `internal/runtime/syscall/linux.Syscall6`.

Immediate sites call a 16-byte per-site thunk that restores the syscall
number and jumps to the shared shim. The generic wrapper jumps to a 64-byte
trampoline that recreates Go's register moves, pushes the original
post-`SYSCALL` Go PC, and jumps to the same shim.

~~~text
Go wrapper or direct runtime site
  -> patched CALL/JMP in Go .text
  -> near thunk
  -> shared shim
  -> naked vclgo_dispatch
  -> switch rsp to 512 KiB dispatcher stack
  -> vclgo_dispatch_impl(nr, a0, a1, a2, a3, a4, a5)
~~~

The exact original bytes, replacement bytes, thunk bytes, register tables,
stack diagrams, and return path are documented in
[text_patching.md](text_patching.md).

## 5. Dispatch decision

`vclgo_dispatch_impl` receives the syscall number and all six Linux syscall
arguments.

~~~mermaid
flowchart TD
    E["dispatch(nr, a0..a5)"] --> X{"exit_group?"}
    X -- yes --> TD["terminal vclgo_teardown"] --> RK["raw kernel exit_group"]
    X -- no --> CR{"close_range()?"}
    CR -- yes --> CU{"active VCL + UNSHARE?"}
    CU -- yes --> CER["-EOPNOTSUPP"]
    CU -- no --> CP["close exact VCL owners<br/>or retain for CLOEXEC"] --> RCR["raw kernel close_range"]
    CR -- no --> S{"socket()?"}
    S -- yes --> F{"AF_INET/AF_INET6<br/>TCP or UDP?"}
    F -- yes --> VS["vclgo_socket"]
    F -- no --> RS["raw kernel socket"]
    S -- no --> O{"a0 exactly registered<br/>as VCL-owned fd?"}
    O -- no --> R["raw kernel syscall"]
    O -- yes --> K{"translated syscall?"}
    K -- yes --> V["vclgo_* operation"]
    K -- explicit reject --> ER["kernel-shaped -errno"]
    K -- no --> U["current raw syscall on surrogate fd"]
~~~

Socket creation is routed only for:

| Domain | Type | Protocol |
|---|---|---|
| `AF_INET`, `AF_INET6` | `SOCK_STREAM` | 0 or `IPPROTO_TCP` |
| `AF_INET`, `AF_INET6` | `SOCK_DGRAM` | 0 or `IPPROTO_UDP` |

For every fd-first syscall, range membership is only a quick rejection. The
registry must contain an exact live entry before the fd is considered owned.

### 5.1 Explicitly translated operations

| Syscall | Dispatcher behavior |
|---|---|
| `socket` | Create TCP/UDP VLS session and surrogate |
| `bind` | Convert sockaddr and call owner-local `vls_bind` |
| `listen` | Owner-local `vls_listen` |
| `accept`, `accept4` | Nonblocking owner-local accept and child surrogate |
| `connect` | TCP async connect or synchronous connected-UDP setup |
| `read`, `write` | Owner-local VLS data operation |
| `readv`, `writev` | Bounded iovec loops over VCL reads/writes |
| `sendfile` | `pread` a regular kernel input file and write to VCL; advance offsets by bytes actually sent |
| `sendto`, `recvfrom` | Per-datagram endpoint-aware UDP path |
| `sendmsg`, `recvmsg` | Limited iovec/name translation; no full control-message support |
| `shutdown` | Owner-local `vls_shutdown` |
| `getsockname`, `getpeername` | VLS attributes or cached UDP peer |
| `setsockopt`, `getsockopt` | Supported option-to-VLS mappings |
| `close` | Owner-serialized VLS/session/surrogate close |
| `close_range` | Close exact VCL sessions before kernel range close; retain sessions for `CLOEXEC`; reject `UNSHARE` while VCL is active |

`dup`, `dup2`, `dup3`, `F_DUPFD`, and `F_DUPFD_CLOEXEC` are
explicitly rejected with `EOPNOTSUPP`.

The current default for an unrecognized syscall on an owned descriptor is a
raw kernel syscall against the surrogate. That is correct only for operations
whose intended semantics are genuinely properties of the surrogate, such as
selected fd flags. It is not generally correct for data-plane operations and
must become an explicit translate/reject table before production.

## 6. Result conversion

Dispatcher APIs return POSIX-style results:

~~~text
success: nonnegative value
failure: -1, with vclgo_errno() containing positive errno
~~~

The fastpath converts failure to Linux's post-`SYSCALL` convention:

~~~text
rax = -errno
rdx = 0
~~~

It returns a C `__int128`, which places the low 64 bits in `rax` and high
64 bits in `rdx`. The original Go Syscall6 result block then produces its
normal `(r1, r2, errno)` values:

| Dispatcher outcome | Go-visible result |
|---|---|
| `rv >= 0` | `r1=rv, r2=0, errno=0` |
| `rv=-1, errno=E` | `r1=-1, r2=0, errno=E` |

Raw fallback is intended to preserve the kernel's `rax:rdx`. The current
helper does not carry a5 and is therefore incomplete for six-argument
syscalls; see [status.md](status.md).

## 7. Permanent session ownership

VCL/VLS worker state is pthread-local. A goroutine, however, may execute on a
different Go runtime M after any scheduling point. A raw VLS handle therefore
cannot follow a goroutine.

The owner transformation is:

~~~text
arbitrary goroutine / arbitrary Go M
        |
        | synchronous request keyed by public fd
        v
exact session registry
        |
        | session.owner is immutable
        v
permanent owner pthread
        |
        | every vls_* call for that session
        v
owner-local VLS worker state
~~~

New outbound sockets and independent listeners use an atomic round-robin
owner selector. Every later operation looks up the session and submits to
`g_workers[session->owner]`.

Accepted TCP children are different. A READY accepted VLS handle cannot be
migrated safely, so the child is registered on the listener's owner. One
listener can serve many goroutines correctly but concentrates all accepted
VLS work on one owner.

VPP transport/dataplane worker selection is independent. There is no formula
mapping owner 0 to VPP worker 0.

## 8. Synchronous request memory and ownership

The public API builds a `native_request_t` on the dedicated dispatcher
stack. Conceptually it contains:

~~~text
operation
session reference
scalar arguments
sockaddr / buffer / iovec pointers owned by the caller
rv and errno output
request-local mutex and condition variable
done flag
owner-queue next pointer
~~~

The submission path:

1. performs an exact registry lookup and increments the session reference;
2. records the session in the request;
3. enqueues the request under the selected owner's queue mutex;
4. waits on the request-local condition variable;
5. receives `rv` and `error_value`;
6. drops the session reference;
7. destroys the request synchronization objects and returns.

The owner cannot retain the request after setting `done`. The caller cannot
destroy it before observing `done`. This gives the request and its borrowed
pointers a bounded synchronous lifetime.

The data buffer itself is not copied by the dispatcher. The submitting
thread remains inside the native call until the owner completes the VLS
operation. Because this interception path does not use ordinary cgo pointer
instrumentation, high-preemption and GC stress remains an explicit
validation requirement.

## 9. Real-fd surrogate

Go's netpoller requires a real kernel fd. A VLS handle is not a kernel fd and
cannot be registered with Linux epoll.

For each VLS session, the owner creates:

~~~text
socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC)

pair[0] -> duplicated into reserved public range 0x000f0000..0x000fffff
pair[1] -> private owner signal endpoint
~~~

The registry record holds:

| Field | Meaning |
|---|---|
| `fd` | Public real fd stored in Go's `netFD` |
| `signal_fd` | Private socketpair endpoint |
| `vlsh` | Raw owner-local VLS handle |
| `owner` | Immutable owner index |
| `refs` | Registry/request lifetime references |
| `closing` | Atomic close arbitration |
| `armed` | VLS epoll interests |
| `notified` | Readiness currently encoded on the surrogate |
| metadata | Family, datagram/listening state, addresses, cached UDP peer |

The public fd is real, so Go can register it with epoll and apply ordinary fd
flags. Patched network operations do not read application data from the Unix
socket; they route to the session owner and VLS.

## 10. Readiness encoding

The two socketpair directions encode read and write readiness independently:

~~~text
owner B -> public A receive queue
  nonempty  => EPOLLIN asserted on A
  empty     => EPOLLIN cleared on A

public A -> owner B send queue
  has room  => EPOLLOUT asserted on A
  prefilled => EPOLLOUT suppressed on A
~~~

Read signal:

1. VLS epoll reports readable.
2. Owner sends one nonblocking token byte from B to A.
3. Linux epoll reports A readable.
4. Go netpoll wakes the goroutine.
5. The patched `read(A,...)` invokes owner-local `vls_read`.
6. The owner drains the token state when the readiness transition is reset.

Write signal:

1. The public A→B send queue starts full, so A is not writable.
2. VLS epoll reports writable.
3. Owner drains B, creating capacity in A's send queue.
4. Linux epoll reports A writable.
5. Go netpoll wakes the goroutine.
6. Patched `write(A,...)` invokes owner-local `vls_write`.
7. Owner refills the queue to suppress the next edge until VLS rearms it.

Token bytes never become application payload.

## 11. Nonblocking operation rule

Owners do not block indefinitely in a VLS data call:

- sessions are created nonblocking;
- `VPPCOM_EAGAIN` is translated to POSIX `EAGAIN`;
- the owner arms the session in its VLS epoll;
- Go parks on its normal netpoll path;
- a VLS event changes surrogate readiness;
- Go retries the syscall.

This keeps Go timers and deadlines authoritative. The owner pool does not
implement a second deadline scheduler.

The owner event loop processes up to 128 queued requests, polls up to 128 VLS
events, uses a 1 ms poll timeout, periodically checks pending connect errors,
and runs a readiness watchdog.

## 12. TCP

### 12.1 Client connect

~~~mermaid
sequenceDiagram
    participant G as Go net.Dial
    participant D as Dispatcher
    participant O as Session owner
    participant V as VLS
    participant N as Go netpoll

    G->>D: socket(SOCK_STREAM)
    D->>O: create TCP VLS session + surrogate
    G->>D: connect(fd, peer)
    D->>O: connect request
    O->>V: vls_connect(nonblocking)
    alt immediate success
        V-->>O: 0
        O-->>G: 0
    else pending
        V-->>O: EAGAIN/EINPROGRESS
        O->>V: arm EPOLLOUT
        O-->>G: EINPROGRESS
        G->>N: wait for writable surrogate
        V-->>O: connect event/error
        O->>N: assert surrogate writable
        N-->>G: wake
        G->>D: getsockopt(SO_ERROR)
        D-->>G: cached owner connect result
    end
~~~

A periodic owner-side connect check covers cases where the VLS event is not
sufficient to expose the completion error promptly.

### 12.2 Listen and accept

The listener is assigned to one owner. `accept4` clears a stale read token
and calls `vls_accept(..., O_NONBLOCK)` on that owner. On `EAGAIN`, the
listener is armed for VLS EPOLLIN and Go returns to netpoll. On success, the
child receives a new surrogate but retains the listener's owner.

### 12.3 Stream I/O

TCP reads and writes are byte-stream operations. Partial success is returned
immediately. An empty VLS write is mapped to `EPIPE`; EOF is returned as
zero from the read path. The iovec helpers stop at partial progress so they
do not invent atomicity beyond ordinary stream semantics.

## 13. UDP

UDP sessions use `VPPCOM_PROTO_UDP`; there is no listen/accept state.

### 13.1 Bind port zero

The tested VCL path did not provide the expected ephemeral result for a
literal port-zero bind. The owner selects ports from 32768–60999 using a
PID-seeded atomic ticket and retries up to 128 `EADDRINUSE` collisions.
The chosen address is cached for `getsockname`.

### 13.2 Connected UDP

`net.DialUDP` invokes `connect`. The owner temporarily clears
`O_NONBLOCK`, calls `vls_connect`, restores the original flags, and caches
the peer sockaddr. Subsequent `write`, null-destination `sendto`, and
`getpeername` use the same cached peer contract.

### 13.3 Unconnected UDP

`net.ListenPacket` uses `sendto` and `recvfrom`. The destination is
converted for every outbound datagram. The source reported by
`vls_recvfrom` is converted back for every inbound datagram; it must never
come from a session-wide cached peer.

Datagram boundaries are preserved by `vls_sendto`/`vls_recvfrom`.

A wildcard-bound VCL listener needs an additional source-selection step.
VCL auto-selects a source only when `sendto` starts from a CLOSED session;
Go's `ListenPacket("udp6", "[::]:0")` has already placed the session in
LISTEN state. On the first destination per owner, the owner creates one
short-lived blocking UDP probe, connects it to the destination, reads the
selected local IP, closes the probe, and stores the IP in an eight-entry
owner-local route cache. Each wildcard application socket combines that IP
with its own bound port before `vls_sendto`. A per-session destination cache
avoids repeating the attribute update, while `getsockname` continues to
report the original wildcard bind.

The initial per-socket probe design passed four-way testing but stalled under
100-way VCL connect/close churn. The owner cache reduces source discovery to
at most one probe per route per owner; routed `[::]:0` then passed 100 × 8
datagrams.

### 13.4 Connected UDP asynchronous errors

For supported IPv4 ICMP destination-unreachable, VPP resets the connected UDP
session and VCL exposes generic RESET plus `EPOLLERR|EPOLLHUP`, not the ICMP
reason. The owner latches `ECONNREFUSED` in `socket_error` and signals the
ordinary surrogate readiness path. The next connected datagram read/write or
`SO_ERROR` consumes the one-shot result. A direct VCL `ECONNRESET` from
connected datagram I/O is mapped the same way.

This mapping is deliberately connected-datagram-only; TCP resets remain
`ECONNRESET`. The tested VPP revision has no IPv6 implementation in
`udp_connection_handle_icmp()`, so IPv6 UDP ICMP delivery is an upstream
boundary rather than a vclgo pass.

Ancillary data, full `MSG_*` semantics, multicast/broadcast coverage, and
truncation behavior are not yet qualified.

## 14. HTTP

HTTP has no separate VCL implementation. Go's `net/http` runs over the TCP
path above.

Keep-alive tests emphasize:

- persistent TCP sessions;
- repeated read/write readiness rearming;
- response-body drain and connection reuse;
- deadlines and close after reuse.

No-keep-alive tests emphasize:

- repeated TCP connect and accept;
- rapid VLS session and surrogate creation;
- close and teardown churn.

The completed routed matrix includes IPv6 TLS/HTTP1 and TLS/HTTP2 at
3,200/3,200 requests each, 100/100 HTTP/2 cancellations, and 3,200/3,200 gRPC
health RPCs. WebSocket, streaming/chunked bodies, and remaining protocol fault
cases are not complete.

These are two-VPP memif results, not app-local cut-through results. The
intended production topology is cut-through, for which only TCP
smoke/concurrency/deadline evidence is recorded. Higher-protocol cut-through
qualification and the known VPP cut-through HTTP churn failure remain open.

## 15. Close and lifetime

An ordinary application `close(fd)`:

1. takes an exact session reference;
2. atomically wins or observes `closing`;
3. removes the registry entry so new operations cannot acquire it;
4. submits close to the session owner;
5. disarms VLS epoll;
6. closes the VLS handle on its owner;
7. closes both surrogate endpoints;
8. releases the final native record after in-flight references drain.

Concurrent operations that lose the close race return a POSIX-shaped error;
they do not use a freed VLS handle.

`close_range(first,last,0)` performs the same exact-registry close for every
owned fd in the overlap, then lets the kernel close ordinary descriptors and
already-removed surrogates. `CLOSE_RANGE_CLOEXEC` changes only kernel fd flags
and retains each VCL session. `CLOSE_RANGE_UNSHARE` is rejected with
`EOPNOTSUPP` whenever VCL is active because one calling thread's private fd
table cannot be reconciled with the process-wide registry.

## 16. Terminal process teardown

`exit_group` is intercepted before the raw kernel exit:

~~~mermaid
flowchart TD
    E["patched exit_group"] --> S["state ACTIVE -> STOPPING"]
    S --> A["owners reject new submissions"]
    A --> C["cancel queued requests"]
    C --> Q["owners quiesce"]
    Q --> D["abandon remaining native records and surrogates"]
    D --> B["bootstrap owner performs one vppcom_app_destroy"]
    B --> P["owner pthreads park"]
    P --> K["raw kernel exit_group"]
~~~

The terminal path intentionally avoids issuing a burst of individual
`vls_close` operations immediately before application detach. One
bootstrap-owned VCL application destroy releases remaining VPP sessions.
This contract applies only to process exit; normal `close` still closes one
session.

Teardown is deliberately idempotent. The lifecycle state machine permits one
caller to win `ACTIVE -> STOPPING`; concurrent or later callers wait for or
observe `STOPPED`. Consequently the `exit_group`, `atexit`, and preload
destructor safety nets cannot destroy VCL state twice.

Active teardown followed by reinitialization is unsupported.

## 17. Passthrough and failure containment

If `VCL_CONFIG` is absent, lifecycle state becomes passthrough and no owner
pool is created. Patches are still installed and dispatches execute the
original raw kernel syscall through `raw_syscall6`, including Linux `%r9` for
a5. A nonzero-offset `mmap` probe covers this path with VCL active and the fd
unowned.

If VCL initialization fails before patching, the constructor leaves the
application unpatched. If discovery finds no Go-shaped path, it returns
without touching VPP.

Current startup is not transactional:

- unresolved wrappers are logged and skipped;
- individual failed patches are counted;
- a partial set is not rolled back;
- some failures after VCL initialization can occur before the destructor is
  marked responsible for teardown.

These behaviors must be hardened before production.

The dispatcher and owner currently dereference application buffers, iovecs,
message headers, sockaddrs, socklen pointers, and `sendfile` offsets directly.
Null pointers receive explicit checks in a few paths, but an arbitrary invalid
non-null address can fault the dispatcher pthread instead of returning
`EFAULT`. Uniform fault containment or safe copy-in/copy-out is still a
production gap.

## 18. Security model

The preload modifies executable memory in its own process. Deployment must
therefore control:

- provenance and integrity of the preload, dispatcher, Frida-Gum archive, and
  VPP libraries;
- `LD_PRELOAD` injection and environment ownership;
- policies governing executable mappings and `mprotect`;
- restrictions on static, setuid, file-capability, or privileged targets;
- core dumps, logs, and addresses printed by constructor diagnostics.

The constructor allocates the thunk pages RW and then RX; it does not intend
to leave a W+X mapping. The exact target container and LSM policy still
require validation.

## 19. File map

| File | Purpose |
|---|---|
| `preload/fastpath/gum_vcl.c` | Discovery, emitters, patching, ABI bridge, stack switch, syscall routing |
| `preload/fastpath/Makefile` | Build the single preload library |
| `dispatcher/include/vclgo.h` | Public POSIX-shaped dispatcher API |
| `dispatcher/src/api_native.c` | API entry points and state/ownership gates |
| `dispatcher/src/lifecycle_native.c` | Initialization, passthrough, and teardown |
| `dispatcher/src/pool_native.c` | Owner queues, all VLS calls, epoll, TCP/UDP semantics |
| `dispatcher/src/registry_native.c` | Exact fd registry, socketpair creation, readiness tokens |
| `dispatcher/src/addr.c` | sockaddr ↔ VPP endpoint conversion |
| `test/run_smoke_fastpath.sh` | Cut-through TCP smoke |
| `test/run_concurrency_fastpath.sh` | Cut-through TCP payload/deadline stress |
| `test/run_smoke_udp_fastpath.sh` | Routed connected/unconnected UDP |
| `test/run_http_soak_fastpath.sh` | Routed HTTP keep-alive/fresh-connection soak |
| `test/run_protocol_matrix_fastpath.sh` | Routed IPv6 protocol matrix plus IPv4 UDP error; not cut-through |

## 20. Required invariants

Changes to the patcher or dispatcher must preserve:

1. no raw VLS call on a Go runtime M;
2. immutable session-to-owner assignment;
3. accepted-child ownership inherited from the listener;
4. exact registry membership before VCL routing;
5. no deep native call chain on a goroutine stack;
6. no application data read from or written to readiness-token queues;
7. request lifetime extending through owner completion;
8. no use of a session after registry removal and final reference release;
9. kernel-shaped `rax:rdx` at the original post-syscall Go path;
10. topology-qualified test claims and zero post-test VPP residue.
