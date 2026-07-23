# vclgo — transparent VCL networking for Go

vclgo lets a dynamically linked, unmodified Linux/amd64 Go application keep
using the standard `net` and `net/http` packages while TCP and UDP sockets
are implemented by VPP's VCL/VLS session layer.

The shipping implementation is **Approach #4: the native Frida-Gum
fastpath**:

~~~text
LD_PRELOAD=preload/fastpath/build/libvclgo_gum_vcl.so
~~~

Frida-Gum and Capstone are embedded native libraries. The preload constructor
examines the main Go executable, patches supported `SYSCALL` paths in its
in-memory `.text`, and routes VCL-owned descriptors through permanent owner
pthreads. No source-code change or Go package import is required.

## Current status

The established baseline fastpath matrix passes:

- 128 concurrent TCP echo connections and 100 simultaneous read deadlines
  over same-VPP VCL cut-through;
- connected and unconnected routed UDP with 128 goroutines;
- routed HTTP/1.1 over TCP with keep-alive enabled and disabled;
- two VPP processes connected by memif, two dataplane workers per VPP, and
  four permanent VCL owners per Go process;
- zero VPP application/session residue in the routed HTTP cleanup gates and
  focused post-run checks.

The expanded routed protocol/error matrix also passes end-to-end. It covers
IPv6 TCP echo, half-close, refused-connect, real peer reset, connected UDP,
wildcard-bound unconnected UDP, TLS/HTTP/1.1, TLS/HTTP/2 with exact ALPN,
HTTP/2 cancellation, and gRPC. The data gates use 100 goroutines; the HTTP
and gRPC gates complete 3,200 operations each with zero failures. The strict
UDP port-unreachable gate uses routed IPv4 because the tested VPP revision's
`udp_connection_handle_icmp()` has no IPv6 implementation.

The intended production topology is **same-VPP app-local VCL cut-through**.
Exactly two harnesses currently have recorded cut-through passes: the TCP
smoke harness and the TCP concurrency/deadline harness. The UDP and complete
HTTP/TLS/HTTP2/gRPC matrix above ran between two VPPs over memif, so it is
routed evidence, not cut-through evidence. A previously observed VPP crash
under same-VPP HTTP connection churn remains open.

This is therefore a strong lab checkpoint, not a production-readiness
declaration. The exact evidence and remaining promotion gates are maintained
in [docs/status.md](docs/status.md).

## Architecture

~~~mermaid
flowchart LR
    G["Go goroutine<br/>net / net/http"] --> W["Go syscall wrapper"]
    W --> P["Patched .text site"]
    P --> T["Near thunk / wrapper trampoline"]
    T --> S["Shared ABI shim"]
    S --> B["Per-OS-thread 512 KiB dispatcher stack"]
    B --> D["POSIX-shaped dispatcher"]
    D --> O["Permanent VCL owner pthread"]
    O --> L["VLS / VCL"]
    L --> V["Multi-worker VPP"]
    O --> F["Real AF_UNIX socketpair surrogate"]
    F --> N["Linux epoll / Go netpoll"]
    N --> G
~~~

The design relies on five invariants:

| Invariant | Consequence |
|---|---|
| Go runtime entry/exit code remains in control | The original wrapper performs its normal scheduler and errno handling |
| Native C/VCL work never runs on a goroutine stack | The shim switches to a dedicated 512 KiB stack before entering C |
| A raw VLS handle never changes pthread owner | Go goroutine migration cannot move VCL thread-local state |
| Go sees a real kernel fd | Standard epoll, netpoll, deadlines, and cancellation continue to work |
| Every return PC visible to the Go unwinder is a Go `.text` PC | Signal-time stack walks never encounter an anonymous trampoline PC |

New outbound sockets and independent listeners are assigned to VCL owners
round-robin. An accepted TCP child remains on its listener's owner because a
READY VLS session cannot be migrated safely. VPP selects its own
transport/dataplane worker independently; goroutines, Go runtime threads, VCL
owners, and VPP workers do not have a one-to-one mapping.

See:

- [Architecture](docs/architecture.md)
- [Architecture diagrams](docs/architecture_diagrams.md)
- [Concrete text-patching examples](docs/text_patching.md)
- [Goroutine and pthread ownership model](docs/model_goroutine_pthread.md)

## Build

Requirements:

- Linux x86-64;
- a dynamically linked Go executable;
- a matching VPP installation containing VCL/VLS headers and
  `libvppcom.so`;
- a VCL configuration whose application socket belongs to the intended VPP
  instance.

Build everything:

~~~bash
make build-fastpath \
  VPP_PREFIX=/home/aritrbas/vpp/vpp/build-root/install-vpp-native/vpp

go test ./...
go vet ./...
~~~

Artifacts:

~~~text
preload/fastpath/build/libvclgo_gum_vcl.so
bin/libvclgo_dispatcher.so
bin/examples/*
~~~

## VCL configuration

More than one owner requires VLS multi-worker mode:

~~~text
vcl {
  app-socket-api /absolute/path/to/vpp/app_ns_sockets/default
  app-scope-global
  use-mq-eventfd
  multi-thread-workers
  max-workers 64
}
~~~

Use `app-scope-local` only when local VCL cut-through is intentional. A
routed acceptance test uses separate VPP instances and global-only VCL
configuration at both endpoints.

## Run an application

~~~bash
export VCL_CONFIG=/absolute/path/to/vcl.conf
export VCLGO_WORKERS=4
export LD_LIBRARY_PATH=/matching/vpp/lib
export LD_PRELOAD=$PWD/preload/fastpath/build/libvclgo_gum_vcl.so

exec /absolute/path/to/go-application arg1 arg2
~~~

| Variable | Meaning |
|---|---|
| `VCL_CONFIG` | VCL configuration path; unset selects the current kernel-passthrough path |
| `VCLGO_WORKERS` | Permanent VCL owner pthreads, from 1 through 64 |
| `VCLGO_LOG` | Dispatcher logging level: 0–3 |
| `VCLGO_FASTPATH_TRACE` | Very verbose per-syscall routing trace |
| `VCLGO_DISABLE` | Disable constructor patching and VCL initialization |

Successful initialization is explicit:

~~~text
[vclgo] native worker pool: 4 owner worker(s), VLS mode 2
[vclgo/gum] vclgo_init ok (workers=4, passthrough=0, trace=0)
~~~

## Tests

The topology is part of every result:

| Harness | Required interpretation |
|---|---|
| `test/run_smoke_fastpath.sh` | Recorded same-VPP app-local cut-through TCP plus raw-a5, `sendfile`, and `close_range` regressions |
| `test/run_concurrency_fastpath.sh` | Same-VPP cut-through TCP payload and deadline stress |
| `test/run_smoke_udp_fastpath.sh` | Acceptance requires two VPPs and routed connected/unconnected UDP |
| `test/run_http_soak_fastpath.sh` | Routed HTTP/1.1, TLS, HTTP/2, protocol assertions, and cancellation |
| `test/run_grpc_fastpath.sh` | Routed concurrent gRPC health RPCs over one HTTP/2 connection |
| `test/run_protocol_matrix_fastpath.sh` | Composes the routed IPv6 protocol/error acceptance matrix |

A local-scope same-VPP result validates the patcher, ABI bridge, VCL owners,
surrogate readiness, and cut-through transport. It does not validate TCP or
UDP packet processing. See [docs/test_topology.md](docs/test_topology.md) for
the exact topologies, commands, and post-test checks.

## Current boundaries

- Linux x86-64 and dynamically linked Go executables only.
- TCP and UDP sockets for `AF_INET` and `AF_INET6` are routed; unrelated
  socket families remain kernel-owned.
- `dup`, `dup2`, `dup3`, `F_DUPFD`, and `TCPConn.File` are not
  supported for VCL-owned descriptors.
- Regular-file-to-VCL-TCP `sendfile` is translated. Ancillary data, complex
  `sendmsg/recvmsg`, socket-specific `ioctl`, `splice`, and uncommon socket
  extensions remain incomplete.
- One listener concentrates its accepted children on one VCL owner.
- Static or privileged executables, fork inheritance, and active VCL
  teardown/reinitialization are unsupported.
- Raw kernel fallback carries all six syscall arguments; the smoke harness
  verifies a nonzero `mmap` offset through argument six, and the same probe
  passes with `VCL_CONFIG` unset in pure passthrough mode.
- Arbitrary invalid application pointers are not yet contained and converted
  uniformly to `EFAULT`; executable-memory/text-write policy must be qualified
  in the target container.
- Routed IPv4 UDP port-unreachable is delivered to connected Go UDP as exact
  `ECONNREFUSED`. IPv6 ICMP error delivery remains unavailable in the tested
  upstream VPP code and is not claimed by vclgo.
- App-local cut-through is the production target, but only its TCP
  smoke/payload/deadline subset has a recorded pass. The full UDP and
  higher-protocol cut-through matrix, live `[CT:*]` assertion, repeated
  cleanup, and the known HTTP churn crash remain open.
- The short IPv6/TLS/HTTP2/gRPC matrix is green. Go-version coverage,
  WebSocket/streaming/control-message cases, container-policy validation,
  fault recovery, and multi-hour 100–1,000-goroutine soaks remain promotion
  gates.

## Documentation

| Document | Purpose |
|---|---|
| [Documentation index](docs/README.md) | Reading order and authority |
| [Status](docs/status.md) | Current evidence and production gates |
| [Architecture](docs/architecture.md) | End-to-end technical design |
| [Diagram atlas](docs/architecture_diagrams.md) | Flowcharts, stacks, memory, readiness, and ownership |
| [Text patching](docs/text_patching.md) | Exact Go `.text`, thunk, trampoline, ABI, and return examples |
| [Concurrency model](docs/model_goroutine_pthread.md) | Goroutine, pthread, VLS, and VPP-worker mapping |
| [Test topology](docs/test_topology.md) | Cut-through versus routed validation |
| [Risk ledger](docs/analysis_bugs.md) | Resolved defects and open risks |
| [Adoption guide](docs/adoption_guide.md) | Build, deployment, validation, and rollback |
| [Plan](docs/plan.md) | Ordered work required for production promotion |
