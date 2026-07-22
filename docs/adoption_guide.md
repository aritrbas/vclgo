# Adoption guide

Last updated: 2026-07-22.

This guide covers **Approach #4 / Approach D**, the Frida-Gum fastpath
selected with `libvclgo_gum_vcl.so`. This is the only backend shipped by
vclgo; Approaches #2 and #3 have been removed from the codebase (docs
retained as design record).

Read [status.md](status.md) and [test_topology.md](test_topology.md) before
using a test result as deployment evidence.

## 1. Fit

Approach #4 is a reasonable candidate when:

- the application must continue using Go's standard `net` stack;
- source changes are undesirable or impossible;
- the target is a dynamically linked Linux/amd64 Go executable;
- VPP/VCL libraries, shared memory, and an application socket are available;
- TCP or UDP is within the implemented compatibility surface;
- the environment permits the preload to map and patch executable memory.

Prefer source-level integration such as vclnet when the application can be
rebuilt and changed. Prefer normal VPP LDP for C/C++ applications that call
libc socket symbols.

## 2. Compatibility

| Application behavior | Approach #4 behavior |
|---|---|
| `net.Dial("tcp", ...)` / `net.Listen("tcp", ...)` | VCL |
| `net/http` | VCL; routed keepalive and no-keepalive soaks passed |
| Connected UDP | VCL; routed concurrency test passed |
| `net.ListenPacket` / `ReadFrom` / `WriteTo` | VCL; routed concurrency test passed |
| IPv4/IPv6 INET sockets | VCL for supported stream/datagram types |
| Unix sockets and unrelated families | Kernel |
| TLS/HTTP2/gRPC | Expected to layer over TCP, but dedicated soaks remain open |
| `TCPConn.File` / descriptor duplication | Unsupported for VCL-owned fds |
| Ancillary control data / OOB / `splice` | Incomplete or unsupported |
| Static executable | Cannot use `LD_PRELOAD` |
| Stripped dynamic Go executable | Supported by instruction scanning |
| setuid/setgid executable | Unsupported |
| forked-child VCL inheritance | Unsupported |

## 3. Requirements

- Matching VPP headers, `libvppcom.so`, VCL configuration, and running VPP.
- VPP session layer and application socket API enabled.
- `multi-thread-workers` in VCL when using more than one owner.
- A sufficiently high hard `RLIMIT_NOFILE`; the current surrogate registry
  reserves the high-fd range ending at 1,048,575.
- Frida-Gum and Capstone from the vendored fastpath dependency.
- Permission to create executable trampoline mappings and temporarily make
  target text writable during controlled patch installation.

Approach #4 has no seccomp-user-notification requirement and does not need a
Frida daemon, JavaScript agent, or eBPF program.

## 4. Build

```bash
cd /home/aritrbas/vpp/vclgo

make pc \
  VPP_PREFIX=/home/aritrbas/vpp/vpp/build-root/install-vpp-native/vpp
make build-fastpath
go test ./...
go vet ./...
```

Artifacts:

```text
preload/fastpath/build/libvclgo_gum_vcl.so
bin/libvclgo_dispatcher.so
bin/examples/*
```

No external Frida installation is required.

## 5. VCL and VPP configuration

For a routed endpoint:

```text
vcl {
  rx-fifo-size 4000000
  tx-fifo-size 4000000
  app-scope-global
  app-socket-api /path/to/vpp/app_ns_sockets/default
  use-mq-eventfd
  multi-thread-workers
  max-workers 64
}
```

The repository contains:

| File | Purpose |
|---|---|
| `test/vcl.native.conf` | One-VPP local cut-through diagnostics |
| `test/vcl.native.global.conf` | Routed server on VPP A |
| `test/vcl.native.peer.conf` | Routed client on VPP B |

Do not add `app-scope-local` to the routed acceptance configs. Doing so can
silently convert a same-VPP test into cut-through.

## 6. Run

```bash
export VCL_CONFIG=/absolute/path/to/vcl.conf
export VCLGO_WORKERS=4
export VCLGO_LOG=1
export LD_LIBRARY_PATH=/matching/vpp/lib:${LD_LIBRARY_PATH:-}
export LD_PRELOAD=$PWD/preload/fastpath/build/libvclgo_gum_vcl.so

exec /absolute/path/to/go-application arg1 arg2
```

The current launcher is not the authority for Approach #4; use direct
`LD_PRELOAD` until the fastpath backend option is implemented and tested.

If `VCL_CONFIG` is unset, patched socket calls stay on the kernel
passthrough path. `VCLGO_DISABLE=1` disables patching entirely.

## 7. Environment reference

| Variable | Default | Meaning |
|---|---|---|
| `VCL_CONFIG` | unset | VCL config; unset means kernel passthrough |
| `VCLGO_WORKERS` | auto | Permanent owner pthread count, 1–64 |
| `VCLGO_LOG` | 0 | Lifecycle/call/session diagnostics |
| `VCLGO_FASTPATH_TRACE` | unset | Extremely verbose syscall trace |
| `VCLGO_DISABLE` | unset | Constructor no-op when set |
| `LD_LIBRARY_PATH` | system | Must find the matching VPP/VCL libraries |
| `LD_PRELOAD` | system | Must include `libvclgo_gum_vcl.so` |

(`VCLGO_NOTIFIERS` was an Approach #3 knob; Approach #3 has been removed
from the codebase and the variable is no longer referenced anywhere.)

## 8. Validate the target

The optional probe reports recognized syscall sites without routing them:

```bash
LD_PRELOAD=$PWD/preload/fastpath/build/libvclgo_gum_probe.so \
  /absolute/path/to/go-binary --help
```

A zero-site result means the binary is not compatible with the current
patcher or is not a dynamic Go executable. Exact counts can change between Go
releases; compatibility is determined by successful classification, not by
hard-coding one historical count.

During a real VCL run, require:

```text
[vclgo/gum] vclgo_init ok ... passthrough=0
```

at every Go endpoint.

## 9. First validation sequence

1. Run with `VCL_CONFIG` unset and confirm kernel behavior is unchanged.
2. Run the one-VPP smoke/concurrency tests and label them cut-through.
3. Create the two-VPP global-scope topology.
4. Run routed UDP and routed HTTP in both keepalive modes.
5. Query both VPPs for application/session residue after shutdown.

Commands and the exact meaning of each step are in
[test_topology.md](test_topology.md).

## 10. Concurrency expectations

`VCLGO_WORKERS=4` creates four permanent VCL owner pthreads. It does not
create a one-to-one mapping from goroutines to owners.

- Goroutines execute on scheduler-managed Go M pthreads.
- Each VCL session is permanently assigned to one owner.
- New outbound sockets and independent listeners are round-robin assigned.
- Accepted children stay on their listener owner.
- VPP chooses its own session/dataplane worker independently.

One Go listener can therefore support 100+ goroutines correctly while still
concentrating all accepted VLS sessions on one owner. If that owner becomes a
bottleneck, use multiple listeners/reuse-port only after adding explicit
tests for the application.

## 11. Teardown behavior

Ordinary `close(2)` closes the individual VLS session on its owner.

At terminal process exit, owners stop admitting work and discard remaining
dispatcher/surrogate records without sending a disconnect for every live VLS
session. The bootstrap owner performs one `vppcom_app_destroy()`, and owner
threads remain parked until raw `exit_group` terminates the process. This
avoids racing or flooding VPP cut-through cleanup.

Active init/teardown/reinit in one process is not supported.

## 12. Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| No patch sites | Static/non-Go/unrecognized Go binary | Run the probe; capture Go version and disassembly |
| `passthrough=1` | Missing `VCL_CONFIG` | Supply a readable config |
| VCL init/app attach failure | Wrong app socket or library/VPP mismatch | Compare config, sockets, build prefix, and permissions |
| Multiple owners rejected | VLS mode 2 unavailable | Enable `multi-thread-workers`; verify matching VPP/VCL |
| Local echo passes, routed test fails | Cut-through masked a routing problem | Verify both memifs, addresses, FIB, and global-only configs |
| UDP bind/connect error | Wrong routed address or stale process/config | Check endpoint config and VPP app/session state |
| HTTP uses a proxy | Proxy environment bypasses test address | Set `NO_PROXY` and `no_proxy` |
| `unexpected return pc` / incomplete traceback | Fastpath stack/unwinder invariant violation | Stop deployment; save core, logs, Go/VPP versions |
| VPP crashes only under same-VPP HTTP churn | Known cut-through-path class on tested VPP branch | Reproduce on VPP; do not treat routed success as a CT fix |
| Sessions remain after exit | Teardown or VPP detach failure | Capture both VPP `show app` and `show session verbose 1` |

## 13. Rollback

```bash
unset LD_PRELOAD
unset VCL_CONFIG
exec ./application
```

Patches exist only in process memory; the executable on disk is unchanged.

## 14. Production gate

The current routed UDP/HTTP and cut-through concurrency results are a lab
checkpoint. Before production use, close the open items in
[plan.md](plan.md), especially:

- target Go-version and container-policy matrices;
- routed raw-TCP, TLS, HTTP/2, and gRPC tests;
- extended preemption and 100–1,000-goroutine soaks;
- reset/refused/half-close/fault-injection coverage;
- owner saturation and listener concentration measurements;
- automated clean-topology regression tests.
