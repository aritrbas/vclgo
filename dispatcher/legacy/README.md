# Legacy Frida-era dispatcher sources

These files were the dispatcher for the retired Frida backend. They are
retained for historical reference only and are **not** included in the built
library.

- `sockets.c`   — POSIX-shaped API implementation on top of `vppcom_*`
                  primitives, coupled to Frida-side fake-fd allocation.
- `fd_map.c`    — Fake-fd (`0x40000000 + n`) allocator and metadata lookup.
- `poller.c`    — Dedicated dispatcher poller thread using `vls_epoll_wait`.
- `worker.c`    — Deep-call offload worker introduced to survive Go's 8 KiB
                  goroutine stack (see `docs/analysis_bugs.md` §S1-14).
- `lifecycle.c` — Frida-era `vclgo_init`/`vclgo_teardown` implementation.

**Do not add these to `dispatcher/Makefile`.** They will not compile against
the current `vclgo.h` (ABI v2) and use symbols/model that are structurally
incompatible with the shared native dispatcher used by Approaches #3 and #4.
See
[docs/phase1_frida.md](../../docs/phase1_frida.md) for why the Frida path was
retired and
[docs/architecture_fastpath.md](../../docs/architecture_fastpath.md) for the
current Approach #4 design.

The active dispatcher sources live in `dispatcher/src/*_native.c` plus
`addr.{c,h}`.
