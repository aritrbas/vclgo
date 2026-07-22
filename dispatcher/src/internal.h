/*
 * internal.h — private helpers shared across dispatcher .c files.
 *
 * Not installed; not part of the ABI.
 *
 * This header is used by the native LD_PRELOAD backend (see
 * dispatcher/src/api_native.c, lifecycle_native.c, pool_native.c,
 * registry_native.c). It collects the shared surface: logging, errno
 * helpers, socket metadata struct, epoll event aliases, and the
 * initialization state machine. Backend-specific interfaces live in
 * native_internal.h.
 */
#ifndef VCLGO_INTERNAL_H
#define VCLGO_INTERNAL_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <vcl/vppcom.h>
#include <vcl/vcl_locked.h>

#include "vclgo.h"

/* ---------- Logging ------------------------------------------------------ */

/* VCLGO_LOG (>=1) enables informational lifecycle messages. VCLGO_LOG >=2
 * enables per-call diagnostics (expensive; for debugging only). Level 3
 * enables per-transition surrogate state tracing used to hunt missed-wake
 * races (see analysis_bugs.md N-24). */
extern int vclgo_log_level;

#define VCLGO_LOGF(lvl, fmt, ...) \
    do { if (vclgo_log_level >= (lvl)) \
             fprintf(stderr, "[vclgo] " fmt "\n", ##__VA_ARGS__); } while (0)

#define VCLGO_LOG1(fmt, ...) VCLGO_LOGF(1, fmt, ##__VA_ARGS__)
#define VCLGO_LOG2(fmt, ...) VCLGO_LOGF(2, fmt, ##__VA_ARGS__)
#define VCLGO_LOG3(fmt, ...) VCLGO_LOGF(3, fmt, ##__VA_ARGS__)

/* ---------- errno helpers ------------------------------------------------ */

/* Set libc errno and return -1, matching POSIX conventions. libc owns the
 * thread-local slot, so each owner pthread reports its own operation error. */
static inline int vclgo_set_errno(int e) {
    errno = e;
    return -1;
}

/* VPP returns negative POSIX errnos as its own return value; translate. */
static inline int vclgo_from_vppcom(int rv) {
    if (rv >= 0) return rv;
    return vclgo_set_errno(-rv);
}

/* ---------- Per-pthread VLS registration -------------------------------- */

/* In the native backend, callers never enter VLS directly, so these are
 * effectively no-ops; VLS pinning happens inside the owner worker. Kept as
 * externally-callable helpers for symmetry and diagnostics. */
int  vclgo_pin_current_thread(void);
void vclgo_unpin_current_thread(void);

/* ---------- Socket metadata --------------------------------------------- */

/* Address-family/mode metadata attached to every VCL session. Cached so
 * getsockname / listen / dual-stack behaviour can be answered without a
 * VPP round-trip on every metadata query. */
typedef struct {
    uint8_t family;      /* AF_INET or AF_INET6 (0 if unknown) */
    uint8_t v6only;      /* 1 if IPV6_V6ONLY has been set */
    uint8_t is_dgram;    /* 1 for SOCK_DGRAM, 0 for SOCK_STREAM */
    uint8_t listening;   /* set after successful listen() */
} vclgo_sock_meta_t;

/* ---------- Event mask aliases ----------------------------------------- */

/* Bitmask kept in the wire format vls_epoll_ctl expects. */
#define VCLGO_EV_READ  EPOLLIN
#define VCLGO_EV_WRITE EPOLLOUT
#define VCLGO_EV_ERR   (EPOLLERR | EPOLLHUP | EPOLLRDHUP)

/* ---------- Stats ------------------------------------------------------- */

extern _Atomic uint64_t vclgo_stat_sockets_opened;
extern _Atomic uint64_t vclgo_stat_sockets_closed;
extern _Atomic uint64_t vclgo_stat_reads;
extern _Atomic uint64_t vclgo_stat_writes;
extern _Atomic uint64_t vclgo_stat_accepts;
extern _Atomic uint64_t vclgo_stat_connects;
extern _Atomic uint64_t vclgo_stat_eagain_parked;
extern _Atomic uint64_t vclgo_stat_poller_wakeups;

/* ---------- Init state ------------------------------------------------- */

/*
 * Init state machine (S1-1):
 *
 *                  vclgo_init entry
 *                          │
 *                          ▼
 *                 UNINIT ──CAS──► INITIALIZING
 *                          │           │
 *                          │           ├──► ACTIVE       (init ok, VCL_CONFIG set)
 *                          │           ├──► PASSTHROUGH  (VCL_CONFIG unset)
 *                          │           └──► UNINIT       (init failure)
 *                          │
 *                          └── loser thread spin-waits until state != INITIALIZING
 *
 * The native backend adds STOPPING (transient, held while teardown runs)
 * and STOPPED (terminal, published after teardown completes so that
 * losing exit_group interceptor threads can wait synchronously before
 * resuming their intercepted syscall). See native_internal.h and G3 in
 * plan.md.
 *
 * State transitions are single-writer (whoever won the CAS). Reads on the
 * hot path use atomic_load(&vclgo_state) == ACTIVE as the "we own this
 * syscall" test.
 */
extern atomic_int vclgo_state;
#define VCLGO_STATE_UNINIT        0
#define VCLGO_STATE_PASSTHROUGH   1
#define VCLGO_STATE_ACTIVE        2
#define VCLGO_STATE_INITIALIZING  3

#endif /* VCLGO_INTERNAL_H */
