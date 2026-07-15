/*
 * native_internal.h - shared state for the native seccomp/LD_PRELOAD backend.
 */
#ifndef VCLGO_NATIVE_INTERNAL_H
#define VCLGO_NATIVE_INTERNAL_H

#include "internal.h"
#include "addr.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/resource.h>
#include <sys/socket.h>

/* Transient: only the CAS winner is inside vclgo_native_pool_stop(). */
#define VCLGO_STATE_STOPPING 4
/* Terminal: teardown is finished. Losing exit_group notifiers park here
 * until the winner publishes STOPPED so the intercepted syscall never
 * races vppcom_app_destroy. See G3 in docs/plan.md. */
#define VCLGO_STATE_STOPPED  5

#define VCLGO_MAX_WORKERS 64

/* Session state trace ring: N-24 diagnostic. Enabled at VCLGO_LOG>=3 and
 * always populated at low overhead so the worker watchdog can dump the
 * recent history when a session appears stuck. Kept tiny to fit in a
 * cache line pair. */
#define VCLGO_TRACE_RING 16

typedef struct {
    uint64_t ts_ns;
    uint16_t op;       /* one of vclgo_trace_op_t */
    uint16_t reserved;
    int32_t  arg1;
    int32_t  arg2;
    uint32_t armed_after;
    uint32_t notified_after;
} vclgo_trace_entry_t;

typedef enum {
    VCLGO_TR_NONE = 0,
    VCLGO_TR_ARM,           /* arg1 = requested add mask, arg2 = op */
    VCLGO_TR_DISARM,
    VCLGO_TR_SIGNAL_TRY,    /* arg1 = requested events, arg2 = mask actually signaled */
    VCLGO_TR_SIGNAL_EAGAIN, /* signal path hit EAGAIN */
    VCLGO_TR_RESET,         /* arg1 = requested events, arg2 = mask actually cleared */
    VCLGO_TR_EVENT,         /* arg1 = delivered mask, arg2 = clear mask */
    VCLGO_TR_READ,          /* arg1 = req.count, arg2 = rv */
    VCLGO_TR_WRITE,         /* arg1 = req.count, arg2 = rv */
    VCLGO_TR_ACCEPT,        /* arg1 = new fd, arg2 = rv */
    VCLGO_TR_CONNECT,       /* arg1 = rv */
} vclgo_trace_op_t;

typedef struct vclgo_native_session {
    int fd;
    int signal_fd;
    vls_handle_t vlsh;
    unsigned owner;

    atomic_uint refs;
    atomic_int closing;

    vclgo_sock_meta_t meta;
    struct sockaddr_storage bound_addr;
    socklen_t bound_len;

    /* UDP peer selected by connect(2). The owner performs VLS connect in
     * blocking mode, then restores O_NONBLOCK before returning to Go.
     * The cache preserves POSIX getpeername/sendto(NULL) semantics even
     * when an explicit sendto temporarily changes VCL's remote endpoint.
     * Mutated only by the owner worker. */
    struct sockaddr_storage connected_peer;
    socklen_t connected_peer_len;
    int has_connected_peer;

    /* Mutated only by the owner worker. */
    uint32_t armed;
    uint32_t notified;
    int connecting;
    int connect_error;

    /* Watchdog + trace state. All mutated only by the owner worker. */
    uint64_t last_transition_ns;
    uint64_t last_dump_ns;
    uint32_t trace_head;
    vclgo_trace_entry_t trace[VCLGO_TRACE_RING];

    struct vclgo_native_session *hash_next;
    struct vclgo_native_session *worker_next;
} vclgo_native_session_t;

/* Record one state transition into the session's ring buffer. Owner-only. */
void vclgo_session_trace(vclgo_native_session_t *session, uint16_t op,
                         int32_t arg1, int32_t arg2);
/* Dump the session's ring buffer to stderr (only at VCLGO_LOG>=1). */
void vclgo_session_trace_dump(vclgo_native_session_t *session,
                              const char *reason);

/* Exact fd registry and real socket-pair-surrogate lifecycle. */
int vclgo_native_registry_prepare(void);
vclgo_native_session_t *
vclgo_native_session_create(vls_handle_t vlsh, unsigned owner,
                            const vclgo_sock_meta_t *meta);
vclgo_native_session_t *vclgo_native_session_lookup(int fd);
void vclgo_native_session_remove(vclgo_native_session_t *session);
void vclgo_native_session_get(vclgo_native_session_t *session);
void vclgo_native_session_put(vclgo_native_session_t *session);
int vclgo_native_registry_contains(int fd);
size_t vclgo_native_registry_size(void);
int vclgo_native_surrogate_reset(vclgo_native_session_t *session,
                                 uint32_t events);
int vclgo_native_surrogate_signal(vclgo_native_session_t *session,
                                  uint32_t events);

/* Permanently pinned VCL owner-worker pool. */
int vclgo_native_pool_start(const char *app_name, int requested_workers);
void vclgo_native_pool_stop(void);
int vclgo_native_pool_worker_count(void);

int vclgo_native_socket(int domain, int type, int protocol);
int vclgo_native_bind(int fd, const struct sockaddr *addr, socklen_t addrlen);
int vclgo_native_listen(int fd, int backlog);
int vclgo_native_accept4(int fd, struct sockaddr *addr, socklen_t *addrlen,
                         int flags);
int vclgo_native_connect(int fd, const struct sockaddr *addr,
                         socklen_t addrlen);
int vclgo_native_shutdown(int fd, int how);
int vclgo_native_close(int fd);
ssize_t vclgo_native_read(int fd, void *buf, size_t count);
ssize_t vclgo_native_write(int fd, const void *buf, size_t count);
ssize_t vclgo_native_sendto(int fd, const void *buf, size_t count, int flags,
                            const struct sockaddr *dest_addr,
                            socklen_t addrlen);
ssize_t vclgo_native_recvfrom(int fd, void *buf, size_t count, int flags,
                              struct sockaddr *src_addr,
                              socklen_t *addrlen);
int vclgo_native_setsockopt(int fd, int level, int optname,
                            const void *optval, socklen_t optlen);
int vclgo_native_getsockopt(int fd, int level, int optname,
                            void *optval, socklen_t *optlen);
int vclgo_native_getsockname(int fd, struct sockaddr *addr,
                             socklen_t *addrlen);
int vclgo_native_getpeername(int fd, struct sockaddr *addr,
                             socklen_t *addrlen);

#endif /* VCLGO_NATIVE_INTERNAL_H */
