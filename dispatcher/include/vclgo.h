/*
 * Public POSIX-shaped API of libvclgo_dispatcher.so.
 *
 * Seccomp notifier threads submit short requests to permanent VCL owner
 * pthreads. Raw VLS handles never leave their owner. All VLS operations are
 * nonblocking; readiness is relayed to Go through real kernel surrogate fds.
 *
 * Functions return ordinary POSIX values and set the caller's libc errno on
 * failure. Range membership is only a fast path: ownership always requires
 * an exact registry lookup.
 */

#ifndef VCLGO_DISPATCHER_H
#define VCLGO_DISPATCHER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- ABI compatibility --------------------------------------------- */

#define VCLGO_ABI_VERSION 2

/* Non-zero if the dispatcher was built against a compatible VPP. Called by
 * the launcher during handshake so we can fail fast on mismatch. */
int vclgo_abi_version(void);

/* ---------- Kernel-surrogate fd namespace -------------------------------- */

/*
 * Each VCL session has one end of a real nonblocking socket pair in this
 * reserved range. Go registers it with normal epoll. The owner uses the
 * private peer to assert EPOLLIN and EPOLLOUT independently when VLS reports
 * readiness, preserving runtime deadlines and cancellation.
 *
 * The preload constructor raises the soft RLIMIT_NOFILE to VCLGO_FD_LIMIT
 * when the hard limit allows it. Exact lookup prevents unrelated high fds
 * from being treated as VCL sessions.
 */
#define VCLGO_FD_BASE  0x000F0000u
#define VCLGO_FD_LIMIT 0x00100000u

static inline int vclgo_fd_in_reserved_range(int fd) {
    return fd >= (int)VCLGO_FD_BASE && fd < (int)VCLGO_FD_LIMIT;
}

/* Range membership is only a seccomp fast-path.  This function performs an
 * exact registry lookup and therefore does not mistake an unrelated high fd
 * for a VCL socket. */
int vclgo_owns_fd(int fd);

/* Number of permanently pinned VCL owner workers selected at init. */
int vclgo_worker_count(void);

/* ---------- Init / lifecycle --------------------------------------------- */

/*
 * Creates the VCL application and permanent owner-worker pool. Safe to call
 * more than once; only the first caller initializes it. When VCL_CONFIG is
 * unset, initialization succeeds in kernel-passthrough mode.
 */
int vclgo_init(const char *app_name);

/* Passthrough means "no VPP configured, do not divert syscalls". */
int vclgo_passthrough(void);

/* Stops submissions, cancels queued calls, closes owner-local sessions and
 * epolls, unregisters secondary workers, then destroys the VCL application
 * on its bootstrap owner.
 *
 * Synchronous and safe to call from any thread. The first caller performs
 * the work; concurrent callers block until the first caller finishes and
 * only then return. This lets multiple seccomp notifiers observing
 * `exit_group` all resolve their notifications before the intercepted
 * syscall is allowed to proceed — otherwise the kernel would start
 * running `do_exit` on a losing thread while the winner is still inside
 * `vppcom_app_destroy`. See docs/plan.md G3.
 */
void vclgo_teardown(void);

/* Blocks until vclgo_teardown() has run to completion in some thread. If
 * teardown has not been started at all, returns immediately. Cheap after
 * teardown finishes; safe to call from any thread; never allocates. */
void vclgo_wait_teardown_complete(void);

/* ---------- Per-thread errno --------------------------------------------- */

/* Returns the current pthread's libc errno address. */
int *vclgo_errno_addr(void);
static inline int vclgo_errno(void) { return *vclgo_errno_addr(); }

/* ---------- POSIX-shaped syscall entry points ---------------------------- */

/* The native backend routes AF_INET/AF_INET6 TCP streams only. The preload
 * layer continues unsupported socket combinations in the kernel. */
int vclgo_socket(int domain, int type, int protocol);

int vclgo_bind(int fd, const struct sockaddr *addr, socklen_t addrlen);
int vclgo_listen(int fd, int backlog);
int vclgo_accept(int fd, struct sockaddr *addr, socklen_t *addrlen);
int vclgo_accept4(int fd, struct sockaddr *addr, socklen_t *addrlen,
                  int flags);
int vclgo_connect(int fd, const struct sockaddr *addr, socklen_t addrlen);
int vclgo_shutdown(int fd, int how);
int vclgo_close(int fd);

ssize_t vclgo_read(int fd, void *buf, size_t count);
ssize_t vclgo_write(int fd, const void *buf, size_t count);

/*
 * UDP-aware send/recv. For connected sockets (both SOCK_STREAM and
 * connected SOCK_DGRAM) pass dest_addr = NULL. For unconnected UDP
 * pass a per-datagram destination. `src_addr` in vclgo_recvfrom is
 * filled with the datagram's sender when non-NULL, matching BSD
 * recvfrom() semantics.
 */
ssize_t vclgo_sendto(int fd, const void *buf, size_t count, int flags,
                     const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t vclgo_recvfrom(int fd, void *buf, size_t count, int flags,
                       struct sockaddr *src_addr, socklen_t *addrlen);

int vclgo_setsockopt(int fd, int level, int optname,
                     const void *optval, socklen_t optlen);
int vclgo_getsockopt(int fd, int level, int optname,
                     void *optval, socklen_t *optlen);
int vclgo_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen);
int vclgo_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen);

int vclgo_fcntl(int fd, int cmd, long arg);

/*
 * Compatibility stubs for direct dispatcher users. Go's runtime epoll works
 * without these because VCL sessions expose real kernel surrogate fds.
 */
int vclgo_epoll_create1(int flags);
int vclgo_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int vclgo_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                     int timeout);

/* ---------- Observability -------------------------------------------------*/

typedef struct {
    uint64_t sockets_opened;
    uint64_t sockets_closed;
    uint64_t reads;
    uint64_t writes;
    uint64_t accepts;
    uint64_t connects;
    uint64_t eagain_parked;
    uint64_t poller_wakeups;
} vclgo_stats_t;

void vclgo_stats_snapshot(vclgo_stats_t *out);

#ifdef __cplusplus
}
#endif

#endif /* VCLGO_DISPATCHER_H */
