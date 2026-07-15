/*
 * sockets.c — POSIX-shaped syscall entry points.
 *
 * Every entry point:
 *   1. Ensures the calling pthread is pinned & registered.
 *   2. Rejects (ENOSYS) in passthrough mode so the hook layer falls back
 *      to the original kernel syscall.
 *   3. Converts VPP's negative-errno return convention into POSIX
 *      (-1 with vclgo_errno set).
 *   4. On EAGAIN/EINPROGRESS parks the caller in the shared poller
 *      instead of spin-waiting.
 *
 * Nothing here calls into Go or holds a long-lived global lock: the whole
 * hot path is per-thread + per-vlsh state.
 */

#include "internal.h"
#include "addr.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/* Blocking-wait budget for connect(). Read/write/accept use unbounded
 * waits (see S1-2 in docs/analysis_bugs.md): the alternative — surfacing
 * EAGAIN to Go — hangs the goroutine forever because we short-circuit
 * runtime.netpollopen and there is nothing wired to fire netpollready
 * for our VCL fds. Connect keeps a bounded timeout so a lost SYN doesn't
 * pin an M forever; the timeout doubles as a de-facto SO_SNDTIMEO. */
static const int CONNECT_TIMEOUT_MS = 30000;
#define WAIT_FOREVER (-1)

/* ---------- Passthrough gate ------------------------------------------- */

static inline int passthrough_gate(void)
{
    switch (atomic_load(&vclgo_state)) {
    case VCLGO_STATE_ACTIVE:
        return 0;
    case VCLGO_STATE_PASSTHROUGH:
        return vclgo_set_errno(ENOSYS);
    default:
        /* Uninitialised — likely a hook fired before vclgo_init(); treat as
         * passthrough so the kernel can handle it. */
        return vclgo_set_errno(ENOSYS);
    }
}

/* ---------- Fake-fd encoding with overflow guard (S1-7) ---------------- */

/* Encode a VLS handle into a fake FD. Returns the fake FD on success, or
 * -1 with errno = ENFILE if the handle does not fit in VCLGO_VLSH_MASK
 * (24 bits). The caller must vls_close() the handle if this returns -1.
 * The check exists so a long-running process that eventually reuses VLS
 * pool indices >= 2^24 fails loudly instead of silently truncating and
 * routing subsequent I/O to the wrong session. */
static int vclgo_encode_fake_fd(vls_handle_t vlsh)
{
    if ((unsigned)vlsh > VCLGO_VLSH_MASK) {
        vls_close(vlsh);
        return vclgo_set_errno(ENFILE);
    }
    return vclgo_vlsh_to_fd((int)vlsh);
}

/* ---------- socket / close ------------------------------------------- */

int vclgo_socket(int domain, int type, int protocol)
{
    if (passthrough_gate() < 0) return -1;

    /* Only IP families with TCP or UDP. Everything else (AF_UNIX, netlink,
     * raw, packet, MPTCP=262) falls back to the kernel. Matches
     * frida-vpp's protocol filter. */
    if (domain != AF_INET && domain != AF_INET6)
        return vclgo_set_errno(EAFNOSUPPORT);
    int stype = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (stype != SOCK_STREAM && stype != SOCK_DGRAM)
        return vclgo_set_errno(ESOCKTNOSUPPORT);
    if (protocol == 262 /* IPPROTO_MPTCP */)
        return vclgo_set_errno(EPROTONOSUPPORT);

    if (vclgo_pin_current_thread() < 0) return -1;

    uint8_t proto = (stype == SOCK_STREAM) ? VPPCOM_PROTO_TCP
                                            : VPPCOM_PROTO_UDP;
    vls_handle_t vlsh = vls_create(proto, 1 /* nonblocking */);
    if (vlsh < 0) return vclgo_from_vppcom((int)vlsh);

    int fd = vclgo_encode_fake_fd(vlsh);
    if (fd < 0) return -1;   /* vlsh already closed, errno set to ENFILE */

    vclgo_sock_meta_t meta = {
        .family    = (uint8_t)domain,
        .is_dgram  = (stype == SOCK_DGRAM),
    };
    if (vclgo_fdmap_track(fd, &meta) < 0) {
        vls_close(vlsh);
        return vclgo_set_errno(ENOMEM);
    }
    atomic_fetch_add(&vclgo_stat_sockets_opened, 1);
    VCLGO_LOG2("socket(dom=%d type=%d proto=%d) -> fd=0x%x (vlsh=%d)",
               domain, type, protocol, fd, (int)vlsh);
    return fd;
}

int vclgo_close(int fd)
{
    if (!vclgo_fd_is_vcl(fd)) return vclgo_set_errno(EBADF);
    if (passthrough_gate() < 0) return -1;
    if (vclgo_pin_current_thread() < 0) return -1;

    int vlsh = vclgo_fd_to_vlsh(fd);
    vclgo_poller_drop(vlsh);
    int rv = vls_close((vls_handle_t)vlsh);
    vclgo_fdmap_untrack(fd);
    atomic_fetch_add(&vclgo_stat_sockets_closed, 1);
    VCLGO_LOG2("close(fd=0x%x) -> %d", fd, rv);
    return vclgo_from_vppcom(rv);
}

int vclgo_shutdown(int fd, int how)
{
    if (!vclgo_fd_is_vcl(fd)) return vclgo_set_errno(EBADF);
    if (passthrough_gate() < 0) return -1;
    if (vclgo_pin_current_thread() < 0) return -1;

    int vlsh = vclgo_fd_to_vlsh(fd);
    int rv = vls_shutdown((vls_handle_t)vlsh, how);
    if (rv == 0 && how == SHUT_RDWR) {
        /* Defence-in-depth (S2-2): VLS does not always raise EPOLLRDHUP
         * for full shutdowns (observed historically on some UDP paths).
         * Explicitly cancel every parked waiter on this vlsh so pending
         * readers/writers observe ECANCELED promptly rather than waiting
         * for the poller's next event delivery. */
        vclgo_poller_drop(vlsh);
    }
    return vclgo_from_vppcom(rv);
}

/* ---------- bind / listen / accept / connect -------------------------- */

int vclgo_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (!vclgo_fd_is_vcl(fd)) return vclgo_set_errno(EBADF);
    if (passthrough_gate() < 0) return -1;
    if (vclgo_pin_current_thread() < 0) return -1;

    vppcom_endpt_t ep; uint8_t ip[16];
    if (vclgo_sockaddr_to_endpt(addr, addrlen, &ep, ip) < 0) return -1;
    int vlsh = vclgo_fd_to_vlsh(fd);
    int rv = vls_bind((vls_handle_t)vlsh, &ep);
    VCLGO_LOG2("bind(fd=0x%x vlsh=%d) -> %d", fd, vlsh, rv);
    return vclgo_from_vppcom(rv);
}

int vclgo_listen(int fd, int backlog)
{
    if (!vclgo_fd_is_vcl(fd)) return vclgo_set_errno(EBADF);
    if (passthrough_gate() < 0) return -1;
    if (vclgo_pin_current_thread() < 0) return -1;

    /* Match frida-vpp's V6ONLY logic: for AF_INET6 listeners, force
     * IPV6_V6ONLY=1 before listen so VLS does not create a companion IPv4
     * listener that would collide with Go's separate AF_INET bind. */
    vclgo_sock_meta_t meta;
    if (vclgo_fdmap_lookup(fd, &meta) == 0 && meta.family == AF_INET6 && !meta.v6only) {
        uint32_t v6only = 1;
        uint32_t len    = sizeof v6only;
        (void)vls_attr((vls_handle_t)vclgo_fd_to_vlsh(fd),
                       VPPCOM_ATTR_SET_V6ONLY, &v6only, &len);
        meta.v6only = 1;
        vclgo_fdmap_update(fd, &meta);
    }

    int vlsh = vclgo_fd_to_vlsh(fd);
    int rv = vls_listen((vls_handle_t)vlsh, backlog);
    if (rv == 0 && vclgo_fdmap_lookup(fd, &meta) == 0) {
        meta.listening = 1;
        vclgo_fdmap_update(fd, &meta);
    }
    VCLGO_LOG2("listen(fd=0x%x vlsh=%d backlog=%d) -> %d",
               fd, vlsh, backlog, rv);
    return vclgo_from_vppcom(rv);
}

int vclgo_accept4(int fd, struct sockaddr *addr, socklen_t *addrlen,
                  int flags)
{
    if (!vclgo_fd_is_vcl(fd)) return vclgo_set_errno(EBADF);
    if (passthrough_gate() < 0) return -1;
    if (vclgo_pin_current_thread() < 0) return -1;

    /* S1-3: refuse to inherit metadata that isn't in the map. The listener
     * must have gone through vclgo_socket() (or a future vclgo_dup) before
     * accept() is called; a missing entry means the caller passed a stale
     * fake fd or vlsh reuse-after-close, either way it must not silently
     * seed the child with garbage metadata. */
    vclgo_sock_meta_t lmeta = {0};
    if (vclgo_fdmap_lookup(fd, &lmeta) < 0) return vclgo_set_errno(EBADF);

    int listen_vlsh = vclgo_fd_to_vlsh(fd);
    vppcom_endpt_t ep; uint8_t ip[16] = {0};
    memset(&ep, 0, sizeof ep);
    ep.ip = ip;

    for (;;) {
        vls_handle_t vlsh = vls_accept((vls_handle_t)listen_vlsh, &ep,
                                       O_NONBLOCK);
        if (vlsh >= 0) {
            int cfd = vclgo_encode_fake_fd(vlsh);
            if (cfd < 0) return -1;   /* ENFILE — vlsh already closed */

            vclgo_sock_meta_t cmeta = {
                .family   = lmeta.family,
                .is_dgram = lmeta.is_dgram,
            };
            if (vclgo_fdmap_track(cfd, &cmeta) < 0) {
                vls_close(vlsh);
                return vclgo_set_errno(ENOMEM);
            }
            if (addr && addrlen && *addrlen > 0) {
                (void)vclgo_endpt_to_sockaddr(&ep, addr, addrlen);
            }
            atomic_fetch_add(&vclgo_stat_accepts, 1);
            VCLGO_LOG2("accept4(fd=0x%x) -> fd=0x%x (vlsh=%d)",
                       fd, cfd, (int)vlsh);
            (void)flags;   /* CLOEXEC / NONBLOCK carry no meaning on VLS fds */
            return cfd;
        }

        if (vlsh != VPPCOM_EAGAIN) {
            return vclgo_from_vppcom((int)vlsh);
        }

        /* S1-2: unbounded wait. Never surface EAGAIN — Go's netpoll is
         * short-circuited for VCL fds so a returned EAGAIN would gopark
         * the goroutine forever (no netpollready will ever fire). We
         * only leave the wait on cancellation (listener close from
         * another goroutine) or on an actual EPOLLIN. */
        int ev = vclgo_poller_wait(listen_vlsh, VCLGO_EV_READ, WAIT_FOREVER);
        if (ev < 0) return -1;              /* errno already set */
        /* Otherwise fall through and retry vls_accept. */
    }
}

int vclgo_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    return vclgo_accept4(fd, addr, addrlen, 0);
}

int vclgo_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (!vclgo_fd_is_vcl(fd)) return vclgo_set_errno(EBADF);
    if (passthrough_gate() < 0) return -1;
    if (vclgo_pin_current_thread() < 0) return -1;

    vppcom_endpt_t ep; uint8_t ip[16];
    if (vclgo_sockaddr_to_endpt(addr, addrlen, &ep, ip) < 0) return -1;

    int vlsh = vclgo_fd_to_vlsh(fd);
    int rv = vls_connect((vls_handle_t)vlsh, &ep);
    VCLGO_LOG2("connect(fd=0x%x vlsh=%d) vls_connect -> %d", fd, vlsh, rv);
    if (rv == 0) {
        atomic_fetch_add(&vclgo_stat_connects, 1);
        return 0;
    }
    if (rv != VPPCOM_EINPROGRESS && rv != VPPCOM_EAGAIN)
        return vclgo_from_vppcom(rv);

    /* Wait for EPOLLOUT to signal that the connect completed (or EPOLLERR
     * / EPOLLHUP on failure). Mirrors vclnet's split-connect path. Unlike
     * read/write/accept this stays bounded — a lost SYN should not pin an
     * M forever, and the timeout doubles as a de-facto SO_SNDTIMEO. */
    int ev = vclgo_poller_wait(vlsh, VCLGO_EV_WRITE, CONNECT_TIMEOUT_MS);
    VCLGO_LOG2("connect(vlsh=%d) poller_wait -> ev=0x%x", vlsh, ev);
    if (ev < 0) return -1;
    if (ev == 0) return vclgo_set_errno(ETIMEDOUT);
    if (ev & (EPOLLERR | EPOLLHUP)) {
        /* Query VPP for the exact error. */
        int sockerr = 0;
        uint32_t len = sizeof sockerr;
        (void)vls_attr((vls_handle_t)vlsh, VPPCOM_ATTR_GET_ERROR,
                       &sockerr, &len);
        if (sockerr == 0) sockerr = ECONNREFUSED;
        VCLGO_LOG2("connect(vlsh=%d) EPOLLERR/HUP sockerr=%d", vlsh, sockerr);
        return vclgo_set_errno(sockerr);
    }
    atomic_fetch_add(&vclgo_stat_connects, 1);
    return 0;
}

/* ---------- read / write --------------------------------------------- */
/*
 * S1-14: the actual vls_read / vls_write loops (and the poller_wait
 * cycles they drive) run on the OFFLOAD WORKER's pthread stack, not on
 * the goroutine's ~8 KiB stack. See dispatcher/src/worker.c for the
 * queue plumbing and stack-overflow crash write-up. The passthrough /
 * EBADF gates stay here so non-VCL fds never even reach the queue.
 */

ssize_t vclgo_read(int fd, void *buf, size_t count)
{
    if (!vclgo_fd_is_vcl(fd)) return vclgo_set_errno(EBADF);
    if (passthrough_gate() < 0) return -1;
    /* pin_current_thread is a no-op in Mode 3, but even in a future
     * Mode 2 the caller doesn't touch VCL — the worker does — so leave
     * it out of the hot path. */
    return vclgo_worker_read(fd, buf, count);
}

ssize_t vclgo_write(int fd, const void *buf, size_t count)
{
    if (!vclgo_fd_is_vcl(fd)) return vclgo_set_errno(EBADF);
    if (passthrough_gate() < 0) return -1;
    return vclgo_worker_write(fd, buf, count);
}

/* ---------- getsockname / getpeername -------------------------------- */

static int getname_generic(int fd, uint32_t attr, struct sockaddr *addr,
                           socklen_t *addrlen)
{
    if (!vclgo_fd_is_vcl(fd)) return vclgo_set_errno(EBADF);
    if (passthrough_gate() < 0) return -1;
    if (vclgo_pin_current_thread() < 0) return -1;

    /* VPPCOM_ATTR_GET_{LCL,PEER}_ADDR fills a vppcom_endpt_t whose `ip`
     * points into a caller-supplied buffer. */
    uint8_t ip[16] = {0};
    vppcom_endpt_t ep;
    memset(&ep, 0, sizeof ep);
    ep.ip = ip;
    uint32_t len = sizeof ep;
    int rv = vls_attr((vls_handle_t)vclgo_fd_to_vlsh(fd), attr, &ep, &len);
    if (rv < 0) return vclgo_from_vppcom(rv);
    return vclgo_endpt_to_sockaddr(&ep, addr, addrlen);
}

int vclgo_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    return getname_generic(fd, VPPCOM_ATTR_GET_LCL_ADDR, addr, addrlen);
}

int vclgo_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    return getname_generic(fd, VPPCOM_ATTR_GET_PEER_ADDR, addr, addrlen);
}

/* ---------- setsockopt / getsockopt (minimal) ------------------------ */

int vclgo_setsockopt(int fd, int level, int optname,
                     const void *optval, socklen_t optlen)
{
    if (!vclgo_fd_is_vcl(fd)) return vclgo_set_errno(EBADF);
    if (passthrough_gate() < 0) return -1;
    if (vclgo_pin_current_thread() < 0) return -1;

    uint32_t len = optlen;
    /* Map only the common options the Go net package actually uses.
     * Everything else is silently accepted so stdlib helpers don't fail
     * hard — the underlying VPP session already applies its own defaults. */
    if (level == SOL_SOCKET) {
        if (optname == SO_REUSEADDR) {
            (void)vls_attr((vls_handle_t)vclgo_fd_to_vlsh(fd),
                           VPPCOM_ATTR_SET_REUSEADDR, (void *)optval, &len);
            return 0;
        }
        if (optname == SO_REUSEPORT) {
            (void)vls_attr((vls_handle_t)vclgo_fd_to_vlsh(fd),
                           VPPCOM_ATTR_SET_REUSEPORT, (void *)optval, &len);
            return 0;
        }
        if (optname == SO_BROADCAST) {
            (void)vls_attr((vls_handle_t)vclgo_fd_to_vlsh(fd),
                           VPPCOM_ATTR_SET_BROADCAST, (void *)optval, &len);
            return 0;
        }
        if (optname == SO_KEEPALIVE) {
            (void)vls_attr((vls_handle_t)vclgo_fd_to_vlsh(fd),
                           VPPCOM_ATTR_SET_KEEPALIVE, (void *)optval, &len);
            return 0;
        }
    }
    if (level == IPPROTO_IPV6 && optname == IPV6_V6ONLY) {
        (void)vls_attr((vls_handle_t)vclgo_fd_to_vlsh(fd),
                       VPPCOM_ATTR_SET_V6ONLY, (void *)optval, &len);
        vclgo_sock_meta_t meta;
        if (vclgo_fdmap_lookup(fd, &meta) == 0) {
            /* Record what the caller actually asked for, not a hardcoded 1.
             * vclgo_listen's dual-stack override consults this flag: if we
             * had lied and said v6only=1 for a caller that set it to 0, the
             * listen path would skip the forced-1 that keeps Go's parallel
             * AF_INET bind from EADDRINUSE'ing. */
            int want = (optval && optlen >= (socklen_t)sizeof(int))
                       ? (*(const int *)optval != 0) : 0;
            meta.v6only = (uint8_t)want;
            vclgo_fdmap_update(fd, &meta);
        }
        return 0;
    }
    if (level == IPPROTO_TCP && optname == TCP_NODELAY) {
        /* VPP always writes eagerly; treat as accepted no-op. */
        return 0;
    }
    /* Unknown option: silently succeed. Real errors would break stdlib. */
    return 0;
}

int vclgo_getsockopt(int fd, int level, int optname,
                     void *optval, socklen_t *optlen)
{
    if (!vclgo_fd_is_vcl(fd)) return vclgo_set_errno(EBADF);
    if (passthrough_gate() < 0) return -1;
    if (vclgo_pin_current_thread() < 0) return -1;

    if (level == SOL_SOCKET && optname == SO_ERROR) {
        int sockerr = 0;
        uint32_t len = sizeof sockerr;
        (void)vls_attr((vls_handle_t)vclgo_fd_to_vlsh(fd),
                       VPPCOM_ATTR_GET_ERROR, &sockerr, &len);
        if (optval && optlen && *optlen >= (socklen_t)sizeof(int)) {
            memcpy(optval, &sockerr, sizeof sockerr);
            *optlen = sizeof(int);
            return 0;
        }
        return vclgo_set_errno(EINVAL);
    }
    if (optval && optlen && *optlen >= (socklen_t)sizeof(int)) {
        int zero = 0;
        memcpy(optval, &zero, sizeof zero);
        *optlen = sizeof(int);
    }
    return 0;
}

/* ---------- fcntl ---------------------------------------------------- */

int vclgo_fcntl(int fd, int cmd, long arg)
{
    if (!vclgo_fd_is_vcl(fd)) return vclgo_set_errno(EBADF);
    if (passthrough_gate() < 0) return -1;
    if (vclgo_pin_current_thread() < 0) return -1;

    /* Go's net package flips O_NONBLOCK via F_GETFL/F_SETFL. VLS sessions
     * created by vclgo_socket are already non-blocking, so silently accept
     * any F_SETFL request and return a compatible F_GETFL. */
    if (cmd == F_GETFL) return O_NONBLOCK;
    if (cmd == F_SETFL) return 0;
    if (cmd == F_GETFD) return FD_CLOEXEC;
    if (cmd == F_SETFD) return 0;

    (void)arg;
    return vclgo_set_errno(EINVAL);
}

/* ---------- epoll (Phase-1 stub) ------------------------------------- */

int vclgo_epoll_create1(int flags)
{
    /* Phase 1 does not wire Go's epoll into VLS's epoll. Go's netpoller
     * never sees VCL fds because every socket call is intercepted, so this
     * stub simply returns a plain kernel epoll fd. */
    (void)flags;
    return vclgo_set_errno(ENOSYS);
}

int vclgo_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    (void)epfd; (void)op; (void)fd; (void)event;
    return vclgo_set_errno(ENOSYS);
}

int vclgo_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                     int timeout)
{
    (void)epfd; (void)events; (void)maxevents; (void)timeout;
    return vclgo_set_errno(ENOSYS);
}
