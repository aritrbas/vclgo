/*
 * api_native.c - POSIX-shaped public dispatcher API backed by owner workers.
 */

#include "native_internal.h"

#include <netinet/in.h>

static int
active_gate(void)
{
    int state = atomic_load(&vclgo_state);
    if (state == VCLGO_STATE_ACTIVE)
        return 0;
    return vclgo_set_errno(state == VCLGO_STATE_STOPPING ?
                           ECANCELED : ENOSYS);
}

static int
owned_gate(int fd)
{
    if (active_gate() < 0)
        return -1;
    if (!vclgo_owns_fd(fd))
        return vclgo_set_errno(EBADF);
    return 0;
}

int
vclgo_socket(int domain, int type, int protocol)
{
    if (active_gate() < 0)
        return -1;
    if (domain != AF_INET && domain != AF_INET6)
        return vclgo_set_errno(EAFNOSUPPORT);

    int socket_type = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (socket_type == SOCK_STREAM) {
        if (protocol != 0 && protocol != IPPROTO_TCP)
            return vclgo_set_errno(EPROTONOSUPPORT);
    } else if (socket_type == SOCK_DGRAM) {
        if (protocol != 0 && protocol != IPPROTO_UDP)
            return vclgo_set_errno(EPROTONOSUPPORT);
    } else {
        return vclgo_set_errno(ESOCKTNOSUPPORT);
    }

    return vclgo_native_socket(domain, type, protocol);
}

int
vclgo_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (owned_gate(fd) < 0)
        return -1;
    return vclgo_native_bind(fd, addr, addrlen);
}

int
vclgo_listen(int fd, int backlog)
{
    if (owned_gate(fd) < 0)
        return -1;
    return vclgo_native_listen(fd, backlog);
}

int
vclgo_accept4(int fd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
    if (owned_gate(fd) < 0)
        return -1;
    int rv = vclgo_native_accept4(fd, addr, addrlen, flags);
    if (rv < 0 && errno == EAGAIN)
        atomic_fetch_add(&vclgo_stat_eagain_parked, 1);
    return rv;
}

int
vclgo_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    return vclgo_accept4(fd, addr, addrlen, 0);
}

int
vclgo_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    if (owned_gate(fd) < 0)
        return -1;
    return vclgo_native_connect(fd, addr, addrlen);
}

int
vclgo_shutdown(int fd, int how)
{
    if (owned_gate(fd) < 0)
        return -1;
    return vclgo_native_shutdown(fd, how);
}

int
vclgo_close(int fd)
{
    if (owned_gate(fd) < 0)
        return -1;
    return vclgo_native_close(fd);
}

ssize_t
vclgo_read(int fd, void *buf, size_t count)
{
    if (owned_gate(fd) < 0)
        return -1;
    ssize_t rv = vclgo_native_read(fd, buf, count);
    if (rv < 0 && errno == EAGAIN)
        atomic_fetch_add(&vclgo_stat_eagain_parked, 1);
    return rv;
}

ssize_t
vclgo_write(int fd, const void *buf, size_t count)
{
    if (owned_gate(fd) < 0)
        return -1;
    ssize_t rv = vclgo_native_write(fd, buf, count);
    if (rv < 0 && errno == EAGAIN)
        atomic_fetch_add(&vclgo_stat_eagain_parked, 1);
    return rv;
}

ssize_t
vclgo_sendto(int fd, const void *buf, size_t count, int flags,
             const struct sockaddr *dest_addr, socklen_t addrlen)
{
    if (owned_gate(fd) < 0)
        return -1;
    ssize_t rv = vclgo_native_sendto(fd, buf, count, flags,
                                     dest_addr, addrlen);
    if (rv < 0 && errno == EAGAIN)
        atomic_fetch_add(&vclgo_stat_eagain_parked, 1);
    return rv;
}

ssize_t
vclgo_recvfrom(int fd, void *buf, size_t count, int flags,
               struct sockaddr *src_addr, socklen_t *addrlen)
{
    if (owned_gate(fd) < 0)
        return -1;
    ssize_t rv = vclgo_native_recvfrom(fd, buf, count, flags,
                                       src_addr, addrlen);
    if (rv < 0 && errno == EAGAIN)
        atomic_fetch_add(&vclgo_stat_eagain_parked, 1);
    return rv;
}

int
vclgo_setsockopt(int fd, int level, int optname,
                 const void *optval, socklen_t optlen)
{
    if (owned_gate(fd) < 0)
        return -1;
    return vclgo_native_setsockopt(fd, level, optname, optval, optlen);
}

int
vclgo_getsockopt(int fd, int level, int optname,
                 void *optval, socklen_t *optlen)
{
    if (owned_gate(fd) < 0)
        return -1;
    return vclgo_native_getsockopt(fd, level, optname, optval, optlen);
}

int
vclgo_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    if (owned_gate(fd) < 0)
        return -1;
    return vclgo_native_getsockname(fd, addr, addrlen);
}

int
vclgo_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    if (owned_gate(fd) < 0)
        return -1;
    return vclgo_native_getpeername(fd, addr, addrlen);
}

int
vclgo_fcntl(int fd, int cmd, long arg)
{
    (void)arg;
    if (owned_gate(fd) < 0)
        return -1;

    switch (cmd) {
    case F_GETFL:
        return O_RDWR | O_NONBLOCK;
    case F_SETFL:
    case F_GETFD:
    case F_SETFD:
        return cmd == F_GETFD ? FD_CLOEXEC : 0;
    default:
        return vclgo_set_errno(EOPNOTSUPP);
    }
}

int
vclgo_epoll_create1(int flags)
{
    (void)flags;
    return vclgo_set_errno(ENOSYS);
}

int
vclgo_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    (void)epfd;
    (void)op;
    (void)fd;
    (void)event;
    return vclgo_set_errno(ENOSYS);
}

int
vclgo_epoll_wait(int epfd, struct epoll_event *events, int maxevents,
                 int timeout)
{
    (void)epfd;
    (void)events;
    (void)maxevents;
    (void)timeout;
    return vclgo_set_errno(ENOSYS);
}
