/*
 * preload.c - native LD_PRELOAD entry point for unmodified Go binaries.
 *
 * Go emits raw SYSCALL instructions, so ordinary ELF symbol interposition
 * cannot see its socket I/O.  This constructor installs a seccomp
 * user-notification filter over syscall instructions in the main executable's
 * text mapping.  The kernel blocks at the normal syscall boundary (after Go's
 * runtime.entersyscall), an unfiltered native helper executes the POSIX-shaped
 * dispatcher call, and the kernel returns the result through Go's untouched
 * syscall wrapper.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "vclgo.h"

#include <asm/unistd.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <link.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef CLOSE_RANGE_UNSHARE
#define CLOSE_RANGE_UNSHARE (1U << 1)
#endif
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif
#ifndef SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (1UL << 5)
#endif

#define MAX_FILTER_INSNS 256
#define MAX_NOTIFIERS 64
#define NOTIFIER_STACK_SIZE (256u * 1024u)

static pthread_mutex_t g_listener_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_listener_cv = PTHREAD_COND_INITIALIZER;
static int g_listener_fd = -1;
static atomic_int g_listener_stop;
static pthread_t g_notifiers[MAX_NOTIFIERS];
static int g_notifier_count;
static struct seccomp_notif_sizes g_notif_sizes;

static void stop_notifiers(void);

typedef struct {
    uintptr_t low;
    uintptr_t high;
    int found;
} text_range_t;

static int
find_main_text(struct dl_phdr_info *info, size_t size, void *opaque)
{
    (void)size;
    text_range_t *range = opaque;
    if (info->dlpi_name && *info->dlpi_name)
        return 0;

    for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *header = &info->dlpi_phdr[i];
        if (header->p_type != PT_LOAD || !(header->p_flags & PF_X))
            continue;
        uintptr_t low = (uintptr_t)info->dlpi_addr + header->p_vaddr;
        uintptr_t high = low + header->p_memsz;
        if (!range->found || low < range->low)
            range->low = low;
        if (!range->found || high > range->high)
            range->high = high;
        range->found = 1;
    }
    return range->found;
}

static void
append_stmt(struct sock_filter *filter, size_t *count,
            unsigned short code, uint32_t value)
{
    filter[(*count)++] = (struct sock_filter)BPF_STMT(code, value);
}

static void
append_jump(struct sock_filter *filter, size_t *count,
            unsigned short code, uint32_t value,
            unsigned char yes, unsigned char no)
{
    filter[(*count)++] =
        (struct sock_filter)BPF_JUMP(code, value, yes, no);
}

static void
append_always_notify_rule(struct sock_filter *filter, size_t *count,
                          int syscall_number)
{
    append_jump(filter, count, BPF_JMP | BPF_JEQ | BPF_K,
                (uint32_t)syscall_number, 0, 1);
    append_stmt(filter, count, BPF_RET | BPF_K,
                SECCOMP_RET_USER_NOTIF);
}

static void
append_fd_rule(struct sock_filter *filter, size_t *count,
               int syscall_number, unsigned argument)
{
    append_jump(filter, count, BPF_JMP | BPF_JEQ | BPF_K,
                (uint32_t)syscall_number, 0, 6);
    append_stmt(filter, count, BPF_LD | BPF_W | BPF_ABS,
                (uint32_t)(offsetof(struct seccomp_data, args) +
                           argument * sizeof(uint64_t)));
    append_jump(filter, count, BPF_JMP | BPF_JGE | BPF_K,
                VCLGO_FD_BASE, 1, 0);
    append_stmt(filter, count, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    append_jump(filter, count, BPF_JMP | BPF_JGE | BPF_K,
                VCLGO_FD_LIMIT, 0, 1);
    append_stmt(filter, count, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    append_stmt(filter, count, BPF_RET | BPF_K,
                SECCOMP_RET_USER_NOTIF);
}

static int
install_filter(void)
{
    text_range_t range = {0};
    dl_iterate_phdr(find_main_text, &range);
    if (!range.found) {
        errno = ENOEXEC;
        return -1;
    }

    uint32_t low_high = (uint32_t)(range.low >> 32);
    uint32_t high_high = (uint32_t)((range.high - 1) >> 32);
    if (low_high != high_high) {
        errno = E2BIG;
        return -1;
    }

    struct sock_filter filter[MAX_FILTER_INSNS];
    size_t count = 0;

    append_stmt(filter, &count, BPF_LD | BPF_W | BPF_ABS,
                offsetof(struct seccomp_data, arch));
    append_jump(filter, &count, BPF_JMP | BPF_JEQ | BPF_K,
                AUDIT_ARCH_X86_64, 1, 0);
    append_stmt(filter, &count, BPF_RET | BPF_K,
                SECCOMP_RET_KILL_PROCESS);

    /* Apply only to raw syscall instructions in the original Go executable.
     * libc/VPP/helper code and a post-fork exec image continue normally. */
    append_stmt(filter, &count, BPF_LD | BPF_W | BPF_ABS,
                offsetof(struct seccomp_data, instruction_pointer) + 4);
    append_jump(filter, &count, BPF_JMP | BPF_JEQ | BPF_K,
                low_high, 1, 0);
    append_stmt(filter, &count, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    append_stmt(filter, &count, BPF_LD | BPF_W | BPF_ABS,
                offsetof(struct seccomp_data, instruction_pointer));
    append_jump(filter, &count, BPF_JMP | BPF_JGE | BPF_K,
                (uint32_t)range.low, 1, 0);
    append_stmt(filter, &count, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    append_jump(filter, &count, BPF_JMP | BPF_JGE | BPF_K,
                (uint32_t)range.high, 0, 1);
    append_stmt(filter, &count, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    append_stmt(filter, &count, BPF_LD | BPF_W | BPF_ABS,
                offsetof(struct seccomp_data, nr));

    append_always_notify_rule(filter, &count, __NR_socket);
    append_always_notify_rule(filter, &count, __NR_exit_group);
#ifdef __NR_close_range
    append_always_notify_rule(filter, &count, __NR_close_range);
#endif

    append_fd_rule(filter, &count, __NR_read, 0);
    append_fd_rule(filter, &count, __NR_write, 0);
    append_fd_rule(filter, &count, __NR_close, 0);
    append_fd_rule(filter, &count, __NR_bind, 0);
    append_fd_rule(filter, &count, __NR_listen, 0);
    append_fd_rule(filter, &count, __NR_accept, 0);
    append_fd_rule(filter, &count, __NR_accept4, 0);
    append_fd_rule(filter, &count, __NR_connect, 0);
    append_fd_rule(filter, &count, __NR_shutdown, 0);
    append_fd_rule(filter, &count, __NR_getsockname, 0);
    append_fd_rule(filter, &count, __NR_getpeername, 0);
    append_fd_rule(filter, &count, __NR_setsockopt, 0);
    append_fd_rule(filter, &count, __NR_getsockopt, 0);
    append_fd_rule(filter, &count, __NR_readv, 0);
    append_fd_rule(filter, &count, __NR_writev, 0);
    append_fd_rule(filter, &count, __NR_recvfrom, 0);
    append_fd_rule(filter, &count, __NR_sendto, 0);
    append_fd_rule(filter, &count, __NR_recvmsg, 0);
    append_fd_rule(filter, &count, __NR_sendmsg, 0);
    append_fd_rule(filter, &count, __NR_fcntl, 0);
    append_fd_rule(filter, &count, __NR_dup, 0);
    append_fd_rule(filter, &count, __NR_dup2, 0);
    append_fd_rule(filter, &count, __NR_dup3, 0);
    append_fd_rule(filter, &count, __NR_sendfile, 0);

    append_stmt(filter, &count, BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    if (count > MAX_FILTER_INSNS) {
        errno = E2BIG;
        return -1;
    }

    struct sock_fprog program = {
        .len = (unsigned short)count,
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;

    int fd = (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                          SECCOMP_FILTER_FLAG_NEW_LISTENER |
                          SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
                          &program);
    if (fd < 0)
        return -1;

    /* The kernel does not open the notification fd with FD_CLOEXEC.  Anything
     * the target subsequently `exec`s would otherwise inherit an active
     * seccomp notification listener for our process. */
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int
notification_is_local(pid_t tid)
{
    char path[64];
    int length = snprintf(path, sizeof(path), "/proc/self/task/%d", tid);
    if (length <= 0 || (size_t)length >= sizeof(path))
        return 0;
    struct stat st;
    return stat(path, &st) == 0;
}

static int
should_route_socket(int domain, int type, int protocol)
{
    int socket_type = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    return (domain == AF_INET || domain == AF_INET6) &&
           socket_type == SOCK_STREAM &&
           (protocol == 0 || protocol == IPPROTO_TCP);
}

static ssize_t
dispatch_writev(int fd, const struct iovec *iov, int iov_count)
{
    if (!iov || iov_count < 0 || iov_count > IOV_MAX) {
        errno = EINVAL;
        return -1;
    }

    ssize_t total = 0;
    for (int i = 0; i < iov_count; i++) {
        const uint8_t *data = iov[i].iov_base;
        size_t remaining = iov[i].iov_len;
        while (remaining) {
            size_t requested = remaining;
            ssize_t rv = vclgo_write(fd, data, remaining);
            if (rv < 0)
                return total ? total : -1;
            total += rv;
            data += rv;
            remaining -= (size_t)rv;
            if ((size_t)rv < requested)
                return total;
        }
    }
    return total;
}

static ssize_t
dispatch_readv(int fd, const struct iovec *iov, int iov_count)
{
    if (!iov || iov_count < 0 || iov_count > IOV_MAX) {
        errno = EINVAL;
        return -1;
    }

    /* Read directly into each caller iovec buffer in turn. This is fully
     * bounded (no intermediate allocation, no per-call malloc growth)
     * and matches kernel readv(2) partial-fill semantics: as soon as a
     * vls_read returns fewer bytes than requested, or 0, or EAGAIN after
     * we already have bytes, we stop and return the accumulated total.
     * A hard error before any bytes were read is propagated as -1. */
    ssize_t total = 0;
    for (int i = 0; i < iov_count; i++) {
        if (iov[i].iov_len == 0)
            continue;
        ssize_t rv = vclgo_read(fd, iov[i].iov_base, iov[i].iov_len);
        if (rv < 0)
            return total ? total : -1;
        if (rv == 0)
            return total;
        total += rv;
        if ((size_t)rv < iov[i].iov_len)
            return total;
    }
    return total;
}

static ssize_t
dispatch_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    uint8_t buffer[64 * 1024];
    size_t remaining = count;
    ssize_t total = 0;

    while (remaining) {
        size_t chunk = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        ssize_t nr = offset ? pread(in_fd, buffer, chunk, *offset)
                            : read(in_fd, buffer, chunk);
        if (nr < 0)
            return total ? total : -1;
        if (nr == 0)
            return total;

        ssize_t nw = vclgo_write(out_fd, buffer, (size_t)nr);
        if (nw < 0)
            return total ? total : -1;
        if (offset)
            *offset += nw;
        total += nw;
        remaining -= (size_t)nw;
        if (nw < nr)
            return total;
    }
    return total;
}

static long
dispatch_notification(const struct seccomp_notif *request, int *continued)
{
    int nr = request->data.nr;
    int fd = (int)request->data.args[0];
    *continued = 0;

    if (nr == __NR_exit_group) {
        /* vclgo_teardown() is synchronous: the CAS winner runs the pool
         * shutdown, and losing notifiers block inside the call until the
         * winner publishes STOPPED. Only then may we set `continued=1`
         * and hand `exit_group` back to the kernel, otherwise a losing
         * notifier would let the kernel start do_exit on that thread
         * while the winner is still inside vppcom_app_destroy. */
        vclgo_teardown();
        *continued = 1;
        return 0;
    }

#ifdef __NR_close_range
    if (nr == __NR_close_range) {
        unsigned first = (unsigned)request->data.args[0];
        unsigned last = (unsigned)request->data.args[1];
        unsigned flags = (unsigned)request->data.args[2];
        if (flags & CLOSE_RANGE_UNSHARE) {
            errno = EOPNOTSUPP;
            return -1;
        }
        if (!(flags & CLOSE_RANGE_CLOEXEC)) {
            unsigned low = first > VCLGO_FD_BASE ? first : VCLGO_FD_BASE;
            unsigned high = last < VCLGO_FD_LIMIT - 1 ?
                            last : VCLGO_FD_LIMIT - 1;
            for (unsigned candidate = low;
                 candidate <= high && candidate < VCLGO_FD_LIMIT;
                 candidate++) {
                if (vclgo_owns_fd((int)candidate))
                    (void)vclgo_close((int)candidate);
            }
        }
        *continued = 1;
        return 0;
    }
#endif

    if (nr == __NR_socket) {
        int domain = (int)request->data.args[0];
        int type = (int)request->data.args[1];
        int protocol = (int)request->data.args[2];
        if (!should_route_socket(domain, type, protocol)) {
            *continued = 1;
            return 0;
        }
        return vclgo_socket(domain, type, protocol);
    }

    if (!vclgo_owns_fd(fd)) {
        *continued = 1;
        return 0;
    }

    switch (nr) {
    case __NR_read:
        return vclgo_read(fd, (void *)request->data.args[1],
                          (size_t)request->data.args[2]);
    case __NR_write:
        return vclgo_write(fd, (const void *)request->data.args[1],
                           (size_t)request->data.args[2]);
    case __NR_close:
        return vclgo_close(fd);
    case __NR_bind:
        return vclgo_bind(fd,
                          (const struct sockaddr *)request->data.args[1],
                          (socklen_t)request->data.args[2]);
    case __NR_listen:
        return vclgo_listen(fd, (int)request->data.args[1]);
    case __NR_accept:
        return vclgo_accept(
            fd, (struct sockaddr *)request->data.args[1],
            (socklen_t *)request->data.args[2]);
    case __NR_accept4:
        return vclgo_accept4(
            fd, (struct sockaddr *)request->data.args[1],
            (socklen_t *)request->data.args[2],
            (int)request->data.args[3]);
    case __NR_connect:
        return vclgo_connect(
            fd, (const struct sockaddr *)request->data.args[1],
            (socklen_t)request->data.args[2]);
    case __NR_shutdown:
        return vclgo_shutdown(fd, (int)request->data.args[1]);
    case __NR_getsockname:
        return vclgo_getsockname(
            fd, (struct sockaddr *)request->data.args[1],
            (socklen_t *)request->data.args[2]);
    case __NR_getpeername:
        return vclgo_getpeername(
            fd, (struct sockaddr *)request->data.args[1],
            (socklen_t *)request->data.args[2]);
    case __NR_setsockopt:
        return vclgo_setsockopt(
            fd, (int)request->data.args[1],
            (int)request->data.args[2],
            (const void *)request->data.args[3],
            (socklen_t)request->data.args[4]);
    case __NR_getsockopt:
        return vclgo_getsockopt(
            fd, (int)request->data.args[1],
            (int)request->data.args[2],
            (void *)request->data.args[3],
            (socklen_t *)request->data.args[4]);
    case __NR_writev:
        return dispatch_writev(
            fd, (const struct iovec *)request->data.args[1],
            (int)request->data.args[2]);
    case __NR_readv:
        return dispatch_readv(
            fd, (const struct iovec *)request->data.args[1],
            (int)request->data.args[2]);
    case __NR_sendto:
        return vclgo_write(fd, (const void *)request->data.args[1],
                           (size_t)request->data.args[2]);
    case __NR_recvfrom: {
        ssize_t rv = vclgo_read(fd, (void *)request->data.args[1],
                                (size_t)request->data.args[2]);
        if (rv >= 0 && request->data.args[4] && request->data.args[5])
            (void)vclgo_getpeername(
                fd, (struct sockaddr *)request->data.args[4],
                (socklen_t *)request->data.args[5]);
        return rv;
    }
    case __NR_sendmsg: {
        const struct msghdr *message =
            (const struct msghdr *)request->data.args[1];
        if (!message) {
            errno = EFAULT;
            return -1;
        }
        return dispatch_writev(fd, message->msg_iov,
                               (int)message->msg_iovlen);
    }
    case __NR_recvmsg: {
        struct msghdr *message =
            (struct msghdr *)request->data.args[1];
        if (!message) {
            errno = EFAULT;
            return -1;
        }
        ssize_t rv = dispatch_readv(fd, message->msg_iov,
                                    (int)message->msg_iovlen);
        if (rv >= 0)
            message->msg_flags = 0;
        return rv;
    }
    case __NR_fcntl: {
        int command = (int)request->data.args[1];
        if (command == F_DUPFD || command == F_DUPFD_CLOEXEC) {
            errno = EOPNOTSUPP;
            return -1;
        }
        *continued = 1;
        return 0;
    }
    case __NR_dup:
    case __NR_dup2:
    case __NR_dup3:
        errno = EOPNOTSUPP;
        return -1;
    case __NR_sendfile:
        return dispatch_sendfile(
            fd, (int)request->data.args[1],
            (off_t *)request->data.args[2],
            (size_t)request->data.args[3]);
    default:
        *continued = 1;
        return 0;
    }
}

static void
fill_response(struct seccomp_notif_resp *response, uint64_t id,
              long result, int saved_errno, int continued)
{
    memset(response, 0, g_notif_sizes.seccomp_notif_resp);
    response->id = id;
    if (continued) {
        response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        return;
    }
    if (result < 0) {
        response->error = -(saved_errno ? saved_errno : EIO);
        return;
    }
    response->val = result;
}

static void *
notifier_main(void *unused)
{
    (void)unused;
    pthread_setname_np(pthread_self(), "vclgo-notify");

    pthread_mutex_lock(&g_listener_mu);
    while (g_listener_fd < 0 && !atomic_load(&g_listener_stop))
        pthread_cond_wait(&g_listener_cv, &g_listener_mu);
    int listener = g_listener_fd;
    int stop = atomic_load(&g_listener_stop);
    pthread_mutex_unlock(&g_listener_mu);
    if (stop)
        return NULL;

    struct seccomp_notif *request =
        calloc(1, g_notif_sizes.seccomp_notif);
    struct seccomp_notif_resp *response =
        calloc(1, g_notif_sizes.seccomp_notif_resp);
    if (!request || !response) {
        free(request);
        free(response);
        return NULL;
    }

    while (!atomic_load(&g_listener_stop)) {
        memset(request, 0, g_notif_sizes.seccomp_notif);
        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, request) != 0) {
            if (errno == EINTR || errno == ENOENT)
                continue;
            /* Closed listener is the documented clean-stop signal. */
            if (errno == EBADF || errno == ENOTCONN)
                break;
            continue;
        }

        if (!notification_is_local(request->pid)) {
            fill_response(response, request->id, 0, 0, 1);
        } else if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID,
                         &request->id) != 0) {
            continue;
        } else {
            int continued = 0;
            errno = 0;
            long result = dispatch_notification(request, &continued);
            int saved_errno = errno;
            fill_response(response, request->id, result, saved_errno,
                          continued);
        }

        if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, response) != 0 &&
            errno != ENOENT)
            continue;
    }

    free(request);
    free(response);
    return NULL;
}

static int
parse_notifier_count(void)
{
    const char *value = getenv("VCLGO_NOTIFIERS");
    if (value && *value) {
        char *end = NULL;
        long count = strtol(value, &end, 10);
        if (!end || *end || count < 1 || count > MAX_NOTIFIERS) {
            errno = EINVAL;
            return -1;
        }
        return (int)count;
    }

    int count = vclgo_worker_count() * 4;
    if (count < 16)
        count = 16;
    if (count > MAX_NOTIFIERS)
        count = MAX_NOTIFIERS;
    return count;
}

static int
start_interceptor(void)
{
    if (syscall(__NR_seccomp, SECCOMP_GET_NOTIF_SIZES, 0,
                &g_notif_sizes) != 0)
        return -1;

    int count = parse_notifier_count();
    if (count < 0)
        return -1;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, NOTIFIER_STACK_SIZE);
    for (int i = 0; i < count; i++) {
        int rv = pthread_create(&g_notifiers[i], &attr,
                                notifier_main, NULL);
        if (rv != 0) {
            pthread_attr_destroy(&attr);
            errno = rv;
            goto fail_threads;
        }
        g_notifier_count++;
    }
    pthread_attr_destroy(&attr);

    /* Only this initial Go thread receives the filter.  VCL owners and
     * notifier helpers already exist and stay unfiltered; future Go runtime
     * threads inherit the filter from this one. */
    int listener = install_filter();
    if (listener < 0)
        goto fail_threads;

    pthread_mutex_lock(&g_listener_mu);
    g_listener_fd = listener;
    pthread_cond_broadcast(&g_listener_cv);
    pthread_mutex_unlock(&g_listener_mu);
    return 0;

fail_threads:
    stop_notifiers();
    return -1;
}

/* Terminates the notifier pool. Idempotent. Safe to call from `_fini` or
 * from a failure path in `start_interceptor`. Not safe to call from
 * inside a notifier itself (a thread cannot join itself); that case is
 * handled by the exit_group path, which does the process-exit in the
 * kernel after teardown has completed. */
static void
stop_notifiers(void)
{
    pthread_mutex_lock(&g_listener_mu);
    atomic_store(&g_listener_stop, 1);
    int fd = g_listener_fd;
    g_listener_fd = -1;
    pthread_cond_broadcast(&g_listener_cv);
    pthread_mutex_unlock(&g_listener_mu);

    /* Closing the listener wakes any notifier blocked in
     * SECCOMP_IOCTL_NOTIF_RECV with EBADF, which exits the loop cleanly. */
    if (fd >= 0)
        (void)close(fd);

    pthread_t self = pthread_self();
    for (int i = 0; i < g_notifier_count; i++) {
        if (pthread_equal(g_notifiers[i], self))
            continue;
        (void)pthread_join(g_notifiers[i], NULL);
    }
    g_notifier_count = 0;
}

__attribute__((constructor(200)))
static void
vclgo_preload_init(void)
{
    if (getenv("VCLGO_DISABLE"))
        return;

    if (vclgo_init("vclgo-preload") != 0) {
        int saved_errno = errno;
        dprintf(STDERR_FILENO,
                "[vclgo/preload] dispatcher initialization failed: %s\n",
                strerror(saved_errno));
        _exit(125);
    }
    if (vclgo_passthrough())
        return;

    if (start_interceptor() != 0) {
        int saved_errno = errno;
        dprintf(STDERR_FILENO,
                "[vclgo/preload] seccomp notification setup failed: %s\n",
                strerror(saved_errno));
        vclgo_teardown();
        _exit(126);
    }

    dprintf(STDERR_FILENO,
            "[vclgo/preload] active: %d VCL owner workers, %d notifiers\n",
            vclgo_worker_count(), g_notifier_count);
}

__attribute__((destructor(200)))
static void
vclgo_preload_fini(void)
{
    /* Ordering matters: stop the notifier pool first so no thread is
     * still blocked in SECCOMP_IOCTL_NOTIF_RECV or holding a reference
     * to VCL state, then run the (idempotent, synchronous) dispatcher
     * teardown. The exit_group syscall interception has usually already
     * driven vclgo_teardown() by this point, in which case it is a
     * fast no-op. */
    stop_notifiers();
    vclgo_teardown();
}
