/*
 * registry_native.c - exact mapping from real socket-pair surrogates to VLS
 * sessions.  The registry owns no VLS calls; raw sessions are created and
 * destroyed only by their permanently pinned owner worker.
 */

#include "native_internal.h"

#include <time.h>

#define REGISTRY_BUCKETS 4096u

static uint64_t
now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static const char *
trace_op_name(uint16_t op)
{
    switch (op) {
    case VCLGO_TR_ARM:            return "ARM";
    case VCLGO_TR_DISARM:         return "DISARM";
    case VCLGO_TR_SIGNAL_TRY:     return "SIGNAL";
    case VCLGO_TR_SIGNAL_EAGAIN:  return "SIGNAL_EAGAIN";
    case VCLGO_TR_RESET:          return "RESET";
    case VCLGO_TR_EVENT:          return "EVENT";
    case VCLGO_TR_READ:           return "READ";
    case VCLGO_TR_WRITE:          return "WRITE";
    case VCLGO_TR_ACCEPT:         return "ACCEPT";
    case VCLGO_TR_CONNECT:        return "CONNECT";
    default:                      return "?";
    }
}

void
vclgo_session_trace(vclgo_native_session_t *session, uint16_t op,
                    int32_t arg1, int32_t arg2)
{
    uint64_t ts = now_ns();
    vclgo_trace_entry_t *entry =
        &session->trace[session->trace_head % VCLGO_TRACE_RING];
    entry->ts_ns = ts;
    entry->op = op;
    entry->arg1 = arg1;
    entry->arg2 = arg2;
    entry->armed_after = session->armed;
    entry->notified_after = session->notified;
    session->trace_head++;
    session->last_transition_ns = ts;
    if (vclgo_log_level >= 3)
        VCLGO_LOG3("trace fd=%d owner=%u %s a1=%d a2=%d armed=0x%x notified=0x%x",
                   session->fd, session->owner, trace_op_name(op),
                   arg1, arg2, session->armed, session->notified);
}

void
vclgo_session_trace_dump(vclgo_native_session_t *session, const char *reason)
{
    if (vclgo_log_level < 1)
        return;
    fprintf(stderr,
            "[vclgo] === session trace fd=%d vlsh=%d owner=%u reason=%s "
            "armed=0x%x notified=0x%x closing=%d connecting=%d "
            "connect_error=%d ===\n",
            session->fd, (int)session->vlsh, session->owner, reason,
            session->armed, session->notified,
            atomic_load(&session->closing), session->connecting,
            session->connect_error);
    uint64_t start = session->trace_head >= VCLGO_TRACE_RING
                     ? session->trace_head - VCLGO_TRACE_RING
                     : 0;
    for (uint64_t i = start; i < session->trace_head; i++) {
        vclgo_trace_entry_t *entry =
            &session->trace[i % VCLGO_TRACE_RING];
        if (entry->op == VCLGO_TR_NONE)
            continue;
        fprintf(stderr,
                "[vclgo]   +%12llu ns  %-14s  a1=%-8d  a2=%-8d  "
                "armed=0x%x  notified=0x%x\n",
                (unsigned long long)entry->ts_ns,
                trace_op_name(entry->op), entry->arg1, entry->arg2,
                entry->armed_after, entry->notified_after);
    }
}

static pthread_mutex_t g_registry_mu = PTHREAD_MUTEX_INITIALIZER;
static vclgo_native_session_t *g_registry[REGISTRY_BUCKETS];
static size_t g_registry_entries;

static unsigned
registry_bucket(int fd)
{
    return ((unsigned)fd * 2654435761u) & (REGISTRY_BUCKETS - 1u);
}

int
vclgo_native_registry_prepare(void)
{
    struct rlimit lim;

    if (getrlimit(RLIMIT_NOFILE, &lim) != 0)
        return vclgo_set_errno(errno);

    if (lim.rlim_cur < (rlim_t)VCLGO_FD_LIMIT) {
        if (lim.rlim_max < (rlim_t)VCLGO_FD_LIMIT)
            return vclgo_set_errno(EMFILE);
        lim.rlim_cur = (rlim_t)VCLGO_FD_LIMIT;
        if (setrlimit(RLIMIT_NOFILE, &lim) != 0)
            return vclgo_set_errno(errno);
    }
    return 0;
}

static int
surrogate_fill_send_buffer(int fd)
{
    static const uint8_t filler[4096];

    for (;;) {
        ssize_t rv = send(fd, filler, sizeof(filler),
                          MSG_DONTWAIT | MSG_NOSIGNAL);
        if (rv > 0)
            continue;
        if (rv < 0 && errno == EINTR)
            continue;
        if (rv < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 0;
        if (rv == 0)
            errno = EIO;
        return -1;
    }
}

static int
surrogate_drain(int fd)
{
    uint8_t buffer[4096];

    for (;;) {
        ssize_t rv = recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (rv > 0)
            continue;
        if (rv < 0 && errno == EINTR)
            continue;
        if (rv < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return 0;
        if (rv == 0)
            errno = EPIPE;
        return -1;
    }
}

vclgo_native_session_t *
vclgo_native_session_create(vls_handle_t vlsh, unsigned owner,
                            const vclgo_sock_meta_t *meta)
{
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                   0, pair) != 0)
        return NULL;

    /* A full application-side send queue makes EPOLLOUT false until the
     * owner drains the private peer. Keep that filler queue small. */
    int buffer_size = 1024;
    (void)setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF,
                     &buffer_size, sizeof(buffer_size));

    int fd = fcntl(pair[0], F_DUPFD_CLOEXEC, (int)VCLGO_FD_BASE);
    int saved_errno = errno;
    close(pair[0]);
    if (fd < 0) {
        close(pair[1]);
        errno = saved_errno;
        return NULL;
    }
    if (fd >= (int)VCLGO_FD_LIMIT) {
        close(fd);
        close(pair[1]);
        errno = EMFILE;
        return NULL;
    }

    vclgo_native_session_t *session = calloc(1, sizeof(*session));
    if (!session) {
        close(fd);
        close(pair[1]);
        errno = ENOMEM;
        return NULL;
    }

    session->fd = fd;
    session->signal_fd = pair[1];
    session->vlsh = vlsh;
    session->owner = owner;
    if (meta)
        session->meta = *meta;
    atomic_init(&session->refs, 1);
    atomic_init(&session->closing, 0);

    if (surrogate_fill_send_buffer(session->fd) != 0) {
        saved_errno = errno;
        close(session->fd);
        close(session->signal_fd);
        free(session);
        errno = saved_errno;
        return NULL;
    }

    pthread_mutex_lock(&g_registry_mu);
    unsigned bucket = registry_bucket(fd);
    session->hash_next = g_registry[bucket];
    g_registry[bucket] = session;
    g_registry_entries++;
    pthread_mutex_unlock(&g_registry_mu);
    return session;
}

int
vclgo_native_surrogate_reset(vclgo_native_session_t *session,
                             uint32_t events)
{
    uint32_t cleared = 0;
    if ((events & VCLGO_EV_READ) &&
        (session->notified & VCLGO_EV_READ)) {
        if (surrogate_drain(session->fd) != 0)
            return -1;
        session->notified &= ~VCLGO_EV_READ;
        cleared |= VCLGO_EV_READ;
    }

    if ((events & VCLGO_EV_WRITE) &&
        (session->notified & VCLGO_EV_WRITE)) {
        if (surrogate_fill_send_buffer(session->fd) != 0)
            return -1;
        session->notified &= ~VCLGO_EV_WRITE;
        cleared |= VCLGO_EV_WRITE;
    }
    if (cleared)
        vclgo_session_trace(session, VCLGO_TR_RESET,
                            (int32_t)events, (int32_t)cleared);
    return 0;
}

int
vclgo_native_surrogate_signal(vclgo_native_session_t *session,
                              uint32_t events)
{
    if (atomic_load(&session->closing))
        return 0;

    uint32_t signaled = 0;
    int hit_eagain = 0;

    if ((events & VCLGO_EV_READ) &&
        !(session->notified & VCLGO_EV_READ)) {
        uint8_t byte = 1;
        ssize_t rv;
        do {
            rv = send(session->signal_fd, &byte, sizeof(byte),
                      MSG_DONTWAIT | MSG_NOSIGNAL);
        } while (rv < 0 && errno == EINTR);
        if (rv == (ssize_t)sizeof(byte)) {
            session->notified |= VCLGO_EV_READ;
            signaled |= VCLGO_EV_READ;
        } else if (rv < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            /* Do NOT mark notified: the queue is full, but the byte we
             * would have queued is not present. Any prior byte we sent has
             * already been consumed by Go (which would have cleared
             * notified via RESET), so a real missed edge is now impossible
             * only if we retry on the next opportunity. Leaving notified
             * clear is the retry hook. */
            hit_eagain = 1;
        } else {
            return -1;
        }
    }

    if ((events & VCLGO_EV_WRITE) &&
        !(session->notified & VCLGO_EV_WRITE)) {
        if (surrogate_drain(session->signal_fd) != 0)
            return -1;
        session->notified |= VCLGO_EV_WRITE;
        signaled |= VCLGO_EV_WRITE;
    }
    if (hit_eagain)
        vclgo_session_trace(session, VCLGO_TR_SIGNAL_EAGAIN,
                            (int32_t)events, (int32_t)signaled);
    else if (signaled)
        vclgo_session_trace(session, VCLGO_TR_SIGNAL_TRY,
                            (int32_t)events, (int32_t)signaled);
    return 0;
}

vclgo_native_session_t *
vclgo_native_session_lookup(int fd)
{
    if (!vclgo_fd_in_reserved_range(fd))
        return NULL;

    pthread_mutex_lock(&g_registry_mu);
    vclgo_native_session_t *session = g_registry[registry_bucket(fd)];
    while (session && session->fd != fd)
        session = session->hash_next;
    if (session)
        atomic_fetch_add_explicit(&session->refs, 1, memory_order_relaxed);
    pthread_mutex_unlock(&g_registry_mu);
    return session;
}

void
vclgo_native_session_remove(vclgo_native_session_t *session)
{
    if (!session)
        return;

    pthread_mutex_lock(&g_registry_mu);
    unsigned bucket = registry_bucket(session->fd);
    vclgo_native_session_t **link = &g_registry[bucket];
    while (*link) {
        if (*link == session) {
            *link = session->hash_next;
            session->hash_next = NULL;
            g_registry_entries--;
            break;
        }
        link = &(*link)->hash_next;
    }
    pthread_mutex_unlock(&g_registry_mu);
}

void
vclgo_native_session_get(vclgo_native_session_t *session)
{
    if (session)
        atomic_fetch_add_explicit(&session->refs, 1, memory_order_relaxed);
}

void
vclgo_native_session_put(vclgo_native_session_t *session)
{
    if (!session)
        return;
    if (atomic_fetch_sub_explicit(&session->refs, 1,
                                  memory_order_acq_rel) == 1)
        free(session);
}

int
vclgo_native_registry_contains(int fd)
{
    vclgo_native_session_t *session = vclgo_native_session_lookup(fd);
    if (!session)
        return 0;
    vclgo_native_session_put(session);
    return 1;
}

size_t
vclgo_native_registry_size(void)
{
    pthread_mutex_lock(&g_registry_mu);
    size_t count = g_registry_entries;
    pthread_mutex_unlock(&g_registry_mu);
    return count;
}

int
vclgo_owns_fd(int fd)
{
    return vclgo_native_registry_contains(fd);
}
