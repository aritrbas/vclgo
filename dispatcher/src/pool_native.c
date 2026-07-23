/*
 * pool_native.c - owner-routed VCL worker pool.
 *
 * Every raw VLS handle is touched only by one permanently pinned pthread.
 * Calls from the Approach #4 fastpath preload's interceptor threads are
 * short synchronous queue submissions. EAGAIN is returned to Go after the
 * owner arms VLS epoll; readiness is relayed through a real socket-pair
 * surrogate so Go's normal runtime netpoller, deadlines, and cancellation
 * remain authoritative.
 */

#include "native_internal.h"

#include <arpa/inet.h>
#include <limits.h>
#include <time.h>

#define WORKER_BATCH 128
#define WORKER_EPOLL_EVENTS 128
#define WORKER_POLL_SECONDS 0.001
#define CONNECT_ERROR_POLL_NS   (50L * 1000L * 1000L)
#define WATCHDOG_POLL_NS        (1L * 1000L * 1000L * 1000L)   /* 1s */
#define WATCHDOG_STALL_NS       (5L * 1000L * 1000L * 1000L)   /* 5s */
#define WATCHDOG_REDUMP_NS      (5L * 1000L * 1000L * 1000L)

/* VCL treats UDP bind(port=0) as a literal bind to port zero. Allocate a
 * real ephemeral port before entering VLS so getsockname() and reply
 * demultiplexing have normal POSIX semantics. */
#define UDP_EPHEMERAL_MIN       32768U
#define UDP_EPHEMERAL_MAX       60999U
#define UDP_EPHEMERAL_ATTEMPTS  128U
#define UDP_SOURCE_CACHE_SLOTS  8U

typedef enum {
    NOP_SOCKET,
    NOP_BIND,
    NOP_LISTEN,
    NOP_ACCEPT,
    NOP_CONNECT,
    NOP_SHUTDOWN,
    NOP_CLOSE,
    NOP_READ,
    NOP_WRITE,
    NOP_SETSOCKOPT,
    NOP_GETSOCKOPT,
    NOP_GETSOCKNAME,
    NOP_GETPEERNAME,
    /* UDP-aware entrypoints. NOP_READ/NOP_WRITE remain for the
     * connected TCP fast path; sendto/recvfrom carry an optional
     * per-datagram address on both send and receive. */
    NOP_SENDTO,
    NOP_RECVFROM,
} native_op_t;

typedef struct native_request {
    native_op_t op;
    vclgo_native_session_t *session;

    int int1;
    int int2;
    int int3;
    const struct sockaddr *addr;
    socklen_t addrlen;
    struct sockaddr *out_addr;
    socklen_t *out_addrlen;
    void *buf;
    const void *const_buf;
    size_t count;
    void *optval;
    const void *const_optval;
    socklen_t *optlen;
    socklen_t optlen_value;
    int flags;               /* MSG_* flags for send/recv variants */

    ssize_t rv;
    int error_value;
    int done;

    pthread_mutex_t mu;
    pthread_cond_t cv;
    struct native_request *next;
} native_request_t;

typedef struct native_udp_source_cache {
    struct sockaddr_storage peer;
    socklen_t peer_len;
    uint8_t source_ip[16];
    uint8_t is_ip4;
    int valid;
} native_udp_source_cache_t;

typedef struct native_worker {
    unsigned id;
    int bootstrap;
    pthread_t thread;

    pthread_mutex_t queue_mu;
    native_request_t *queue_head;
    native_request_t *queue_tail;
    int accepting;
    atomic_int stop;

    pthread_mutex_t state_mu;
    pthread_cond_t state_cv;
    int registered;
    int register_error;
    int ready;
    int ready_error;
    int quiesced;
    int destroy_requested;
    int destroyed;
    int detach_only;

    int ep_vlsh;
    vclgo_native_session_t *sessions;
    native_udp_source_cache_t udp_source_cache[UDP_SOURCE_CACHE_SLOTS];
    unsigned udp_source_cache_next;
} native_worker_t;

static native_worker_t g_workers[VCLGO_MAX_WORKERS];
static pthread_once_t g_workers_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_start_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_start_cv = PTHREAD_COND_INITIALIZER;
static int g_start_released;
static int g_worker_count;
static int g_mode2;
static char g_app_name[64];
static atomic_uint g_round_robin;
static atomic_uint g_udp_ephemeral_ticket;
static atomic_int g_pool_active;

static uint16_t
next_udp_ephemeral_port(void)
{
    const uint32_t span = UDP_EPHEMERAL_MAX - UDP_EPHEMERAL_MIN + 1U;
    uint32_t ticket = atomic_fetch_add(&g_udp_ephemeral_ticket, 1U);
    uint32_t process_seed = (uint32_t)getpid() * 2654435761U;

    return (uint16_t)(UDP_EPHEMERAL_MIN +
                      ((process_seed + ticket) % span));
}

static socklen_t
sockaddr_size(const struct sockaddr *addr, socklen_t addrlen)
{
    if (!addr)
        return 0;
    if (addr->sa_family == AF_INET &&
        addrlen >= (socklen_t)sizeof(struct sockaddr_in))
        return sizeof(struct sockaddr_in);
    if (addr->sa_family == AF_INET6 &&
        addrlen >= (socklen_t)sizeof(struct sockaddr_in6))
        return sizeof(struct sockaddr_in6);
    return 0;
}

static void
sockaddr_set_port(struct sockaddr_storage *addr, uint16_t port)
{
    if (addr->ss_family == AF_INET)
        ((struct sockaddr_in *)addr)->sin_port = htons(port);
    else
        ((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
}

static int
sockaddr_is_wildcard(const struct sockaddr *addr, socklen_t addrlen)
{
    if (addr->sa_family == AF_INET &&
        addrlen >= (socklen_t)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *sin =
            (const struct sockaddr_in *)addr;
        return sin->sin_addr.s_addr == htonl(INADDR_ANY);
    }
    if (addr->sa_family == AF_INET6 &&
        addrlen >= (socklen_t)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *sin6 =
            (const struct sockaddr_in6 *)addr;
        return IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr);
    }
    return 0;
}

/* UDP source routing is independent of the destination port. */
static int
sockaddr_same_route(const struct sockaddr_storage *cached,
                    socklen_t cached_len, const struct sockaddr *addr,
                    socklen_t addrlen)
{
    if (cached->ss_family != addr->sa_family)
        return 0;
    if (addr->sa_family == AF_INET &&
        cached_len >= (socklen_t)sizeof(struct sockaddr_in) &&
        addrlen >= (socklen_t)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *left =
            (const struct sockaddr_in *)cached;
        const struct sockaddr_in *right =
            (const struct sockaddr_in *)addr;
        return left->sin_addr.s_addr == right->sin_addr.s_addr;
    }
    if (addr->sa_family == AF_INET6 &&
        cached_len >= (socklen_t)sizeof(struct sockaddr_in6) &&
        addrlen >= (socklen_t)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *left =
            (const struct sockaddr_in6 *)cached;
        const struct sockaddr_in6 *right =
            (const struct sockaddr_in6 *)addr;
        return left->sin6_scope_id == right->sin6_scope_id &&
               memcmp(&left->sin6_addr, &right->sin6_addr,
                      sizeof(left->sin6_addr)) == 0;
    }
    return 0;
}

static int
session_connected_endpoint(vclgo_native_session_t *session,
                           vppcom_endpt_t *endpoint, uint8_t ip[16])
{
    if (!session->has_connected_peer)
        return vclgo_set_errno(EDESTADDRREQ);
    return vclgo_sockaddr_to_endpt(
        (const struct sockaddr *)&session->connected_peer,
        session->connected_peer_len, endpoint, ip);
}

/*
 * VCL selects a connectionless source only while auto-binding a CLOSED
 * session. Go has already bound ListenPacket sockets, so an existing
 * wildcard VCL listener would otherwise transmit with 0.0.0.0/:: as its
 * source. Resolve the route through a short-lived blocking UDP session
 * owned by this same pinned worker, then copy the selected address and the
 * real bound port into the original session's application-side metadata.
 * The VPP listener itself remains wildcard-bound for reply delivery.
 */
static int
session_select_wildcard_source(vclgo_native_session_t *session,
                               native_worker_t *worker,
                               const struct sockaddr *peer,
                               socklen_t peer_len,
                               vppcom_endpt_t *peer_endpoint)
{
    if (!session->meta.is_dgram || !session->wildcard_bound ||
        session->has_connected_peer)
        return 0;
    if (session->has_source_route_peer &&
        sockaddr_same_route(&session->source_route_peer,
                            session->source_route_peer_len,
                            peer, peer_len))
        return 0;

    native_udp_source_cache_t *cached = NULL;
    for (unsigned i = 0; i < UDP_SOURCE_CACHE_SLOTS; i++) {
        native_udp_source_cache_t *candidate =
            &worker->udp_source_cache[i];
        if (candidate->valid &&
            sockaddr_same_route(&candidate->peer,
                                candidate->peer_len, peer, peer_len)) {
            cached = candidate;
            break;
        }
    }

    if (!cached) {
        vls_handle_t probe = vls_create(VPPCOM_PROTO_UDP, 0);
        if (probe < 0)
            return (int)probe;

        int rv = vls_connect(probe, peer_endpoint);
        vppcom_endpt_t probe_local;
        uint8_t probe_ip[16] = {0};
        if (rv >= 0) {
            memset(&probe_local, 0, sizeof(probe_local));
            probe_local.ip = probe_ip;
            uint32_t probe_len = sizeof(probe_local);
            rv = vls_attr(probe, VPPCOM_ATTR_GET_LCL_ADDR,
                          &probe_local, &probe_len);
        }
        (void)vls_close(probe);
        if (rv < 0)
            return rv;

        cached = &worker->udp_source_cache[
            worker->udp_source_cache_next++ % UDP_SOURCE_CACHE_SLOTS];
        memset(cached, 0, sizeof(*cached));
        socklen_t route_len = sockaddr_size(peer, peer_len);
        memcpy(&cached->peer, peer, route_len);
        cached->peer_len = route_len;
        cached->is_ip4 = probe_local.is_ip4;
        memcpy(cached->source_ip, probe_ip,
               probe_local.is_ip4 ? 4U : 16U);
        cached->valid = 1;
    }

    vppcom_endpt_t local_endpoint;
    memset(&local_endpoint, 0, sizeof(local_endpoint));
    local_endpoint.ip = cached->source_ip;
    local_endpoint.is_ip4 = cached->is_ip4;

    if (session->bound_addr.ss_family == AF_INET) {
        const struct sockaddr_in *sin =
            (const struct sockaddr_in *)&session->bound_addr;
        local_endpoint.port = sin->sin_port;
    } else {
        const struct sockaddr_in6 *sin6 =
            (const struct sockaddr_in6 *)&session->bound_addr;
        local_endpoint.port = sin6->sin6_port;
    }

    uint32_t endpoint_len = sizeof(local_endpoint);
    int rv = vls_attr(session->vlsh, VPPCOM_ATTR_SET_LCL_ADDR,
                      &local_endpoint, &endpoint_len);
    if (rv < 0)
        return rv;

    socklen_t copy_len = sockaddr_size(peer, peer_len);
    memset(&session->source_route_peer, 0,
           sizeof(session->source_route_peer));
    memcpy(&session->source_route_peer, peer, copy_len);
    session->source_route_peer_len = copy_len;
    session->has_source_route_peer = 1;
    return 0;
}

static int
session_take_socket_error(vclgo_native_session_t *session,
                          native_request_t *request)
{
    if (!session->socket_error)
        return 0;
    request->rv = -1;
    request->error_value = session->socket_error;
    session->socket_error = 0;
    return -1;
}

static void
workers_init_once(void)
{
    for (unsigned i = 0; i < VCLGO_MAX_WORKERS; i++) {
        native_worker_t *worker = &g_workers[i];
        worker->id = i;
        worker->ep_vlsh = -1;
        pthread_mutex_init(&worker->queue_mu, NULL);
        pthread_mutex_init(&worker->state_mu, NULL);
        pthread_cond_init(&worker->state_cv, NULL);
    }
}

static void
worker_reset(native_worker_t *worker, unsigned id)
{
    worker->id = id;
    worker->bootstrap = id == 0;
    worker->queue_head = NULL;
    worker->queue_tail = NULL;
    worker->accepting = 1;
    atomic_store(&worker->stop, 0);

    worker->registered = 0;
    worker->register_error = 0;
    worker->ready = 0;
    worker->ready_error = 0;
    worker->quiesced = 0;
    worker->destroy_requested = 0;
    worker->destroyed = 0;
    worker->detach_only = 0;
    worker->ep_vlsh = -1;
    worker->sessions = NULL;
    memset(worker->udp_source_cache, 0,
           sizeof(worker->udp_source_cache));
    worker->udp_source_cache_next = 0;
}

static native_worker_t *
pick_worker(void)
{
    unsigned count = (unsigned)g_worker_count;
    if (count == 0)
        return NULL;
    unsigned index = atomic_fetch_add(&g_round_robin, 1) % count;
    return &g_workers[index];
}

static void
request_finish(native_request_t *request, ssize_t rv, int error_value)
{
    pthread_mutex_lock(&request->mu);
    request->rv = rv;
    request->error_value = error_value;
    request->done = 1;
    pthread_cond_signal(&request->cv);
    pthread_mutex_unlock(&request->mu);
}

static int
request_init(native_request_t *request, native_op_t op)
{
    memset(request, 0, sizeof(*request));
    request->op = op;
    if (pthread_mutex_init(&request->mu, NULL) != 0)
        return vclgo_set_errno(ENOMEM);
    if (pthread_cond_init(&request->cv, NULL) != 0) {
        pthread_mutex_destroy(&request->mu);
        return vclgo_set_errno(ENOMEM);
    }
    return 0;
}

static void
request_destroy(native_request_t *request)
{
    pthread_cond_destroy(&request->cv);
    pthread_mutex_destroy(&request->mu);
}

static int
worker_enqueue(native_worker_t *worker, native_request_t *request)
{
    pthread_mutex_lock(&worker->queue_mu);
    if (!worker->accepting || atomic_load(&worker->stop)) {
        pthread_mutex_unlock(&worker->queue_mu);
        return -1;
    }

    request->next = NULL;
    if (worker->queue_tail)
        worker->queue_tail->next = request;
    else
        worker->queue_head = request;
    worker->queue_tail = request;
    pthread_mutex_unlock(&worker->queue_mu);
    return 0;
}

static native_request_t *
worker_dequeue(native_worker_t *worker)
{
    pthread_mutex_lock(&worker->queue_mu);
    native_request_t *request = worker->queue_head;
    if (request) {
        worker->queue_head = request->next;
        if (!worker->queue_head)
            worker->queue_tail = NULL;
        request->next = NULL;
    }
    pthread_mutex_unlock(&worker->queue_mu);
    return request;
}

static ssize_t
submit_request(native_worker_t *worker, native_request_t *request)
{
    if (!worker || worker_enqueue(worker, request) != 0) {
        errno = ECANCELED;
        return -1;
    }

    pthread_mutex_lock(&request->mu);
    while (!request->done)
        pthread_cond_wait(&request->cv, &request->mu);
    ssize_t rv = request->rv;
    int error_value = request->error_value;
    pthread_mutex_unlock(&request->mu);

    if (rv < 0)
        errno = error_value ? error_value : EIO;
    return rv;
}

static void
worker_add_session(native_worker_t *worker,
                   vclgo_native_session_t *session)
{
    session->worker_next = worker->sessions;
    worker->sessions = session;
}

static void
worker_remove_session(native_worker_t *worker,
                      vclgo_native_session_t *session)
{
    vclgo_native_session_t **link = &worker->sessions;
    while (*link) {
        if (*link == session) {
            *link = session->worker_next;
            session->worker_next = NULL;
            return;
        }
        link = &(*link)->worker_next;
    }
}

static vclgo_native_session_t *
worker_find_session(native_worker_t *worker, int fd)
{
    for (vclgo_native_session_t *session = worker->sessions;
         session; session = session->worker_next) {
        if (session->fd == fd)
            return session;
    }
    return NULL;
}

static int
session_connect_error(vclgo_native_session_t *session)
{
    vcl_session_handle_t handle = vlsh_to_sh(session->vlsh);
    if (handle == (vcl_session_handle_t)-1)
        return -EBADF;
    return vppcom_session_get_error((uint32_t)handle);
}

static int
session_update_interest(native_worker_t *worker,
                        vclgo_native_session_t *session,
                        uint32_t new_mask)
{
    if (new_mask == session->armed)
        return 0;

    uint32_t old_mask = session->armed;
    struct epoll_event event;
    memset(&event, 0, sizeof(event));
    event.events = new_mask | VCLGO_EV_ERR;
    event.data.u64 = (uint64_t)(uint32_t)session->fd;

    int op;
    if (session->armed == 0 && new_mask != 0)
        op = EPOLL_CTL_ADD;
    else if (new_mask == 0)
        op = EPOLL_CTL_DEL;
    else
        op = EPOLL_CTL_MOD;

    int rv = vls_epoll_ctl((vls_handle_t)worker->ep_vlsh, op,
                           session->vlsh,
                           op == EPOLL_CTL_DEL ? NULL : &event);
    if (rv < 0) {
        VCLGO_LOG1("worker %u: epoll_ctl op=%d fd=%d vlsh=%d: %d",
                   worker->id, op, session->fd, (int)session->vlsh, rv);
        return rv;
    }
    session->armed = new_mask;
    if (new_mask > old_mask)
        vclgo_session_trace(session, VCLGO_TR_ARM,
                            (int32_t)(new_mask & ~old_mask), op);
    else if (new_mask < old_mask)
        vclgo_session_trace(session, VCLGO_TR_DISARM,
                            (int32_t)(old_mask & ~new_mask), op);
    return 0;
}

static int
session_arm(native_worker_t *worker, vclgo_native_session_t *session,
            uint32_t events)
{
    return session_update_interest(worker, session,
                                   session->armed | events);
}

static void
session_disarm(native_worker_t *worker, vclgo_native_session_t *session)
{
    if (session->armed)
        (void)session_update_interest(worker, session, 0);
}

static void
session_signal(vclgo_native_session_t *session, uint32_t events)
{
    if (vclgo_native_surrogate_signal(session, events) != 0)
        VCLGO_LOG1("surrogate signal fd=%d events=0x%x: %s",
                   session->fd, events, strerror(errno));
}

static void
session_clear_signal(vclgo_native_session_t *session, uint32_t events)
{
    if (vclgo_native_surrogate_reset(session, events) != 0)
        VCLGO_LOG1("surrogate reset fd=%d events=0x%x: %s",
                   session->fd, events, strerror(errno));
}

static int
create_registered_session(native_worker_t *worker, vls_handle_t vlsh,
                          const vclgo_sock_meta_t *meta)
{
    vclgo_native_session_t *session =
        vclgo_native_session_create(vlsh, worker->id, meta);
    if (!session) {
        int saved_errno = errno;
        vls_close(vlsh);
        errno = saved_errno;
        return -1;
    }
    worker_add_session(worker, session);
    return session->fd;
}

static void
close_session_on_owner(native_worker_t *worker,
                       vclgo_native_session_t *session)
{
    if (atomic_exchange(&session->closing, 1))
        return;

    session_disarm(worker, session);
    vclgo_native_session_remove(session);
    worker_remove_session(worker, session);
    (void)vls_close(session->vlsh);
    close(session->fd);
    close(session->signal_fd);
    vclgo_native_session_put(session);
}

/* At process exit VPP's application-detach is the single authoritative
 * cleanup operation. Sending an asynchronous disconnect for every live
 * VLS session immediately before detach races (and, with HTTP churn,
 * floods) cut-through cleanup. Remove only the dispatcher/surrogate state;
 * vppcom_app_destroy() will release all VCL workers and VPP sessions in one
 * detach transaction. */
static void
abandon_session_on_exit(native_worker_t *worker,
                        vclgo_native_session_t *session)
{
    if (atomic_exchange(&session->closing, 1))
        return;

    vclgo_native_session_remove(session);
    worker_remove_session(worker, session);
    close(session->fd);
    close(session->signal_fd);
    vclgo_native_session_put(session);
}

static int
set_request_vpp_error(native_request_t *request, int rv)
{
    request->rv = -1;
    request->error_value = rv < 0 ? -rv : EIO;
    return -1;
}

static int
set_request_io_error(vclgo_native_session_t *session,
                     native_request_t *request, int rv)
{
    int error_value = rv < 0 ? -rv : EIO;

    /*
     * VPP closes a connected UDP session after an IPv4 destination-
     * unreachable notification, and VCL exposes only its generic RESET
     * state. Linux connected UDP reports that asynchronous port error as
     * ECONNREFUSED. VCL carries no finer reset reason, so this mapping is
     * intentionally limited to connected datagram I/O.
     */
    if (error_value == ECONNRESET && session->meta.is_dgram &&
        session->has_connected_peer)
        error_value = ECONNREFUSED;

    request->rv = -1;
    request->error_value = error_value;
    return -1;
}

static int
handle_socket(native_worker_t *worker, native_request_t *request)
{
    int stype = request->int2 & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    uint8_t proto = stype == SOCK_STREAM ? VPPCOM_PROTO_TCP
                                         : VPPCOM_PROTO_UDP;
    vls_handle_t vlsh = vls_create(proto, 1);
    if (vlsh < 0)
        return set_request_vpp_error(request, (int)vlsh);

    vclgo_sock_meta_t meta = {
        .family = (uint8_t)request->int1,
        .is_dgram = stype == SOCK_DGRAM,
    };
    int fd = create_registered_session(worker, vlsh, &meta);
    if (fd < 0) {
        request->rv = -1;
        request->error_value = errno;
        return -1;
    }

    request->rv = fd;
    request->error_value = 0;
    atomic_fetch_add(&vclgo_stat_sockets_opened, 1);
    VCLGO_LOG2("worker %u: socket -> fd=%d vlsh=%d",
               worker->id, fd, (int)vlsh);
    return 0;
}

static int
handle_bind(native_request_t *request)
{
    vclgo_native_session_t *session = request->session;
    vppcom_endpt_t endpoint;
    uint8_t ip[16];
    struct sockaddr_storage selected_addr;
    const struct sockaddr *bound_addr = request->addr;
    socklen_t bound_len = request->addrlen;

    if (vclgo_sockaddr_to_endpt(request->addr, request->addrlen,
                                &endpoint, ip) < 0) {
        request->rv = -1;
        request->error_value = errno;
        return -1;
    }

    int rv;
    if (session->meta.is_dgram && endpoint.port == 0) {
        bound_len = sockaddr_size(request->addr, request->addrlen);
        if (bound_len == 0) {
            request->rv = -1;
            request->error_value = EINVAL;
            return -1;
        }
        memset(&selected_addr, 0, sizeof(selected_addr));
        memcpy(&selected_addr, request->addr, bound_len);
        bound_addr = (const struct sockaddr *)&selected_addr;

        rv = VPPCOM_EADDRINUSE;
        for (unsigned attempt = 0; attempt < UDP_EPHEMERAL_ATTEMPTS;
             attempt++) {
            uint16_t port = next_udp_ephemeral_port();
            endpoint.port = htons(port);
            sockaddr_set_port(&selected_addr, port);
            rv = vls_bind(session->vlsh, &endpoint);
            if (rv != VPPCOM_EADDRINUSE)
                break;
        }
    } else {
        rv = vls_bind(session->vlsh, &endpoint);
    }
    if (rv < 0)
        return set_request_vpp_error(request, rv);

    size_t copy_len = bound_len;
    if (copy_len > sizeof(session->bound_addr))
        copy_len = sizeof(session->bound_addr);
    memcpy(&session->bound_addr, bound_addr, copy_len);
    session->bound_len = (socklen_t)copy_len;
    session->wildcard_bound =
        session->meta.is_dgram &&
        sockaddr_is_wildcard(bound_addr, bound_len);
    session->has_source_route_peer = 0;
    request->rv = 0;
    return 0;
}

static int
handle_listen(native_request_t *request)
{
    vclgo_native_session_t *session = request->session;
    int rv = vls_listen(session->vlsh, request->int1);
    if (rv < 0)
        return set_request_vpp_error(request, rv);

    session->meta.listening = 1;
    request->rv = 0;
    return 0;
}

static int
handle_accept(native_worker_t *worker, native_request_t *request)
{
    vclgo_native_session_t *listener = request->session;
    session_clear_signal(listener, VCLGO_EV_READ);

    vppcom_endpt_t endpoint;
    uint8_t ip[16] = {0};
    memset(&endpoint, 0, sizeof(endpoint));
    endpoint.ip = ip;

    vls_handle_t child =
        vls_accept(listener->vlsh, &endpoint, O_NONBLOCK);
    if (child < 0) {
        if (child == VPPCOM_EAGAIN) {
            int arm_rv = session_arm(worker, listener, VCLGO_EV_READ);
            if (arm_rv < 0)
                return set_request_vpp_error(request, arm_rv);
        }
        return set_request_vpp_error(request, (int)child);
    }

    if (request->out_addr && request->out_addrlen &&
        *request->out_addrlen > 0) {
        if (vclgo_endpt_to_sockaddr(&endpoint, request->out_addr,
                                    request->out_addrlen) < 0) {
            int saved_errno = errno;
            vls_close(child);
            request->rv = -1;
            request->error_value = saved_errno;
            return -1;
        }
    }

    /* VLS cannot migrate an accepted session after it reaches READY state.
     * Keep it on the listener owner. Independent listeners and outbound
     * sockets are still distributed across the pool. */
    vclgo_sock_meta_t child_meta = {
        .family = listener->meta.family,
        .is_dgram = listener->meta.is_dgram,
    };
    int fd = create_registered_session(worker, child, &child_meta);
    if (fd < 0) {
        request->rv = -1;
        request->error_value = errno;
        return -1;
    }

    request->rv = fd;
    request->error_value = 0;
    atomic_fetch_add(&vclgo_stat_accepts, 1);
    return 0;
}

static int
handle_connect(native_worker_t *worker, native_request_t *request)
{
    vclgo_native_session_t *session = request->session;
    session_clear_signal(session, VCLGO_EV_WRITE);

    vppcom_endpt_t endpoint;
    uint8_t ip[16];
    if (vclgo_sockaddr_to_endpt(request->addr, request->addrlen,
                                &endpoint, ip) < 0) {
        request->rv = -1;
        request->error_value = errno;
        return -1;
    }

    if (session->meta.is_dgram) {
        socklen_t peer_len = sockaddr_size(request->addr,
                                           request->addrlen);
        if (peer_len == 0) {
            request->rv = -1;
            request->error_value = EINVAL;
            return -1;
        }

        /* Keep Go's UDP connect synchronous. The raw VLS session is
         * nonblocking, which otherwise returns EINPROGRESS and leaves this
         * connectionless path waiting on unreliable VLS epoll readiness.
         * Only its permanently pinned owner changes the flag. */
        int saved_flags = 0;
        uint32_t flags_len = sizeof(saved_flags);
        int rv = vls_attr(session->vlsh, VPPCOM_ATTR_GET_FLAGS,
                          &saved_flags, &flags_len);
        if (rv < 0)
            return set_request_vpp_error(request, rv);

        int blocking_flags = saved_flags & ~O_NONBLOCK;
        flags_len = sizeof(blocking_flags);
        rv = vls_attr(session->vlsh, VPPCOM_ATTR_SET_FLAGS,
                      &blocking_flags, &flags_len);
        if (rv < 0)
            return set_request_vpp_error(request, rv);

        rv = vls_connect(session->vlsh, &endpoint);
        flags_len = sizeof(saved_flags);
        int restore_rv = vls_attr(session->vlsh, VPPCOM_ATTR_SET_FLAGS,
                                  &saved_flags, &flags_len);
        if (rv >= 0 && restore_rv < 0)
            rv = restore_rv;
        vclgo_session_trace(session, VCLGO_TR_CONNECT, rv, 0);
        if (rv < 0)
            return set_request_vpp_error(request, rv);

        memset(&session->connected_peer, 0,
               sizeof(session->connected_peer));
        memcpy(&session->connected_peer, request->addr, peer_len);
        session->connected_peer_len = peer_len;
        session->has_connected_peer = 1;
        session->connecting = 0;
        session->connect_error = 0;
        request->rv = 0;
        request->error_value = 0;
        atomic_fetch_add(&vclgo_stat_connects, 1);
        return 0;
    }

    int rv = vls_connect(session->vlsh, &endpoint);
    if (rv == 0) {
        session->connecting = 0;
        session->connect_error = 0;
        request->rv = 0;
        atomic_fetch_add(&vclgo_stat_connects, 1);
        return 0;
    }

    if (rv == VPPCOM_EINPROGRESS || rv == VPPCOM_EAGAIN) {
        session->connecting = 1;
        session->connect_error = 0;
        int arm_rv = session_arm(worker, session, VCLGO_EV_WRITE);
        if (arm_rv < 0)
            return set_request_vpp_error(request, arm_rv);
        request->rv = -1;
        request->error_value = EINPROGRESS;
        return -1;
    }

    return set_request_vpp_error(request, rv);
}

static int
handle_read(native_worker_t *worker, native_request_t *request)
{
    vclgo_native_session_t *session = request->session;
    session_clear_signal(session, VCLGO_EV_READ);

    if (request->count == 0) {
        request->rv = 0;
        return 0;
    }
    if (session_take_socket_error(session, request) < 0)
        return -1;

    ssize_t rv = vls_read(session->vlsh, request->buf, request->count);
    vclgo_session_trace(session, VCLGO_TR_READ,
                        (int32_t)request->count, (int32_t)rv);
    if (rv == VPPCOM_EAGAIN) {
        int arm_rv = session_arm(worker, session, VCLGO_EV_READ);
        if (arm_rv < 0)
            return set_request_vpp_error(request, arm_rv);
    }
    if (rv < 0)
        return set_request_io_error(session, request, (int)rv);

    request->rv = rv;
    atomic_fetch_add(&vclgo_stat_reads, 1);
    return 0;
}

static int
handle_write(native_worker_t *worker, native_request_t *request)
{
    vclgo_native_session_t *session = request->session;
    session_clear_signal(session, VCLGO_EV_WRITE);

    if (request->count == 0) {
        request->rv = 0;
        return 0;
    }
    if (session_take_socket_error(session, request) < 0)
        return -1;

    if (session->meta.is_dgram && !session->has_connected_peer) {
        request->rv = -1;
        request->error_value = EDESTADDRREQ;
        return -1;
    }
    ssize_t rv = vls_write(session->vlsh, (void *)request->const_buf,
                           request->count);
    vclgo_session_trace(session, VCLGO_TR_WRITE,
                        (int32_t)request->count, (int32_t)rv);
    if (rv == VPPCOM_EAGAIN) {
        int arm_rv = session_arm(worker, session, VCLGO_EV_WRITE);
        if (arm_rv < 0)
            return set_request_vpp_error(request, arm_rv);
    }
    if (rv < 0)
        return set_request_io_error(session, request, (int)rv);
    if (rv == 0) {
        request->rv = -1;
        request->error_value = EPIPE;
        return -1;
    }

    request->rv = rv;
    atomic_fetch_add(&vclgo_stat_writes, 1);
    return 0;
}

/*
 * UDP-aware datagram send. When `addr` is NULL the datagram is sent
 * to the dispatcher's cached connected peer (matches BSD sendto(NULL)
 * semantics on a connected socket, which UDP also supports). When
 * `addr` is set, VLS routes the datagram to that endpoint irrespective
 * of any per-session default peer.
 *
 * For SOCK_STREAM this function still works (VLS ignores the endpoint
 * for connected TCP), so the gum fastpath is free to route all
 * sendto()/write() calls through it without a per-fd branch — the
 * caller decides when to pass the address.
 */
static int
handle_sendto(native_worker_t *worker, native_request_t *request)
{
    vclgo_native_session_t *session = request->session;
    session_clear_signal(session, VCLGO_EV_WRITE);

    if (request->count == 0) {
        request->rv = 0;
        return 0;
    }

    vppcom_endpt_t endpoint;
    uint8_t ip[16];
    vppcom_endpt_t *ep_arg = NULL;
    if (request->addr) {
        if (vclgo_sockaddr_to_endpt(request->addr, request->addrlen,
                                    &endpoint, ip) < 0) {
            request->rv = -1;
            request->error_value = errno;
            return -1;
        }
        ep_arg = &endpoint;
    } else if (session->meta.is_dgram) {
        if (session_connected_endpoint(session, &endpoint, ip) < 0) {
            request->rv = -1;
            request->error_value = errno;
            return -1;
        }
        ep_arg = &endpoint;
    }

    if (request->addr) {
        int source_rv = session_select_wildcard_source(
            session, worker, request->addr, request->addrlen, &endpoint);
        if (source_rv < 0)
            return set_request_vpp_error(request, source_rv);
    }
    if (session_take_socket_error(session, request) < 0)
        return -1;

    int rv = vls_sendto(session->vlsh, (void *)request->const_buf,
                        (int)request->count, request->flags, ep_arg);
    vclgo_session_trace(session, VCLGO_TR_WRITE,
                        (int32_t)request->count, (int32_t)rv);
    if (rv == VPPCOM_EAGAIN) {
        int arm_rv = session_arm(worker, session, VCLGO_EV_WRITE);
        if (arm_rv < 0)
            return set_request_vpp_error(request, arm_rv);
    }
    if (rv < 0)
        return set_request_io_error(session, request, rv);

    request->rv = rv;
    atomic_fetch_add(&vclgo_stat_writes, 1);
    return 0;
}

/*
 * UDP-aware datagram receive. If `out_addr` is set we fill it with the
 * datagram's sender using VLS's endpoint report; UDP peer identity
 * changes per datagram, so this must never come from a cached session
 * peer. For SOCK_STREAM sockets VLS returns the connected peer, which
 * is what BSD recvfrom() expects, so this also serves as a working
 * recvfrom() over TCP.
 */
static int
handle_recvfrom(native_worker_t *worker, native_request_t *request)
{
    vclgo_native_session_t *session = request->session;
    session_clear_signal(session, VCLGO_EV_READ);

    if (request->count == 0) {
        request->rv = 0;
        return 0;
    }
    if (session_take_socket_error(session, request) < 0)
        return -1;

    vppcom_endpt_t endpoint;
    uint8_t ip[16];
    vppcom_endpt_t *ep_arg = NULL;
    if (request->out_addr && request->out_addrlen &&
        *request->out_addrlen > 0) {
        memset(&endpoint, 0, sizeof endpoint);
        endpoint.ip = ip;
        ep_arg = &endpoint;
    }

    ssize_t rv = vls_recvfrom(session->vlsh, request->buf,
                              (uint32_t)request->count, request->flags,
                              ep_arg);
    vclgo_session_trace(session, VCLGO_TR_READ,
                        (int32_t)request->count, (int32_t)rv);
    if (rv == VPPCOM_EAGAIN) {
        int arm_rv = session_arm(worker, session, VCLGO_EV_READ);
        if (arm_rv < 0)
            return set_request_vpp_error(request, arm_rv);
    }
    if (rv < 0)
        return set_request_io_error(session, request, (int)rv);

    if (ep_arg && rv >= 0) {
        (void)vclgo_endpt_to_sockaddr(&endpoint, request->out_addr,
                                      request->out_addrlen);
    }

    request->rv = rv;
    atomic_fetch_add(&vclgo_stat_reads, 1);
    return 0;
}

static int
handle_shutdown(native_worker_t *worker, native_request_t *request)
{
    int rv = vls_shutdown(request->session->vlsh, request->int1);
    if (rv < 0)
        return set_request_vpp_error(request, rv);

    if (request->int1 == SHUT_RDWR)
        session_disarm(worker, request->session);
    session_signal(request->session,
                   VCLGO_EV_READ | VCLGO_EV_WRITE);
    request->rv = 0;
    return 0;
}

static int
handle_close(native_worker_t *worker, native_request_t *request)
{
    vclgo_native_session_t *session = request->session;
    if (atomic_load(&session->closing)) {
        request->rv = -1;
        request->error_value = EBADF;
        return -1;
    }

    close_session_on_owner(worker, session);
    request->rv = 0;
    request->error_value = 0;
    atomic_fetch_add(&vclgo_stat_sockets_closed, 1);
    return 0;
}

static int
reject_sockopt(native_request_t *request)
{
    request->rv = -1;
    request->error_value = ENOPROTOOPT;
    return -1;
}

static int
handle_setsockopt(native_request_t *request)
{
    vclgo_native_session_t *session = request->session;
    uint32_t length = request->optlen_value;
    uint32_t attr = 0;
    int ignored = 0;

    if (request->int1 == SOL_SOCKET) {
        switch (request->int2) {
        case SO_REUSEADDR:
            attr = VPPCOM_ATTR_SET_REUSEADDR;
            break;
        case SO_REUSEPORT:
            attr = VPPCOM_ATTR_SET_REUSEPORT;
            break;
        case SO_BROADCAST:
            attr = VPPCOM_ATTR_SET_BROADCAST;
            break;
        case SO_KEEPALIVE:
            attr = VPPCOM_ATTR_SET_KEEPALIVE;
            break;
        case SO_SNDBUF:
            attr = VPPCOM_ATTR_SET_TX_FIFO_LEN;
            break;
        case SO_RCVBUF:
            attr = VPPCOM_ATTR_SET_RX_FIFO_LEN;
            break;
        case SO_LINGER:
            ignored = 1;
            break;
        default:
            break;
        }
    } else if (request->int1 == IPPROTO_IPV6) {
        if (request->int2 == IPV6_V6ONLY)
            attr = VPPCOM_ATTR_SET_V6ONLY;
    } else if (request->int1 == IPPROTO_TCP) {
        switch (request->int2) {
        case TCP_NODELAY:
            attr = VPPCOM_ATTR_SET_TCP_NODELAY;
            break;
        case TCP_MAXSEG:
            attr = VPPCOM_ATTR_SET_TCP_USER_MSS;
            break;
        case TCP_KEEPIDLE:
            attr = VPPCOM_ATTR_SET_TCP_KEEPIDLE;
            break;
        case TCP_KEEPINTVL:
            attr = VPPCOM_ATTR_SET_TCP_KEEPINTVL;
            break;
        case TCP_CONGESTION:
        case TCP_CORK:
            ignored = 1;
            break;
        default:
            break;
        }
    }

    if (!attr && !ignored)
        return reject_sockopt(request);

    if (attr) {
        int rv = vls_attr(session->vlsh, attr,
                          (void *)request->const_optval, &length);
        if (rv < 0)
            return set_request_vpp_error(request, rv);
    }

    if (request->int1 == IPPROTO_IPV6 &&
        request->int2 == IPV6_V6ONLY &&
        request->const_optval &&
        request->optlen_value >= (socklen_t)sizeof(int)) {
        session->meta.v6only =
            *(const int *)request->const_optval != 0;
    }

    request->rv = 0;
    return 0;
}

static int
write_int_sockopt(native_request_t *request, int value)
{
    if (!request->optval || !request->optlen ||
        *request->optlen < (socklen_t)sizeof(value)) {
        request->rv = -1;
        request->error_value = EINVAL;
        return -1;
    }
    memcpy(request->optval, &value, sizeof(value));
    *request->optlen = sizeof(value);
    request->rv = 0;
    return 0;
}

static int
get_vls_int_attr(native_request_t *request, uint32_t attr)
{
    vclgo_native_session_t *session = request->session;

    /* Some VPP FIFO getters store a size_t but report a four-byte result.
     * Use local eight-byte storage and copy a POSIX int to user memory. */
    uint64_t storage = 0;
    uint32_t length = sizeof(storage);
    int rv = vls_attr(session->vlsh, attr, &storage, &length);
    if (rv < 0)
        return set_request_vpp_error(request, rv);
    return write_int_sockopt(request, (int)(uint32_t)storage);
}

static int
handle_getsockopt(native_worker_t *worker, native_request_t *request)
{
    vclgo_native_session_t *session = request->session;

    if (request->int1 == SOL_SOCKET && request->int2 == SO_ERROR) {
        session_clear_signal(session, VCLGO_EV_READ | VCLGO_EV_WRITE);
        int value = 0;
        if (session->socket_error) {
            value = session->socket_error;
            session->socket_error = 0;
        } else if (session->connect_error) {
            value = session->connect_error;
            session->connect_error = 0;
        } else if (session->connecting) {
            value = EINPROGRESS;
            if (session_arm(worker, session, VCLGO_EV_WRITE) < 0)
                value = EIO;
        }
        return write_int_sockopt(request, value);
    }

    uint32_t attr = 0;
    if (request->int1 == SOL_SOCKET) {
        switch (request->int2) {
        case SO_ACCEPTCONN:
            return write_int_sockopt(request,
                                     session->meta.listening != 0);
        case SO_TYPE:
            return write_int_sockopt(
                request, session->meta.is_dgram ?
                SOCK_DGRAM : SOCK_STREAM);
        case SO_DOMAIN:
            return write_int_sockopt(request, session->meta.family);
        case SO_PROTOCOL:
            return write_int_sockopt(
                request, session->meta.is_dgram ?
                IPPROTO_UDP : IPPROTO_TCP);
        case SO_KEEPALIVE:
            attr = VPPCOM_ATTR_GET_KEEPALIVE;
            break;
        case SO_SNDBUF:
            attr = VPPCOM_ATTR_GET_TX_FIFO_LEN;
            break;
        case SO_RCVBUF:
            attr = VPPCOM_ATTR_GET_RX_FIFO_LEN;
            break;
        case SO_REUSEADDR:
            attr = VPPCOM_ATTR_GET_REUSEADDR;
            break;
        case SO_REUSEPORT:
            attr = VPPCOM_ATTR_GET_REUSEPORT;
            break;
        case SO_BROADCAST:
            attr = VPPCOM_ATTR_GET_BROADCAST;
            break;
        default:
            break;
        }
    } else if (request->int1 == IPPROTO_IPV6) {
        if (request->int2 == IPV6_V6ONLY)
            attr = VPPCOM_ATTR_GET_V6ONLY;
    } else if (request->int1 == IPPROTO_TCP) {
        switch (request->int2) {
        case TCP_NODELAY:
            attr = VPPCOM_ATTR_GET_TCP_NODELAY;
            break;
        case TCP_MAXSEG:
            attr = VPPCOM_ATTR_GET_TCP_USER_MSS;
            break;
        case TCP_KEEPIDLE:
            attr = VPPCOM_ATTR_GET_TCP_KEEPIDLE;
            break;
        case TCP_KEEPINTVL:
            attr = VPPCOM_ATTR_GET_TCP_KEEPINTVL;
            break;
        default:
            break;
        }
    }

    if (!attr)
        return reject_sockopt(request);
    return get_vls_int_attr(request, attr);
}

static int
handle_getname(native_request_t *request, uint32_t attr)
{
    vclgo_native_session_t *session = request->session;
    if (attr == VPPCOM_ATTR_GET_LCL_ADDR &&
        session->meta.is_dgram && session->wildcard_bound &&
        !session->has_connected_peer && session->bound_len > 0) {
        if (!request->out_addr || !request->out_addrlen ||
            *request->out_addrlen < session->bound_len) {
            request->rv = -1;
            request->error_value = EINVAL;
            return -1;
        }
        memcpy(request->out_addr, &session->bound_addr,
               session->bound_len);
        *request->out_addrlen = session->bound_len;
        request->rv = 0;
        request->error_value = 0;
        return 0;
    }

    if (attr == VPPCOM_ATTR_GET_PEER_ADDR && session->meta.is_dgram) {
        if (!session->has_connected_peer) {
            request->rv = -1;
            request->error_value = ENOTCONN;
            return -1;
        }
        if (!request->out_addr || !request->out_addrlen ||
            *request->out_addrlen < session->connected_peer_len) {
            request->rv = -1;
            request->error_value = EINVAL;
            return -1;
        }
        memcpy(request->out_addr, &session->connected_peer,
               session->connected_peer_len);
        *request->out_addrlen = session->connected_peer_len;
        request->rv = 0;
        request->error_value = 0;
        return 0;
    }

    if (attr == VPPCOM_ATTR_GET_PEER_ADDR &&
        (session->connecting || session->connect_error)) {
        /* Pending connect and failed-but-not-yet-consumed connect both mean
         * "no peer": SO_ERROR may not yet have been observed by the caller. */
        request->rv = -1;
        request->error_value = ENOTCONN;
        return -1;
    }

    uint8_t ip[16] = {0};
    vppcom_endpt_t endpoint;
    memset(&endpoint, 0, sizeof(endpoint));
    endpoint.ip = ip;
    uint32_t length = sizeof(endpoint);

    int rv = vls_attr(session->vlsh, attr, &endpoint, &length);
    if (rv < 0)
        return set_request_vpp_error(request, rv);

    if (vclgo_endpt_to_sockaddr(&endpoint, request->out_addr,
                                request->out_addrlen) < 0) {
        request->rv = -1;
        request->error_value = errno;
        return -1;
    }

    request->rv = 0;
    return 0;
}

static int
process_request(native_worker_t *worker, native_request_t *request)
{
    if (request->op != NOP_SOCKET) {
        vclgo_native_session_t *session = request->session;
        if (!session || session->owner != worker->id ||
            atomic_load(&session->closing)) {
            request->rv = -1;
            request->error_value = EBADF;
            return 0;
        }
    }

    switch (request->op) {
    case NOP_SOCKET:
        (void)handle_socket(worker, request);
        break;
    case NOP_BIND:
        (void)handle_bind(request);
        break;
    case NOP_LISTEN:
        (void)handle_listen(request);
        break;
    case NOP_ACCEPT:
        (void)handle_accept(worker, request);
        break;
    case NOP_CONNECT:
        (void)handle_connect(worker, request);
        break;
    case NOP_SHUTDOWN:
        (void)handle_shutdown(worker, request);
        break;
    case NOP_CLOSE:
        (void)handle_close(worker, request);
        break;
    case NOP_READ:
        (void)handle_read(worker, request);
        break;
    case NOP_WRITE:
        (void)handle_write(worker, request);
        break;
    case NOP_SETSOCKOPT:
        (void)handle_setsockopt(request);
        break;
    case NOP_GETSOCKOPT:
        (void)handle_getsockopt(worker, request);
        break;
    case NOP_GETSOCKNAME:
        (void)handle_getname(request, VPPCOM_ATTR_GET_LCL_ADDR);
        break;
    case NOP_GETPEERNAME:
        (void)handle_getname(request, VPPCOM_ATTR_GET_PEER_ADDR);
        break;
    case NOP_SENDTO:
        (void)handle_sendto(worker, request);
        break;
    case NOP_RECVFROM:
        (void)handle_recvfrom(worker, request);
        break;
    }
    return 0;
}

static void
worker_handle_event(native_worker_t *worker,
                    const struct epoll_event *event)
{
    int fd = (int)(uint32_t)event->data.u64;
    vclgo_native_session_t *session = worker_find_session(worker, fd);
    if (!session || atomic_load(&session->closing))
        return;

    uint32_t delivered = event->events;
    uint32_t clear = delivered & session->armed;
    if (delivered & VCLGO_EV_ERR)
        clear = session->armed;

    if (session->connecting &&
        (delivered & (VCLGO_EV_WRITE | VCLGO_EV_ERR))) {
        int connect_rv = session_connect_error(session);
        if (connect_rv < 0)
            session->connect_error = -connect_rv;
        else
            session->connect_error = 0;
        session->connecting = 0;
        clear |= VCLGO_EV_WRITE;
        atomic_fetch_add(&vclgo_stat_connects, 1);
    }
    if (!session->connecting && (delivered & VCLGO_EV_ERR) &&
        session->meta.is_dgram && session->has_connected_peer)
        session->socket_error = ECONNREFUSED;

    vclgo_session_trace(session, VCLGO_TR_EVENT,
                        (int32_t)delivered, (int32_t)clear);
    (void)session_update_interest(worker, session,
                                  session->armed & ~clear);
    session_signal(session, clear);
    atomic_fetch_add(&vclgo_stat_poller_wakeups, 1);
}

static int64_t
timespec_to_ns(const struct timespec *ts)
{
    return (int64_t)ts->tv_sec * 1000000000LL + ts->tv_nsec;
}

static void
worker_poll_connect_errors(native_worker_t *worker)
{
    for (vclgo_native_session_t *session = worker->sessions;
         session; session = session->worker_next) {
        if (!session->connecting || atomic_load(&session->closing))
            continue;
        int rv = session_connect_error(session);
        if (rv < 0 && rv != -EINPROGRESS && rv != -EALREADY) {
            session->connect_error = -rv;
            session->connecting = 0;
            (void)session_update_interest(
                worker, session, session->armed & ~VCLGO_EV_WRITE);
            session_signal(session, VCLGO_EV_WRITE);
            continue;
        }

        /* For UDP, VPP's CONNECTED msg often arrives via the mq but
         * the emitted EPOLLOUT event is dropped between VLS and
         * vppcom_epoll_wait — the session simply flips to READY with
         * no wake. We can detect that by asking VLS for the local
         * address: it's only populated after
         * vcl_session_connected_handler processes the CONNECTED msg
         * (which is what flips the state to READY). Querying
         * VPPCOM_ATTR_GET_LCL_ADDR exposes that transition: if the local
         * port is non-zero, treat the connect as done. */
        if (!session->meta.is_dgram)
            continue;
        vcl_session_handle_t handle = vlsh_to_sh(session->vlsh);
        if (handle == (vcl_session_handle_t)-1)
            continue;
        vppcom_endpt_t lcl;
        uint8_t lcl_ip[16] = {0};
        memset(&lcl, 0, sizeof lcl);
        lcl.ip = lcl_ip;
        uint32_t len = sizeof(lcl);
        if (vppcom_session_attr((uint32_t)handle,
                                VPPCOM_ATTR_GET_LCL_ADDR,
                                &lcl, &len) != 0)
            continue;
        if (lcl.port == 0)
            continue;
        session->connecting = 0;
        session->connect_error = 0;
        (void)session_update_interest(
            worker, session, session->armed & ~VCLGO_EV_WRITE);
        session_signal(session, VCLGO_EV_WRITE);
    }
}

static void
worker_watchdog(native_worker_t *worker, uint64_t now_ns)
{
    for (vclgo_native_session_t *session = worker->sessions;
         session; session = session->worker_next) {
        if (atomic_load(&session->closing))
            continue;
        /* Only sessions that Go is actually waiting on (armed) are
         * potentially in a missed-wake state. Ignore idle sockets. */
        if (session->armed == 0 || session->last_transition_ns == 0)
            continue;
        uint64_t stall = now_ns - session->last_transition_ns;
        if (stall < WATCHDOG_STALL_NS)
            continue;
        /* Rate-limit dumps per session so a persistent hang doesn't spam. */
        if (session->last_dump_ns != 0 &&
            now_ns - session->last_dump_ns < WATCHDOG_REDUMP_NS)
            continue;
        /* Independent evidence: does VLS think this session has an event
         * queued right now that we're not delivering? */
        int vpp_ready = -1;
        vcl_session_handle_t handle = vlsh_to_sh(session->vlsh);
        if (handle != (vcl_session_handle_t)-1) {
            uint32_t is_read = 0;
            uint32_t is_write = 0;
            uint32_t len = sizeof(is_read);
            (void)vppcom_session_attr((uint32_t)handle,
                                      VPPCOM_ATTR_GET_NREAD,
                                      &is_read, &len);
            len = sizeof(is_write);
            (void)vppcom_session_attr((uint32_t)handle,
                                      VPPCOM_ATTR_GET_NWRITE,
                                      &is_write, &len);
            vpp_ready = (int)((is_read ? 1 : 0) | (is_write ? 2 : 0));
        }
        VCLGO_LOG1(
            "watchdog worker %u fd=%d stalled_ns=%llu vpp_ready=0x%x",
            worker->id, session->fd,
            (unsigned long long)stall, vpp_ready);
        vclgo_session_trace_dump(session, "watchdog");
        session->last_dump_ns = now_ns;
    }
}

static void
worker_cancel_queue(native_worker_t *worker)
{
    pthread_mutex_lock(&worker->queue_mu);
    native_request_t *request = worker->queue_head;
    worker->queue_head = worker->queue_tail = NULL;
    pthread_mutex_unlock(&worker->queue_mu);

    while (request) {
        native_request_t *next = request->next;
        request->next = NULL;
        request_finish(request, -1, ECANCELED);
        request = next;
    }
}

static void
worker_quiesce(native_worker_t *worker)
{
    pthread_mutex_lock(&worker->queue_mu);
    worker->accepting = 0;
    pthread_mutex_unlock(&worker->queue_mu);

    worker_cancel_queue(worker);
    if (worker->detach_only) {
        while (worker->sessions)
            abandon_session_on_exit(worker, worker->sessions);
    } else {
        while (worker->sessions)
            close_session_on_owner(worker, worker->sessions);

        if (worker->ep_vlsh >= 0) {
            (void)vls_close((vls_handle_t)worker->ep_vlsh);
            worker->ep_vlsh = -1;
        }

        if (!worker->bootstrap)
            (void)vls_unregister_vcl_worker();
    }

    pthread_mutex_lock(&worker->state_mu);
    worker->quiesced = 1;
    pthread_cond_broadcast(&worker->state_cv);
    pthread_mutex_unlock(&worker->state_mu);
}

static void *
worker_main(void *arg)
{
    native_worker_t *worker = arg;
    char thread_name[16];
    snprintf(thread_name, sizeof(thread_name), "vclgo-vcl-%u", worker->id);
    pthread_setname_np(pthread_self(), thread_name);

    int register_error = 0;
    if (worker->bootstrap) {
        int rv = vls_app_create(g_app_name);
        if (rv != 0)
            register_error = rv < 0 ? -rv : EIO;
    } else {
        vls_register_vcl_worker();
        if (vppcom_worker_index() < 0)
            register_error = EIO;
    }

    pthread_mutex_lock(&worker->state_mu);
    worker->registered = 1;
    worker->register_error = register_error;
    pthread_cond_broadcast(&worker->state_cv);
    pthread_mutex_unlock(&worker->state_mu);

    if (register_error) {
        pthread_mutex_lock(&worker->state_mu);
        worker->quiesced = 1;
        pthread_cond_broadcast(&worker->state_cv);
        pthread_mutex_unlock(&worker->state_mu);
        return NULL;
    }

    pthread_mutex_lock(&g_start_mu);
    while (!g_start_released)
        pthread_cond_wait(&g_start_cv, &g_start_mu);
    pthread_mutex_unlock(&g_start_mu);

    if (!atomic_load(&worker->stop)) {
        int ep = vls_epoll_create();
        if (ep < 0)
            worker->ready_error = -ep;
        else
            worker->ep_vlsh = ep;
    } else {
        worker->ready_error = ECANCELED;
    }

    pthread_mutex_lock(&worker->state_mu);
    worker->ready = 1;
    pthread_cond_broadcast(&worker->state_cv);
    pthread_mutex_unlock(&worker->state_mu);

    if (!worker->ready_error) {
        struct epoll_event events[WORKER_EPOLL_EVENTS];
        struct timespec last_connect_poll;
        struct timespec last_watchdog_poll;
        clock_gettime(CLOCK_MONOTONIC, &last_connect_poll);
        last_watchdog_poll = last_connect_poll;

        while (!atomic_load(&worker->stop)) {
            for (int i = 0; i < WORKER_BATCH; i++) {
                native_request_t *request = worker_dequeue(worker);
                if (!request)
                    break;
                if (!process_request(worker, request))
                    request_finish(request, request->rv,
                                   request->error_value);
            }

            int count = vls_epoll_wait(
                (vls_handle_t)worker->ep_vlsh, events,
                WORKER_EPOLL_EVENTS, WORKER_POLL_SECONDS);
            if (count < 0 && count != -EINTR) {
                VCLGO_LOG1("worker %u: vls_epoll_wait: %d",
                           worker->id, count);
            } else {
                for (int i = 0; i < count; i++)
                    worker_handle_event(worker, &events[i]);
            }

            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (timespec_to_ns(&now) - timespec_to_ns(&last_connect_poll) >=
                CONNECT_ERROR_POLL_NS) {
                worker_poll_connect_errors(worker);
                last_connect_poll = now;
            }
            if (timespec_to_ns(&now) - timespec_to_ns(&last_watchdog_poll) >=
                WATCHDOG_POLL_NS) {
                worker_watchdog(worker, (uint64_t)timespec_to_ns(&now));
                last_watchdog_poll = now;
            }
        }
    }

    worker_quiesce(worker);

    if (!worker->bootstrap) {
        if (!worker->detach_only)
            return NULL;

        /* app_destroy invalidates this worker's VCL/VLS TLS. Keep the
         * pthread parked until exit_group terminates the process. */
        for (;;)
            pause();
    }

    pthread_mutex_lock(&worker->state_mu);
    while (!worker->destroy_requested)
        pthread_cond_wait(&worker->state_cv, &worker->state_mu);
    pthread_mutex_unlock(&worker->state_mu);

    vppcom_app_destroy();

    pthread_mutex_lock(&worker->state_mu);
    worker->destroyed = 1;
    pthread_cond_broadcast(&worker->state_cv);
    pthread_mutex_unlock(&worker->state_mu);

    /* VPP invalidates bootstrap TLS during app_destroy.  Keep this pthread
     * alive until exit_group terminates the process so its TLS destructor
     * cannot run against destroyed VCL process state. */
    for (;;)
        pause();
}

static int
start_thread(native_worker_t *worker)
{
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 2u * 1024u * 1024u);
    int rv = pthread_create(&worker->thread, &attr, worker_main, worker);
    pthread_attr_destroy(&attr);
    return rv;
}

static int
wait_registered(native_worker_t *worker)
{
    pthread_mutex_lock(&worker->state_mu);
    while (!worker->registered)
        pthread_cond_wait(&worker->state_cv, &worker->state_mu);
    int error_value = worker->register_error;
    pthread_mutex_unlock(&worker->state_mu);
    return error_value;
}

static int
wait_ready(native_worker_t *worker)
{
    pthread_mutex_lock(&worker->state_mu);
    while (!worker->ready && !worker->quiesced)
        pthread_cond_wait(&worker->state_cv, &worker->state_mu);
    int error_value = worker->ready_error;
    pthread_mutex_unlock(&worker->state_mu);
    return error_value;
}

static void
release_workers(void)
{
    pthread_mutex_lock(&g_start_mu);
    g_start_released = 1;
    pthread_cond_broadcast(&g_start_cv);
    pthread_mutex_unlock(&g_start_mu);
}

static void
stop_started_workers(int count, int detach_only)
{
    for (int i = 0; i < count; i++) {
        pthread_mutex_lock(&g_workers[i].queue_mu);
        g_workers[i].accepting = 0;
        g_workers[i].detach_only = detach_only;
        pthread_mutex_unlock(&g_workers[i].queue_mu);
        atomic_store(&g_workers[i].stop, 1);
    }
    release_workers();

    for (int i = 0; i < count; i++) {
        pthread_mutex_lock(&g_workers[i].state_mu);
        while (!g_workers[i].quiesced)
            pthread_cond_wait(&g_workers[i].state_cv,
                              &g_workers[i].state_mu);
        pthread_mutex_unlock(&g_workers[i].state_mu);
    }

    if (!detach_only) {
        for (int i = 1; i < count; i++)
            pthread_join(g_workers[i].thread, NULL);
    }

    native_worker_t *bootstrap = &g_workers[0];
    pthread_mutex_lock(&bootstrap->state_mu);
    bootstrap->destroy_requested = 1;
    pthread_cond_broadcast(&bootstrap->state_cv);
    while (!bootstrap->destroyed)
        pthread_cond_wait(&bootstrap->state_cv, &bootstrap->state_mu);
    pthread_mutex_unlock(&bootstrap->state_mu);
}

int
vclgo_native_pool_start(const char *app_name, int requested_workers)
{
    pthread_once(&g_workers_once, workers_init_once);
    if (atomic_load(&g_pool_active))
        return 0;
    if (requested_workers < 0 || requested_workers > VCLGO_MAX_WORKERS)
        return vclgo_set_errno(EINVAL);

    snprintf(g_app_name, sizeof(g_app_name), "%s",
             app_name && *app_name ? app_name : "vclgo");
    g_start_released = 0;
    g_worker_count = 1;
    atomic_store(&g_round_robin, 0);

    worker_reset(&g_workers[0], 0);
    int rv = start_thread(&g_workers[0]);
    if (rv != 0)
        return vclgo_set_errno(rv);

    int error_value = wait_registered(&g_workers[0]);
    if (error_value) {
        pthread_join(g_workers[0].thread, NULL);
        return vclgo_set_errno(error_value);
    }

    g_mode2 = vls_mt_wrk_supported() != 0;
    int desired = requested_workers;
    if (desired == 0) {
        long cpus = sysconf(_SC_NPROCESSORS_ONLN);
        if (cpus < 1)
            cpus = 1;
        if (cpus > 8)
            cpus = 8;
        desired = g_mode2 ? (int)cpus : 1;
    }

    if (desired > 1 && !g_mode2) {
        atomic_store(&g_workers[0].stop, 1);
        stop_started_workers(1, 0);
        return vclgo_set_errno(EINVAL);
    }

    for (int i = 1; i < desired; i++) {
        worker_reset(&g_workers[i], (unsigned)i);
        rv = start_thread(&g_workers[i]);
        if (rv != 0) {
            g_worker_count = i;
            stop_started_workers(i, 0);
            return vclgo_set_errno(rv);
        }
        g_worker_count = i + 1;
        error_value = wait_registered(&g_workers[i]);
        if (error_value) {
            stop_started_workers(i + 1, 0);
            return vclgo_set_errno(error_value);
        }
    }

    release_workers();
    for (int i = 0; i < desired; i++) {
        error_value = wait_ready(&g_workers[i]);
        if (error_value) {
            stop_started_workers(desired, 0);
            return vclgo_set_errno(error_value);
        }
    }

    g_worker_count = desired;
    atomic_store(&g_pool_active, 1);
    VCLGO_LOG1("native worker pool: %d owner worker(s), VLS mode %d",
               desired, g_mode2 ? 2 : 3);
    return 0;
}

void
vclgo_native_pool_stop(void)
{
    if (!atomic_exchange(&g_pool_active, 0))
        return;
    stop_started_workers(g_worker_count, 1);
    VCLGO_LOG1("native worker pool: stopped");
}

int
vclgo_native_pool_worker_count(void)
{
    return atomic_load(&g_pool_active) ? g_worker_count : 0;
}

static ssize_t
call_session_request(int fd, native_request_t *request)
{
    vclgo_native_session_t *session = vclgo_native_session_lookup(fd);
    if (!session) {
        errno = EBADF;
        return -1;
    }

    request->session = session;
    ssize_t rv = submit_request(&g_workers[session->owner], request);
    vclgo_native_session_put(session);
    return rv;
}

int
vclgo_native_socket(int domain, int type, int protocol)
{
    native_request_t request;
    if (request_init(&request, NOP_SOCKET) < 0)
        return -1;
    request.int1 = domain;
    request.int2 = type;
    request.int3 = protocol;

    native_worker_t *worker = pick_worker();
    ssize_t rv = submit_request(worker, &request);
    request_destroy(&request);
    return (int)rv;
}

int
vclgo_native_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    native_request_t request;
    if (request_init(&request, NOP_BIND) < 0)
        return -1;
    request.addr = addr;
    request.addrlen = addrlen;
    ssize_t rv = call_session_request(fd, &request);
    request_destroy(&request);
    return (int)rv;
}

int
vclgo_native_listen(int fd, int backlog)
{
    native_request_t request;
    if (request_init(&request, NOP_LISTEN) < 0)
        return -1;
    request.int1 = backlog;
    ssize_t rv = call_session_request(fd, &request);
    request_destroy(&request);
    return (int)rv;
}

int
vclgo_native_accept4(int fd, struct sockaddr *addr, socklen_t *addrlen,
                     int flags)
{
    native_request_t request;
    if (request_init(&request, NOP_ACCEPT) < 0)
        return -1;
    request.out_addr = addr;
    request.out_addrlen = addrlen;
    request.int1 = flags;
    ssize_t rv = call_session_request(fd, &request);
    request_destroy(&request);
    return (int)rv;
}

int
vclgo_native_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    native_request_t request;
    if (request_init(&request, NOP_CONNECT) < 0)
        return -1;
    request.addr = addr;
    request.addrlen = addrlen;
    ssize_t rv = call_session_request(fd, &request);
    request_destroy(&request);
    return (int)rv;
}

int
vclgo_native_shutdown(int fd, int how)
{
    native_request_t request;
    if (request_init(&request, NOP_SHUTDOWN) < 0)
        return -1;
    request.int1 = how;
    ssize_t rv = call_session_request(fd, &request);
    request_destroy(&request);
    return (int)rv;
}

int
vclgo_native_close(int fd)
{
    native_request_t request;
    if (request_init(&request, NOP_CLOSE) < 0)
        return -1;
    ssize_t rv = call_session_request(fd, &request);
    request_destroy(&request);
    return (int)rv;
}

ssize_t
vclgo_native_read(int fd, void *buf, size_t count)
{
    native_request_t request;
    if (request_init(&request, NOP_READ) < 0)
        return -1;
    request.buf = buf;
    request.count = count;
    ssize_t rv = call_session_request(fd, &request);
    request_destroy(&request);
    return rv;
}

ssize_t
vclgo_native_write(int fd, const void *buf, size_t count)
{
    native_request_t request;
    if (request_init(&request, NOP_WRITE) < 0)
        return -1;
    request.const_buf = buf;
    request.count = count;
    ssize_t rv = call_session_request(fd, &request);
    request_destroy(&request);
    return rv;
}

ssize_t
vclgo_native_sendto(int fd, const void *buf, size_t count, int flags,
                    const struct sockaddr *dest_addr, socklen_t addrlen)
{
    native_request_t request;
    if (request_init(&request, NOP_SENDTO) < 0)
        return -1;
    request.const_buf = buf;
    request.count = count;
    request.flags = flags;
    request.addr = dest_addr;
    request.addrlen = addrlen;
    ssize_t rv = call_session_request(fd, &request);
    request_destroy(&request);
    return rv;
}

ssize_t
vclgo_native_recvfrom(int fd, void *buf, size_t count, int flags,
                      struct sockaddr *src_addr, socklen_t *addrlen)
{
    native_request_t request;
    if (request_init(&request, NOP_RECVFROM) < 0)
        return -1;
    request.buf = buf;
    request.count = count;
    request.flags = flags;
    request.out_addr = src_addr;
    request.out_addrlen = addrlen;
    ssize_t rv = call_session_request(fd, &request);
    request_destroy(&request);
    return rv;
}

int
vclgo_native_setsockopt(int fd, int level, int optname,
                        const void *optval, socklen_t optlen)
{
    native_request_t request;
    if (request_init(&request, NOP_SETSOCKOPT) < 0)
        return -1;
    request.int1 = level;
    request.int2 = optname;
    request.const_optval = optval;
    request.optlen_value = optlen;
    ssize_t rv = call_session_request(fd, &request);
    request_destroy(&request);
    return (int)rv;
}

int
vclgo_native_getsockopt(int fd, int level, int optname,
                        void *optval, socklen_t *optlen)
{
    native_request_t request;
    if (request_init(&request, NOP_GETSOCKOPT) < 0)
        return -1;
    request.int1 = level;
    request.int2 = optname;
    request.optval = optval;
    request.optlen = optlen;
    ssize_t rv = call_session_request(fd, &request);
    request_destroy(&request);
    return (int)rv;
}

static int
native_getname(int fd, struct sockaddr *addr, socklen_t *addrlen,
               native_op_t op)
{
    native_request_t request;
    if (request_init(&request, op) < 0)
        return -1;
    request.out_addr = addr;
    request.out_addrlen = addrlen;
    ssize_t rv = call_session_request(fd, &request);
    request_destroy(&request);
    return (int)rv;
}

int
vclgo_native_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    return native_getname(fd, addr, addrlen, NOP_GETSOCKNAME);
}

int
vclgo_native_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    return native_getname(fd, addr, addrlen, NOP_GETPEERNAME);
}
