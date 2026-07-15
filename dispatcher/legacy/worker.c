/*
 * worker.c — Stack-safe offload of deep VLS calls.
 *
 * Motivation (S1-14): Frida's `Interceptor.attach` callbacks — and any
 * `NativeFunction` invoked from them — run on **the target thread's
 * current stack**. When the target is Go, that thread is an M running a
 * goroutine whose initial stack is **8 KiB** and grows lazily via a
 * compiler-emitted prologue check. `Interceptor.replace` replaces the
 * Go function's body with a bare `ret` trampoline, so the prologue
 * never runs and Go never grows the stack before we descend into
 * `vls_read` → `vppcom_session_read` → memcpy machinery. Under sustained
 * load (multi-goroutine echo workloads) we consistently push past 4 – 6
 * KiB and corrupt whichever frame slot happens to sit past the guard,
 * yielding the classic `pc == addr` control-flow hijack fingerprint
 * (see docs/analysis_bugs.md §S1-14). frida-vpp hit the same class of
 * bug on their `accept4` epoll wait and worked around it by keeping
 * hot-path handlers free of `NativeFunction` calls; we take the more
 * general fix and move the deep call chain onto a dedicated pthread
 * with a normal (multi-MiB) stack.
 *
 * Design (single worker thread):
 *
 *   1. The interceptor calls `vclgo_worker_read` / `_write`, which:
 *      - assemble a `wreq_t` on the *caller's* stack (≈ 200 B),
 *      - link it onto a shared FIFO,
 *      - signal the worker via a global condvar,
 *      - park on the request's own condvar until `done`.
 *      Total goroutine-stack cost: ≈ 500 B in the hot path plus
 *      whatever `pthread_cond_wait` uses (≈ 200 B). Well under 8 KiB.
 *
 *   2. The worker thread pops requests, runs the exact same loop that
 *      previously lived in `vclgo_read` / `_write` (vls_read + poller
 *      park + retry on EAGAIN), and signals completion. Because it runs
 *      on a normal pthread stack (~8 MiB), the deep vppcom call chain
 *      is safe.
 *
 * Serialisation trade-off: a single worker thread means all VLS r/w
 * calls are serialised. This is acceptable for Phase 1 because VLS
 * already serialises via its per-worker lock; parallelism would require
 * multiple VCL workers (`multi-thread-workers 1` in vcl.conf plus
 * per-thread `vls_register_vcl_worker` bookkeeping), which is Phase-2
 * scope. If throughput becomes a bottleneck before Phase 2, promote
 * this to a small worker pool + round-robin dispatch.
 *
 * The passthrough / EBADF gates stay in the interceptor-facing wrappers
 * (`vclgo_read` / `_write` in sockets.c) so that non-VCL fds never even
 * reach the queue.
 */

#include "internal.h"

#include <stdint.h>

/* ---------- Request struct & FIFO ------------------------------------- */

typedef enum {
    WOP_READ,
    WOP_WRITE,
} wop_t;

typedef struct wreq {
    wop_t          op;
    int            fd;
    void          *buf;    /* WOP_READ: dest; WOP_WRITE: source (const cast) */
    size_t         count;

    /* Output — worker writes these before signalling `done`. */
    ssize_t        rv;
    int            errno_val;

    /* Per-request sync. Placed on the CALLER's stack because we hold
     * the lock across the entire wait; the worker never dereferences
     * `w` after signalling, and the caller doesn't return until it has
     * observed done=1 under `mu`. See S1-14 discussion for why we do
     * NOT reuse the S2-1 stack-allocated waiter pattern from poller.c
     * (different lifetime story: g_pmu mediates every waiter access
     * there; here the sync is 1:1 caller↔worker). */
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    int             done;

    struct wreq   *next;
} wreq_t;

static pthread_mutex_t g_wq_mu   = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_wq_cv;                /* CLOCK_MONOTONIC */
static wreq_t         *g_wq_head, *g_wq_tail;

static pthread_t       g_worker;
static atomic_int      g_worker_running;       /* 1 while worker alive */
static atomic_int      g_worker_stop;          /* set by teardown */

/* ---------- Queue helpers -------------------------------------------- */

static void wq_push(wreq_t *r)
{
    pthread_mutex_lock(&g_wq_mu);
    r->next = NULL;
    if (g_wq_tail)
        g_wq_tail->next = r;
    else
        g_wq_head = r;
    g_wq_tail = r;
    pthread_cond_signal(&g_wq_cv);
    pthread_mutex_unlock(&g_wq_mu);
}

/* Blocks until a request arrives or `g_worker_stop` is set. Returns NULL
 * on stop, otherwise the head request (removed from the queue). */
static wreq_t *wq_pop_blocking(void)
{
    pthread_mutex_lock(&g_wq_mu);
    while (!g_wq_head && !atomic_load(&g_worker_stop))
        pthread_cond_wait(&g_wq_cv, &g_wq_mu);

    wreq_t *r = NULL;
    if (g_wq_head) {
        r = g_wq_head;
        g_wq_head = r->next;
        if (!g_wq_head) g_wq_tail = NULL;
    }
    pthread_mutex_unlock(&g_wq_mu);
    return r;
}

/* Wake every pending caller with -1/EIO on stop so nobody hangs. */
static void wq_drain_on_stop(void)
{
    pthread_mutex_lock(&g_wq_mu);
    wreq_t *r = g_wq_head;
    g_wq_head = g_wq_tail = NULL;
    pthread_mutex_unlock(&g_wq_mu);

    while (r) {
        wreq_t *next = r->next;
        pthread_mutex_lock(&r->mu);
        r->rv        = -1;
        r->errno_val = EIO;
        r->done      = 1;
        pthread_cond_signal(&r->cv);
        pthread_mutex_unlock(&r->mu);
        r = next;
    }
}

/* ---------- Actual read/write bodies (formerly in sockets.c) --------- */
/*
 * These are the exact loops that used to live inline in vclgo_read /
 * vclgo_write. They still call vclgo_poller_wait (which itself blocks
 * on pthread_cond_wait) but they run on the worker's own 8-MiB pthread
 * stack, so the deep vppcom_session_read call chain no longer eats into
 * a goroutine's 8-KiB slice.
 *
 * Semantics are unchanged. See the retained comments for the S1-2 /
 * S1-6 / S1-8 references.
 */

static ssize_t do_write_partial_or_err(size_t remaining, size_t count)
{
    if (remaining < count) {
        atomic_fetch_add(&vclgo_stat_writes, 1);
        return (ssize_t)(count - remaining);
    }
    return -1;
}

static ssize_t do_read(int fd, void *buf, size_t count)
{
    int vlsh = vclgo_fd_to_vlsh(fd);
    int peer_closed = 0;
    for (;;) {
        ssize_t n = vls_read((vls_handle_t)vlsh, buf, count);
        if (n > 0) {
            atomic_fetch_add(&vclgo_stat_reads, 1);
            return n;
        }
        if (n == 0) {
            atomic_fetch_add(&vclgo_stat_reads, 1);
            return 0;
        }
        if (n != VPPCOM_EAGAIN)
            return (ssize_t)vclgo_from_vppcom((int)n);

        /* S1-8: one final drain attempt once we've observed HUP; a
         * second EAGAIN is genuine EOF. */
        if (peer_closed) return 0;

        /* S1-2: unbounded wait — never surface EAGAIN to Go. */
        int ev = vclgo_poller_wait(vlsh, VCLGO_EV_READ, -1);
        if (ev < 0) return -1;
        /*
         * EPOLLERR means a hard session error (RST, ECONNRESET, ECONNABORTED).
         * If vls_read on the next iteration doesn't surface the error via a
         * negative return, we would otherwise silently promote the error to
         * EOF — Go would then see (0, io.EOF) and think the peer closed
         * cleanly, which loses the ECONNRESET. Query VPP's per-session
         * error, and if there's a real errno pending, surface it.
         */
        if (ev & EPOLLERR) {
            int sockerr = 0;
            uint32_t elen = sizeof sockerr;
            (void)vls_attr((vls_handle_t)vlsh, VPPCOM_ATTR_GET_ERROR,
                           &sockerr, &elen);
            if (sockerr != 0) return vclgo_set_errno(sockerr);
            /* Fall through to the HUP drain path if no explicit errno. */
        }
        if (ev & (EPOLLHUP | EPOLLRDHUP)) peer_closed = 1;
    }
}

static ssize_t do_write(int fd, const void *buf, size_t count)
{
    int vlsh = vclgo_fd_to_vlsh(fd);
    const uint8_t *p = buf;
    size_t remaining = count;

    while (remaining > 0) {
        ssize_t n = vls_write((vls_handle_t)vlsh, (void *)p, remaining);
        if (n > 0) {
            p         += (size_t)n;
            remaining -= (size_t)n;
            continue;
        }
        if (n == 0) {
            /* Zero-progress write with room to write: treat as EPIPE-shaped
             * refusal so we don't falsely report `count` bytes accepted.
             * Return any partial we already made; otherwise surface EPIPE. */
            vclgo_set_errno(EPIPE);
            return do_write_partial_or_err(remaining, count);
        }
        if (n != VPPCOM_EAGAIN) {
            int e = -((int)n);
            vclgo_set_errno(e);
            return do_write_partial_or_err(remaining, count);
        }
        int ev = vclgo_poller_wait(vlsh, VCLGO_EV_WRITE, -1);
        if (ev < 0)
            return do_write_partial_or_err(remaining, count);
        if (ev & (EPOLLERR | EPOLLHUP)) {
            vclgo_set_errno(EPIPE);
            return do_write_partial_or_err(remaining, count);
        }
    }
    atomic_fetch_add(&vclgo_stat_writes, 1);
    return (ssize_t)count;
}

/* ---------- Worker main --------------------------------------------- */

static void *worker_main(void *unused)
{
    (void)unused;

    /* No explicit vls_register_vcl_worker call here — VLS Mode 3
     * (default) lazily attaches on first vls_* use. See
     * vclgo_pin_current_thread() for the rationale. */
    VCLGO_LOG1("worker: started");

    for (;;) {
        wreq_t *r = wq_pop_blocking();
        if (!r) {
            /* Stop was requested and the queue is empty. */
            break;
        }

        errno = 0;
        switch (r->op) {
        case WOP_READ:
            r->rv = do_read(r->fd, r->buf, r->count);
            break;
        case WOP_WRITE:
            r->rv = do_write(r->fd, r->buf, r->count);
            break;
        }
        r->errno_val = (r->rv < 0) ? errno : 0;

        pthread_mutex_lock(&r->mu);
        r->done = 1;
        pthread_cond_signal(&r->cv);
        pthread_mutex_unlock(&r->mu);
        /* MUST NOT touch `r` after this: caller may have already
         * returned and popped its stack frame. */
    }

    VCLGO_LOG1("worker: stopped");
    return NULL;
}

/* ---------- Lifecycle ------------------------------------------------ */

int vclgo_worker_start(void)
{
    pthread_condattr_t cvattr;
    pthread_condattr_init(&cvattr);
    pthread_condattr_setclock(&cvattr, CLOCK_MONOTONIC);
    pthread_cond_init(&g_wq_cv, &cvattr);
    pthread_condattr_destroy(&cvattr);

    atomic_store(&g_worker_stop, 0);
    atomic_store(&g_worker_running, 1);

    int rc = pthread_create(&g_worker, NULL, worker_main, NULL);
    if (rc != 0) {
        atomic_store(&g_worker_running, 0);
        return vclgo_set_errno(rc);
    }
    return 0;
}

void vclgo_worker_stop(void)
{
    if (!atomic_load(&g_worker_running)) return;

    atomic_store(&g_worker_stop, 1);
    pthread_mutex_lock(&g_wq_mu);
    pthread_cond_broadcast(&g_wq_cv);
    pthread_mutex_unlock(&g_wq_mu);

    pthread_join(g_worker, NULL);
    atomic_store(&g_worker_running, 0);

    /* Any request that snuck in between broadcast and join must not
     * leave its caller parked forever. */
    wq_drain_on_stop();

    pthread_cond_destroy(&g_wq_cv);
}

/* ---------- Caller-facing API --------------------------------------- */

static ssize_t submit_and_wait(wop_t op, int fd, void *buf, size_t count)
{
    if (!atomic_load(&g_worker_running)) {
        /* Belt-and-braces: shouldn't happen if vclgo_init succeeded,
         * but bail gracefully rather than hanging on a dead worker. */
        return vclgo_set_errno(EIO);
    }

    wreq_t r;
    memset(&r, 0, sizeof r);
    r.op    = op;
    r.fd    = fd;
    r.buf   = buf;
    r.count = count;

    if (pthread_mutex_init(&r.mu, NULL) != 0)
        return vclgo_set_errno(ENOMEM);

    pthread_condattr_t cvattr;
    pthread_condattr_init(&cvattr);
    pthread_condattr_setclock(&cvattr, CLOCK_MONOTONIC);
    if (pthread_cond_init(&r.cv, &cvattr) != 0) {
        pthread_condattr_destroy(&cvattr);
        pthread_mutex_destroy(&r.mu);
        return vclgo_set_errno(ENOMEM);
    }
    pthread_condattr_destroy(&cvattr);

    wq_push(&r);

    pthread_mutex_lock(&r.mu);
    while (!r.done)
        pthread_cond_wait(&r.cv, &r.mu);
    pthread_mutex_unlock(&r.mu);

    ssize_t rv        = r.rv;
    int     errno_val = r.errno_val;

    pthread_mutex_destroy(&r.mu);
    pthread_cond_destroy(&r.cv);

    if (rv < 0 && errno_val != 0) errno = errno_val;
    return rv;
}

ssize_t vclgo_worker_read(int fd, void *buf, size_t count)
{
    return submit_and_wait(WOP_READ, fd, buf, count);
}

ssize_t vclgo_worker_write(int fd, const void *buf, size_t count)
{
    /* WOP_WRITE never mutates the buffer; cast away const at the ABI
     * edge, mirroring vls_write's own signature. */
    return submit_and_wait(WOP_WRITE, fd, (void *)buf, count);
}
