/*
 * poller.c — the single vls_epoll_wait thread and waiter machinery.
 *
 * Design (Mode 3 default, matching vclnet/internal/vclpoll/poller.go):
 *
 *   • One dedicated pthread owns a persistent vls_epoll handle. This thread
 *     runs vls_epoll_wait in a loop, drains VPP's message queue, and fans
 *     events out to matching waiters.
 *   • Every caller that would block (EAGAIN / EINPROGRESS) registers a
 *     waiter_t with the desired event mask, then parks on that waiter's
 *     condition variable.
 *   • Multiple waiters per vlsh are supported (reader + writer). The
 *     registered epoll mask is the union; the poller wakes only waiters
 *     whose desired mask intersects the returned event bits, with
 *     EPOLLERR / EPOLLHUP / EPOLLRDHUP waking everyone (parity with
 *     vclnet's `wakeWaitSet`).
 *   • Cancellations (deadline elapsed, session closed) are honoured by
 *     signalling the waiter with `cancelled = 1`; the caller returns -1
 *     with errno = ECANCELED.
 *
 * This file deliberately does NOT spin-wait or call vls_accept in a busy
 * loop — the exact bug that made frida-vpp burn 100% CPU on idle listeners
 * (see docs/architecture.md and vclnet_deep_dive.md §13.5 issue A2).
 */

#include "internal.h"

/* ---------- Waiter state ------------------------------------------------- */

typedef struct waiter {
    int              vlsh;
    uint32_t         wanted;    /* events the caller cares about */
    uint32_t         ready;     /* events actually delivered */
    int              done;      /* 1 = wake-up delivered */
    int              cancelled; /* 1 = wake-up was a cancellation */
    pthread_mutex_t  mu;
    pthread_cond_t   cv;
    struct waiter   *next;      /* per-vlsh list */
} waiter_t;

/* Per-vlsh registration state. */
typedef struct vlsh_state {
    int                 vlsh;
    uint32_t            registered_mask;
    waiter_t           *head;
    struct vlsh_state  *next;   /* hash chain */
} vlsh_state_t;

/* ---------- Global state ------------------------------------------------- */

#define VCLGO_POLLER_BUCKETS 1024

static pthread_mutex_t g_pmu = PTHREAD_MUTEX_INITIALIZER;
static vlsh_state_t   *g_buckets[VCLGO_POLLER_BUCKETS];
static int             g_ep_vlsh = -1;
static pthread_t       g_thread;
static atomic_int      g_running;
static atomic_int      g_stop;

/* ---------- Bucket helpers ---------------------------------------------- */

static inline unsigned bucket_of(int vlsh) {
    /* Fibonacci hash on a 32-bit key, cheap and diffuses well. */
    return (unsigned)((uint32_t)vlsh * 2654435761u) & (VCLGO_POLLER_BUCKETS - 1u);
}

static vlsh_state_t *state_lookup(int vlsh) {
    vlsh_state_t *s = g_buckets[bucket_of(vlsh)];
    while (s) {
        if (s->vlsh == vlsh) return s;
        s = s->next;
    }
    return NULL;
}

static vlsh_state_t *state_intern(int vlsh) {
    vlsh_state_t *s = state_lookup(vlsh);
    if (s) return s;
    s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->vlsh = vlsh;
    unsigned b = bucket_of(vlsh);
    s->next = g_buckets[b];
    g_buckets[b] = s;
    return s;
}

static void state_remove(int vlsh) {
    unsigned b = bucket_of(vlsh);
    vlsh_state_t **link = &g_buckets[b];
    while (*link) {
        if ((*link)->vlsh == vlsh) {
            vlsh_state_t *s = *link;
            *link = s->next;
            free(s);
            return;
        }
        link = &(*link)->next;
    }
}

/* ---------- Epoll interest management ---------------------------------- */

/* Caller holds g_pmu. */
static int recompute_mask(vlsh_state_t *s, uint32_t *out) {
    uint32_t m = 0;
    for (waiter_t *w = s->head; w; w = w->next) m |= w->wanted;
    *out = m;
    return 0;
}

/* Caller holds g_pmu. */
static int ep_apply(vlsh_state_t *s, uint32_t new_mask) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof ev);
    ev.events   = new_mask | VCLGO_EV_ERR;
    ev.data.u64 = (uint64_t)(uint32_t)s->vlsh;

    int op;
    if (s->registered_mask == 0 && new_mask != 0) {
        op = EPOLL_CTL_ADD;
    } else if (new_mask == 0) {
        op = EPOLL_CTL_DEL;
    } else {
        op = EPOLL_CTL_MOD;
    }

    int rv = vls_epoll_ctl(g_ep_vlsh, op, s->vlsh, &ev);
    if (rv < 0) {
        VCLGO_LOG2("epoll_ctl(op=%d vlsh=%d mask=0x%x) -> %d",
                   op, s->vlsh, new_mask, rv);
        return -1;
    }
    s->registered_mask = new_mask;
    return 0;
}

/* ---------- Public poller API ------------------------------------------ */

static void *poller_main(void *arg);

int vclgo_poller_start(void)
{
    if (atomic_load(&g_running)) return 0;

    /* Create the shared VLS epoll instance. The pthread that owns it must
     * be the same one that later drains it, per VLS's contract. */
    int ep = vls_epoll_create();
    if (ep < 0) {
        VCLGO_LOG1("poller: vls_epoll_create failed: %d", ep);
        return vclgo_from_vppcom(ep);
    }
    g_ep_vlsh = ep;

    atomic_store(&g_stop, 0);
    atomic_store(&g_running, 1);
    int rc = pthread_create(&g_thread, NULL, poller_main, NULL);
    if (rc != 0) {
        atomic_store(&g_running, 0);
        vls_close(ep);
        g_ep_vlsh = -1;
        return vclgo_set_errno(rc);
    }
    VCLGO_LOG1("poller: started (ep_vlsh=%d)", ep);
    return 0;
}

void vclgo_poller_stop(void)
{
    if (!atomic_load(&g_running)) return;
    atomic_store(&g_stop, 1);

    /* Wake all parked waiters. */
    pthread_mutex_lock(&g_pmu);
    for (int b = 0; b < VCLGO_POLLER_BUCKETS; b++) {
        for (vlsh_state_t *s = g_buckets[b]; s; s = s->next) {
            for (waiter_t *w = s->head; w; w = w->next) {
                pthread_mutex_lock(&w->mu);
                if (!w->done) {
                    w->done      = 1;
                    w->cancelled = 1;
                    pthread_cond_signal(&w->cv);
                }
                pthread_mutex_unlock(&w->mu);
            }
        }
    }
    pthread_mutex_unlock(&g_pmu);

    pthread_join(g_thread, NULL);
    atomic_store(&g_running, 0);

    if (g_ep_vlsh >= 0) {
        vls_close(g_ep_vlsh);
        g_ep_vlsh = -1;
    }
    VCLGO_LOG1("poller: stopped");
}

int vclgo_poller_wait(int vlsh, uint32_t events, int timeout_ms)
{
    if (g_ep_vlsh < 0) {
        return vclgo_set_errno(ENOSYS);
    }

    waiter_t w;
    memset(&w, 0, sizeof w);
    w.vlsh   = vlsh;
    w.wanted = events;
    pthread_mutex_init(&w.mu, NULL);

    /* Bind the cv to CLOCK_MONOTONIC so wall-clock changes (NTP step,
     * VM restore, `date -s`) don't shift the wait deadline (S1-4). */
    pthread_condattr_t cvattr;
    pthread_condattr_init(&cvattr);
    pthread_condattr_setclock(&cvattr, CLOCK_MONOTONIC);
    pthread_cond_init(&w.cv, &cvattr);
    pthread_condattr_destroy(&cvattr);

    /* Publish waiter and (re-)arm epoll interest. */
    pthread_mutex_lock(&g_pmu);
    vlsh_state_t *s = state_intern(vlsh);
    if (!s) {
        pthread_mutex_unlock(&g_pmu);
        pthread_mutex_destroy(&w.mu);
        pthread_cond_destroy(&w.cv);
        return vclgo_set_errno(ENOMEM);
    }
    w.next = s->head;
    s->head = &w;

    uint32_t new_mask;
    recompute_mask(s, &new_mask);
    if (new_mask != s->registered_mask) {
        if (ep_apply(s, new_mask) < 0) {
            /* Undo the enqueue on hard failure. */
            s->head = w.next;
            if (!s->head) state_remove(vlsh);
            pthread_mutex_unlock(&g_pmu);
            pthread_mutex_destroy(&w.mu);
            pthread_cond_destroy(&w.cv);
            return vclgo_set_errno(EIO);
        }
    }
    atomic_fetch_add(&vclgo_stat_eagain_parked, 1);
    pthread_mutex_unlock(&g_pmu);

    /* Park on the waiter cv. timeout_ms < 0 means "wait indefinitely";
     * the caller is unblocked only by an epoll event, a cancellation
     * (peer close / vclgo_poller_drop), or teardown. */
    struct timespec deadline_ts;
    int use_deadline = 0;
    if (timeout_ms >= 0) {
        clock_gettime(CLOCK_MONOTONIC, &deadline_ts);
        deadline_ts.tv_sec  += timeout_ms / 1000;
        deadline_ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
        if (deadline_ts.tv_nsec >= 1000000000L) {
            deadline_ts.tv_sec  += 1;
            deadline_ts.tv_nsec -= 1000000000L;
        }
        use_deadline = 1;
    }

    int timed_out = 0;
    pthread_mutex_lock(&w.mu);
    while (!w.done) {
        int rc;
        if (use_deadline) {
            rc = pthread_cond_timedwait(&w.cv, &w.mu, &deadline_ts);
            if (rc == ETIMEDOUT) { timed_out = 1; break; }
        } else {
            rc = pthread_cond_wait(&w.cv, &w.mu);
            (void)rc;
        }
    }
    int cancelled = w.cancelled;
    uint32_t ready = w.ready;
    pthread_mutex_unlock(&w.mu);

    /* Detach waiter and re-arm epoll to the (possibly reduced) mask. */
    pthread_mutex_lock(&g_pmu);
    s = state_lookup(vlsh);
    if (s) {
        waiter_t **link = &s->head;
        while (*link) {
            if (*link == &w) { *link = w.next; break; }
            link = &(*link)->next;
        }
        uint32_t nm;
        recompute_mask(s, &nm);
        if (nm != s->registered_mask) ep_apply(s, nm);
        if (!s->head) state_remove(vlsh);
    }
    pthread_mutex_unlock(&g_pmu);

    pthread_mutex_destroy(&w.mu);
    pthread_cond_destroy(&w.cv);

    if (cancelled) return vclgo_set_errno(ECANCELED);
    if (timed_out) return 0;   /* zero events = timeout */
    return (int)ready;
}

void vclgo_poller_drop(int vlsh)
{
    pthread_mutex_lock(&g_pmu);
    vlsh_state_t *s = state_lookup(vlsh);
    if (s) {
        /* Cancel every parked waiter so they return promptly. */
        for (waiter_t *w = s->head; w; w = w->next) {
            pthread_mutex_lock(&w->mu);
            if (!w->done) {
                w->done      = 1;
                w->cancelled = 1;
                pthread_cond_signal(&w->cv);
            }
            pthread_mutex_unlock(&w->mu);
        }
        if (s->registered_mask != 0) {
            struct epoll_event ev = { 0 };
            vls_epoll_ctl(g_ep_vlsh, EPOLL_CTL_DEL, vlsh, &ev);
            s->registered_mask = 0;
        }
        s->head = NULL;
        state_remove(vlsh);
    }
    pthread_mutex_unlock(&g_pmu);
}

/* ---------- Poller thread body ---------------------------------------- */

static void deliver(int vlsh, uint32_t events)
{
    pthread_mutex_lock(&g_pmu);
    vlsh_state_t *s = state_lookup(vlsh);
    if (!s) {
        VCLGO_LOG2("poller: deliver vlsh=%d events=0x%x — no state (dropped)",
                   vlsh, events);
        pthread_mutex_unlock(&g_pmu);
        return;
    }

    /* An error/hangup wakes every parked waiter regardless of desired mask,
     * matching vclnet's wakeWaitSet-on-error behaviour so close/reset never
     * strand a reader or writer. */
    int wake_all = (events & VCLGO_EV_ERR) != 0;

    int woken = 0, skipped = 0;
    for (waiter_t *w = s->head; w; w = w->next) {
        if (!wake_all && (w->wanted & events) == 0) { skipped++; continue; }
        pthread_mutex_lock(&w->mu);
        if (!w->done) {
            w->done  = 1;
            w->ready = events;
            pthread_cond_signal(&w->cv);
            woken++;
        }
        pthread_mutex_unlock(&w->mu);
    }
    VCLGO_LOG2("poller: deliver vlsh=%d events=0x%x → woken=%d skipped=%d",
               vlsh, events, woken, skipped);
    pthread_mutex_unlock(&g_pmu);
    atomic_fetch_add(&vclgo_stat_poller_wakeups, 1);
}

static void *poller_main(void *arg)
{
    (void)arg;

    /* Name for observability (harmless if it fails). */
    pthread_setname_np(pthread_self(), "vclgo-poller");

    struct epoll_event events[128];

    while (!atomic_load(&g_stop)) {
        /* Short timeout keeps us responsive to stop signals and periodic
         * MQ drain without spinning. 50ms mirrors vclnet's compromise. */
        int n = vls_epoll_wait(g_ep_vlsh, events, 128, 50);
        if (n < 0) {
            if (n == -EINTR) continue;
            VCLGO_LOG1("poller: vls_epoll_wait: %d", n);
            struct timespec ts = { 0, 10 * 1000 * 1000 };
            nanosleep(&ts, NULL);
            continue;
        }
        for (int i = 0; i < n; i++) {
            int vlsh = (int)events[i].data.u64;
            deliver(vlsh, events[i].events);
        }
    }
    return NULL;
}
