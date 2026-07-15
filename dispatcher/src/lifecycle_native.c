/*
 * lifecycle_native.c - process lifecycle for the LD_PRELOAD/seccomp backend.
 */

#include "native_internal.h"

int vclgo_log_level = 1;
atomic_int vclgo_state;

/* Serialises the STOPPING → STOPPED transition so concurrent teardown
 * callers (particularly seccomp notifiers observing `exit_group` on
 * multiple threads) synchronise before returning to the kernel. */
static pthread_mutex_t g_teardown_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_teardown_cv = PTHREAD_COND_INITIALIZER;

_Atomic uint64_t vclgo_stat_sockets_opened;
_Atomic uint64_t vclgo_stat_sockets_closed;
_Atomic uint64_t vclgo_stat_reads;
_Atomic uint64_t vclgo_stat_writes;
_Atomic uint64_t vclgo_stat_accepts;
_Atomic uint64_t vclgo_stat_connects;
_Atomic uint64_t vclgo_stat_eagain_parked;
_Atomic uint64_t vclgo_stat_poller_wakeups;

int *
vclgo_errno_addr(void)
{
    return &errno;
}

int
vclgo_abi_version(void)
{
    return VCLGO_ABI_VERSION;
}

int
vclgo_passthrough(void)
{
    return atomic_load(&vclgo_state) == VCLGO_STATE_PASSTHROUGH;
}

int
vclgo_pin_current_thread(void)
{
    /* Public calls are queued to pinned owner workers; callers never enter
     * VLS and therefore need no VCL TLS registration. */
    return 0;
}

void
vclgo_unpin_current_thread(void)
{
}

static int
parse_worker_count(void)
{
    const char *value = getenv("VCLGO_WORKERS");
    if (!value || !*value)
        return 0; /* auto */

    char *end = NULL;
    errno = 0;
    long count = strtol(value, &end, 10);
    if (errno || !end || *end || count < 1 ||
        count > VCLGO_MAX_WORKERS)
        return -1;
    return (int)count;
}

static void
parse_env(void)
{
    const char *value = getenv("VCLGO_LOG");
    if (value && *value)
        vclgo_log_level = atoi(value);
}

int
vclgo_init(const char *app_name)
{
    int expected = VCLGO_STATE_UNINIT;
    if (!atomic_compare_exchange_strong(&vclgo_state, &expected,
                                        VCLGO_STATE_INITIALIZING)) {
        while (atomic_load(&vclgo_state) == VCLGO_STATE_INITIALIZING)
            sched_yield();
        int state = atomic_load(&vclgo_state);
        if (state == VCLGO_STATE_ACTIVE ||
            state == VCLGO_STATE_PASSTHROUGH)
            return 0;
        return vclgo_set_errno((state == VCLGO_STATE_STOPPING ||
                                state == VCLGO_STATE_STOPPED) ?
                               ECANCELED : EIO);
    }

    parse_env();
    if (!getenv(VPPCOM_ENV_CONF)) {
        VCLGO_LOG1("VCL_CONFIG unset - native backend is passthrough");
        atomic_store(&vclgo_state, VCLGO_STATE_PASSTHROUGH);
        return 0;
    }

    int requested_workers = parse_worker_count();
    if (requested_workers < 0) {
        VCLGO_LOG1("invalid VCLGO_WORKERS (expected 1..%d)",
                   VCLGO_MAX_WORKERS);
        atomic_store(&vclgo_state, VCLGO_STATE_UNINIT);
        return vclgo_set_errno(EINVAL);
    }

    if (vclgo_native_registry_prepare() < 0) {
        VCLGO_LOG1("RLIMIT_NOFILE must permit reserved fd range %u..%u",
                   VCLGO_FD_BASE, VCLGO_FD_LIMIT - 1);
        atomic_store(&vclgo_state, VCLGO_STATE_UNINIT);
        return -1;
    }

    char name[64];
    const char *base = app_name && *app_name ? app_name : "vclgo";
    snprintf(name, sizeof(name), "%s-%d", base, (int)getpid());

    if (vclgo_native_pool_start(name, requested_workers) < 0) {
        int saved_errno = errno;
        if (saved_errno == EINVAL && requested_workers > 1) {
            VCLGO_LOG1("VCLGO_WORKERS=%d requires multi-thread-workers "
                       "inside the vcl configuration block",
                       requested_workers);
        } else {
            VCLGO_LOG1("native worker-pool initialization failed: %s",
                       strerror(saved_errno));
        }
        atomic_store(&vclgo_state, VCLGO_STATE_UNINIT);
        errno = saved_errno;
        return -1;
    }

    atomic_store(&vclgo_state, VCLGO_STATE_ACTIVE);
    atexit(vclgo_teardown);
    return 0;
}

static int
teardown_state_is_terminal(int state)
{
    /* STOPPED means "winner finished". UNINIT means "teardown was never
     * needed, e.g. passthrough or failed init"; either way no VCL state
     * is live. PASSTHROUGH is likewise trivially safe to return from. */
    return state == VCLGO_STATE_STOPPED ||
           state == VCLGO_STATE_UNINIT ||
           state == VCLGO_STATE_PASSTHROUGH;
}

void
vclgo_teardown(void)
{
    int expected = VCLGO_STATE_ACTIVE;
    if (atomic_compare_exchange_strong(&vclgo_state, &expected,
                                       VCLGO_STATE_STOPPING)) {
        /* We won; do the actual work. */
        vclgo_native_pool_stop();
        size_t leaked = vclgo_native_registry_size();
        if (leaked)
            VCLGO_LOG1("teardown: %zu registry entr%s remained",
                       leaked, leaked == 1 ? "y" : "ies");

        pthread_mutex_lock(&g_teardown_mu);
        atomic_store(&vclgo_state, VCLGO_STATE_STOPPED);
        pthread_cond_broadcast(&g_teardown_cv);
        pthread_mutex_unlock(&g_teardown_mu);
        VCLGO_LOG1("teardown complete");
        return;
    }

    /* Loser: either another thread is running teardown right now, or it
     * already finished, or the state is trivially terminal. In all cases
     * we block until the terminal state is visible before returning. */
    vclgo_wait_teardown_complete();
}

void
vclgo_wait_teardown_complete(void)
{
    if (teardown_state_is_terminal(atomic_load(&vclgo_state)))
        return;

    pthread_mutex_lock(&g_teardown_mu);
    while (!teardown_state_is_terminal(atomic_load(&vclgo_state)))
        pthread_cond_wait(&g_teardown_cv, &g_teardown_mu);
    pthread_mutex_unlock(&g_teardown_mu);
}

int
vclgo_worker_count(void)
{
    return vclgo_native_pool_worker_count();
}

void
vclgo_stats_snapshot(vclgo_stats_t *out)
{
    if (!out)
        return;
    out->sockets_opened = atomic_load(&vclgo_stat_sockets_opened);
    out->sockets_closed = atomic_load(&vclgo_stat_sockets_closed);
    out->reads = atomic_load(&vclgo_stat_reads);
    out->writes = atomic_load(&vclgo_stat_writes);
    out->accepts = atomic_load(&vclgo_stat_accepts);
    out->connects = atomic_load(&vclgo_stat_connects);
    out->eagain_parked = atomic_load(&vclgo_stat_eagain_parked);
    out->poller_wakeups = atomic_load(&vclgo_stat_poller_wakeups);
}
