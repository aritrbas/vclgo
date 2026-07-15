/*
 * lifecycle.c — init/teardown, global state, stats, per-thread errno.
 */

#include "internal.h"

#include <signal.h>
#include <string.h>

int  vclgo_log_level = 1;
atomic_int vclgo_state;

_Atomic uint64_t vclgo_stat_sockets_opened;
_Atomic uint64_t vclgo_stat_sockets_closed;
_Atomic uint64_t vclgo_stat_reads;
_Atomic uint64_t vclgo_stat_writes;
_Atomic uint64_t vclgo_stat_accepts;
_Atomic uint64_t vclgo_stat_connects;
_Atomic uint64_t vclgo_stat_eagain_parked;
_Atomic uint64_t vclgo_stat_poller_wakeups;

/*
 * vclgo_errno_addr returns the address of the *current thread's* libc errno
 * slot. It's just `&errno` — glibc/musl define `errno` as
 * `(*__errno_location())`, so taking its address gives you the per-thread
 * int the caller can then read/write.
 *
 *   1. `vclgo_set_errno` (see internal.h) writes to libc `errno`, so any
 *      consumer that reads via this accessor sees the same value.
 *   2. Callers that cache the returned pointer must cache it per-thread.
 *      The Frida interceptor previously cached it once at script init on a
 *      helper thread, so every failing hook read that thread's zero slot
 *      and `readErrno() || EIO` misreported every error as EIO. The Frida
 *      side has been rewritten to call `__errno_location` on every access
 *      to sidestep that pitfall (S1-9).
 */
int *vclgo_errno_addr(void)
{
    return &errno;
}

int vclgo_abi_version(void) { return VCLGO_ABI_VERSION; }

int vclgo_passthrough(void) {
    return atomic_load(&vclgo_state) == VCLGO_STATE_PASSTHROUGH;
}

int vclgo_pin_current_thread(void)
{
    /* In Mode 3 (no `multi-thread-workers` in vcl.conf) VLS's own vls_mt_add
     * machinery lazily attaches the calling pthread to the shared VCL
     * worker 0 on first use. We do not need to call vls_register_vcl_worker
     * ourselves. The Go runtime already guarantees that the calling M/pthread
     * cannot migrate mid-syscall (we are inside a syscall wrapper), so no
     * additional pinning is required in the C dispatcher.
     *
     * This function exists as an explicit hook so Phase 2 / Mode 2 can add
     * proper vls_register_vcl_worker calls without disturbing callers. */
    return 0;
}

void vclgo_unpin_current_thread(void)
{
    /* Currently a no-op in Mode 3. Kept as a symmetric hook for Phase 2. */
}

static void parse_env(void)
{
    const char *lv = getenv("VCLGO_LOG");
    if (lv && *lv) vclgo_log_level = atoi(lv);
}

/*
 * B-11: emergency crash-time cleanup.
 *
 * When Go crashes (SIGSEGV / SIGABRT / SIGBUS from `runtime.throw`),
 * atexit handlers do NOT run, so `vclgo_teardown` is skipped, so
 * `vppcom_app_destroy` never fires, so VPP retains our bind/listen state
 * — the next `vclgo run` collides with EADDRINUSE.
 *
 * We install a saved-and-chained handler for the fatal signals that
 * calls `vppcom_app_destroy` from a signal context, then re-raises the
 * signal against the previously-installed handler (Go's own crash
 * reporter) so the process still dies with its original signal and
 * exit code.
 *
 * Signal-safety: `vppcom_app_destroy` is emphatically NOT async-signal-safe,
 * but at this point the process is dying anyway. Best-effort cleanup with
 * a lock-around-recursion guard is strictly better than the alternative
 * of leaving VPP with a dangling app.
 */
static struct sigaction g_prev_segv, g_prev_abrt, g_prev_bus;
static atomic_int       g_in_crash_handler;

static void crash_cleanup(int signo, siginfo_t *info, void *ctx)
{
    /* Re-entrancy guard: if we crash INSIDE cleanup, don't loop. */
    int expected = 0;
    if (atomic_compare_exchange_strong(&g_in_crash_handler, &expected, 1)) {
        /* Only clean up if we still think VPP is initialised. */
        if (atomic_load(&vclgo_state) == VCLGO_STATE_ACTIVE) {
            atomic_store(&vclgo_state, VCLGO_STATE_UNINIT);
            /* Skip poller/worker stop — they may be parked on this
             * exact stack; touching them from a signal handler is
             * strictly worse than leaking their threads (process is
             * dying anyway). Just release VPP's app-side state. */
            vppcom_app_destroy();
        }
    }

    /* Chain to Go's / the default handler so the crash still surfaces. */
    struct sigaction *prev = NULL;
    switch (signo) {
    case SIGSEGV: prev = &g_prev_segv; break;
    case SIGABRT: prev = &g_prev_abrt; break;
    case SIGBUS:  prev = &g_prev_bus;  break;
    }
    if (prev && (prev->sa_flags & SA_SIGINFO) && prev->sa_sigaction) {
        prev->sa_sigaction(signo, info, ctx);
        return;
    }
    if (prev && prev->sa_handler && prev->sa_handler != SIG_DFL
             && prev->sa_handler != SIG_IGN) {
        prev->sa_handler(signo);
        return;
    }
    /* Default: reset to SIG_DFL and re-raise so the process dies with the
     * original signal (and any core dump the shell asked for). */
    struct sigaction dfl;
    memset(&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    sigemptyset(&dfl.sa_mask);
    sigaction(signo, &dfl, NULL);
    raise(signo);
}

static void install_crash_handlers(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = crash_cleanup;
    sa.sa_flags     = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, &g_prev_segv);
    sigaction(SIGABRT, &sa, &g_prev_abrt);
    sigaction(SIGBUS,  &sa, &g_prev_bus);
}

int vclgo_init(const char *app_name)
{
    /*
     * S1-1: three-state CAS. Reserve the initialisation slot by moving
     * UNINIT -> INITIALIZING. Losers spin (sched_yield) until the winner
     * publishes a terminal state, then return based on that state.
     *
     * The original code CAS'd UNINIT -> UNINIT which was a no-op; every
     * racing caller would independently attempt vls_app_create and the
     * duplicate calls would fail. Under Phase-1 Frida injection the race
     * is latent (interceptor.js runs before user code), but Phase-2's
     * native LD_PRELOAD injector runs from a .init ctor concurrently
     * with the loader's own threads, where the race is real.
     */
    int expected = VCLGO_STATE_UNINIT;
    if (!atomic_compare_exchange_strong(&vclgo_state, &expected,
                                        VCLGO_STATE_INITIALIZING)) {
        /* Someone else is either initialising, initialised, or has
         * declared passthrough. Wait for them and mirror their outcome. */
        while (atomic_load(&vclgo_state) == VCLGO_STATE_INITIALIZING) {
            sched_yield();
        }
        int st = atomic_load(&vclgo_state);
        if (st == VCLGO_STATE_ACTIVE || st == VCLGO_STATE_PASSTHROUGH) {
            return 0;
        }
        /* The winner failed and reset state to UNINIT; report the same. */
        return vclgo_set_errno(EIO);
    }

    /* We won the CAS. From here on we are the single writer of
     * vclgo_state until we publish a terminal value. */
    parse_env();

    if (!getenv(VPPCOM_ENV_CONF)) {
        VCLGO_LOG1("VCL_CONFIG unset — running in passthrough mode "
                   "(all syscalls forwarded to kernel)");
        atomic_store(&vclgo_state, VCLGO_STATE_PASSTHROUGH);
        return 0;
    }

    vclgo_fdmap_init();

    /*
     * Build a per-process unique app name so two vclgo-intercepted binaries
     * on the same VPP (echo_server + echo_client in the smoke test) do NOT
     * collide in VPP's app-registration table. Historically both called
     * vls_app_create("vclgo-app"): vpp accepted both (each got a distinct
     * internal app_index), but it is a footgun the moment a future VPP
     * build tightens name uniqueness — and it obscures logs.
     *
     * Layout: "<caller-supplied>-<pid>", or "vclgo-<pid>" when NULL/empty.
     * The <pid> suffix also makes it trivial to grep VPP's `show app` output
     * for the specific test process that owns a hung session.
     */
    char name_buf[64];
    const char *base = (app_name && *app_name) ? app_name : "vclgo";
    (void)snprintf(name_buf, sizeof name_buf, "%s-%d", base, (int)getpid());
    const char *name = name_buf;

    int rv = vls_app_create((char *)name);
    if (rv != 0) {
        VCLGO_LOG1("vls_app_create(%s) failed: %d", name, rv);
        atomic_store(&vclgo_state, VCLGO_STATE_UNINIT);
        return vclgo_from_vppcom(rv);
    }
    VCLGO_LOG1("vls_app_create(%s) ok", name);

    if (vclgo_poller_start() < 0) {
        vppcom_app_destroy();
        atomic_store(&vclgo_state, VCLGO_STATE_UNINIT);
        return -1;
    }

    /* S1-14: spin up the deep-call offload worker BEFORE flipping to
     * ACTIVE — once the interceptor sees ACTIVE it will start pushing
     * read/write requests. Order matters: teardown reverses it (stop
     * worker before poller so in-flight requests can drain via the
     * poller before its cvars go away). */
    if (vclgo_worker_start() < 0) {
        vclgo_poller_stop();
        vppcom_app_destroy();
        atomic_store(&vclgo_state, VCLGO_STATE_UNINIT);
        return -1;
    }

    atomic_store(&vclgo_state, VCLGO_STATE_ACTIVE);
    atexit(vclgo_teardown);

    /* B-11: install crash-time VPP cleanup. Chains to Go's own signal
     * handlers so the target still dies with its original signal.
     *
     * DISABLED for now: even chaining, `sigaction` before Go bootstraps
     * has been observed to disrupt Go's own signal handler installation.
     * Needs to happen from a Go-side context (e.g. runtime.SetFinalizer
     * on a magic object) or via a Go-visible cleanup hook. */
    (void)install_crash_handlers;

    return 0;
}

void vclgo_teardown(void)
{
    if (atomic_load(&vclgo_state) != VCLGO_STATE_ACTIVE) return;
    atomic_store(&vclgo_state, VCLGO_STATE_UNINIT);

    /* Stop the offload worker first — it may be parked in
     * vclgo_poller_wait, and vclgo_poller_stop cancels waiters, which
     * will wake it. Order matters for a clean shutdown. */
    vclgo_worker_stop();
    vclgo_poller_stop();

    vppcom_app_destroy();
    vclgo_fdmap_destroy();
    VCLGO_LOG1("teardown complete");
}

void vclgo_stats_snapshot(vclgo_stats_t *out)
{
    if (!out) return;
    out->sockets_opened = atomic_load(&vclgo_stat_sockets_opened);
    out->sockets_closed = atomic_load(&vclgo_stat_sockets_closed);
    out->reads          = atomic_load(&vclgo_stat_reads);
    out->writes         = atomic_load(&vclgo_stat_writes);
    out->accepts        = atomic_load(&vclgo_stat_accepts);
    out->connects       = atomic_load(&vclgo_stat_connects);
    out->eagain_parked  = atomic_load(&vclgo_stat_eagain_parked);
    out->poller_wakeups = atomic_load(&vclgo_stat_poller_wakeups);
}
