/*
 * gum_vcl.c — fastpath preload wired to the vclgo dispatcher.
 *
 * This is the M3b+M3c+M3d combined library. It builds on gum_full.c
 * (M2: immediate-NR site patcher + M2.5: function-entry patcher for the
 * 3 generic Go syscall wrappers) and adds the real dispatch machinery:
 *
 *   - New: a Syscall6-specific trampoline that converts Go's internal
 *     ABI (a0..a5 in rbx/rcx/rdi/rsi/r8/r9, NR in rax) into the SysV
 *     syscall ABI (a0..a5 in rdi/rsi/rdx/r10/r8/r9), calls a shared
 *     C dispatcher, and JMPs back into Syscall6's own result-translation
 *     code so the wrapper's Go-ABI return convention (rax=result,
 *     rbx=result2, rcx=errno) is reconstructed for free.
 *
 *   - New: a C dispatcher `vclgo_dispatch` that mirrors the routing
 *     switch of the retired seccomp preload 1:1 — checks
 *     vclgo_owns_fd(a0), routes owned fds to the vclgo_XXX POSIX-shaped
 *     APIs in libvclgo_dispatcher.so, and executes a raw kernel syscall
 *     otherwise. Returns __int128 so the kernel's rdx (result2) survives
 *     the C round-trip on the small set of syscalls that use it (pipe,
 *     fork, etc.).
 *
 *   - New: init/teardown lifecycle. Ctor calls vclgo_init("vclgo-fastpath")
 *     to bootstrap the VCL app + permanent owner-worker pool. If VCL
 *     reports passthrough (VCL_CONFIG unset), patches are still installed
 *     for observability but the dispatcher's owns_fd check always fails
 *     and everything falls through to raw syscall — semantically a no-op
 *     for the app. Dtor calls vclgo_teardown().
 *
 * Everything else — M2 site scan/patch and M2.5 wrapper detour — is
 * copied verbatim from gum_full.c. gum_init_embedded() is called exactly
 * once because it is not re-entrant.
 *
 * The M2 shim from M3a is reused unchanged. It doesn't restore
 * rdi/rsi/rdx/r10/r8/r9 after the C call, which is fine because Go's
 * ABI0 inline SYSCALL wrappers reload their args from the stack before
 * the syscall and never read them again after (verified against
 * runtime.futex.abi0). The shim also naturally preserves whatever the
 * dispatcher put into rdx (as the high 64 bits of an __int128 return),
 * so a shared shim serves both M2 sites and the Syscall6 wrapper.
 *
 * Stack invariant (critical for Go's unwinder):
 * -------------------------------------------------------------
 * From M2 sites the shim is entered via `call rel32 -> tramp` at the
 * SITE, followed by `mov+jmp shim` inside the tramp. The return
 * address on the stack is the site's `NOPs` slot — a valid Go PC.
 *
 * From the Syscall6 wrapper the shim is entered via `push post; jmp
 * shim` inside the tramp. The return address on the stack is `post =
 * Syscall6+14` — also a valid Go PC.
 *
 * Both entry paths guarantee that no return address inside our
 * anonymous trampoline page is ever live on any thread's stack. This
 * matters because when Go delivers SIGURG or SIGPROF (or a nested
 * SIGSEGV from within a VLS/VPP callback), runtime.gentraceback walks
 * up the frame-pointer chain and demands each PC resolve to a known
 * Go function; a PC pointing into our page trips
 * "unexpected return pc" and aborts the process. Long-blocking VLS
 * calls (connect, read, write on a routed socket) make that window
 * wide enough that the crash was reliably reproducible.
 *
 * Not on the fastpath (left identity-passthrough, same as gum_full.c):
 *   - rawSyscallNoError.abi0 (used only for no-error syscalls like
 *     getpid/getuid — not network)
 *   - rawVforkSyscall.abi0 (used only for vfork/exec — not network)
 */

#define _GNU_SOURCE

#include "frida-gum.h"
#include "vclgo.h"

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

/* ============================================================
 * Section 1: shared C dispatcher
 * ============================================================
 */

static _Atomic uint64_t g_disp_total;
static _Atomic uint64_t g_disp_owned;
static _Atomic uint64_t g_disp_raw;
static _Atomic uint64_t g_disp_socket_routed;
static _Atomic uint64_t g_disp_socket_raw;
static _Atomic uint64_t g_disp_exit_group;

/* Snapshot of vclgo_passthrough() taken at ctor time. In passthrough
 * mode the dispatcher is a no-op — we still install patches so the
 * observability counters accumulate, but every dispatch decision
 * decays to a raw kernel syscall.
 *
 * This mirrors the retired seccomp preload, which bailed out of
 * `start_interceptor` when passthrough was true. We're stricter: we
 * intercept, but do not route to vclgo_XXX APIs (which would return
 * -ENOSYS via active_gate).
 */
static gboolean g_passthrough;

/* Raw syscall path. Lives in this .so so it is never patched by our
 * fastpath (which only touches the main executable). Returns kernel
 * convention in `ret_lo` (negative errno on failure, non-negative on
 * success) and the kernel's %rdx side-value (result2) in `ret_hi`.
 * Most syscalls leave %rdx untouched — we still capture it so pipe(2)
 * and friends work if they ever land here. */
static inline void
raw_syscall5 (long nr, long a0, long a1, long a2, long a3, long a4,
              long *ret_lo, long *ret_hi)
{
    long rax;
    long rdx_io = a2;
    register long r10 __asm__ ("r10") = a3;
    register long r8  __asm__ ("r8")  = a4;
    __asm__ volatile ("syscall"
                      : "=a" (rax), "+d" (rdx_io)
                      : "0" (nr), "D" (a0), "S" (a1),
                        "r" (r10), "r" (r8)
                      : "rcx", "r11", "memory");
    *ret_lo = rax;
    *ret_hi = rdx_io;
}

/* Pack (lo, hi) into __int128 so SysV returns it in rax:rdx. */
static inline __int128
pack128 (long lo, long hi)
{
    return ((__int128)(unsigned long)hi << 64) | (unsigned long)lo;
}

/* POSIX-return -> kernel-return convention. vclgo_XXX APIs return -1
 * with libc errno set; the Go wrapper we're returning into expects
 * "negative errno on failure" instead. rdx (result2) is always 0
 * because none of the vclgo_XXX APIs return a second value. */
static inline __int128
posix_to_kernel (long rv)
{
    if (rv >= 0) return pack128 (rv, 0);
    int e = vclgo_errno ();
    if (e == 0) e = EIO;
    return pack128 (-e, 0);
}

/* Route both AF_INET/AF_INET6 SOCK_STREAM (TCP) and SOCK_DGRAM (UDP)
 * through the dispatcher; the dispatcher enforces the equivalent gate
 * in vclgo_socket. Any other combination stays with the kernel. */
static inline int
should_route_socket (int domain, int type, int protocol)
{
    int t = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (domain != AF_INET && domain != AF_INET6)
        return 0;
    if (t == SOCK_STREAM)
        return protocol == 0 || protocol == IPPROTO_TCP;
    if (t == SOCK_DGRAM)
        return protocol == 0 || protocol == IPPROTO_UDP;
    return 0;
}

/* Bounded, no allocation. Matches the retired seccomp preload's
 * dispatch_writev semantics. */
static ssize_t
dispatch_writev (int fd, const struct iovec *iov, int iov_count)
{
    if (iov == NULL || iov_count < 0 || iov_count > IOV_MAX) {
        *vclgo_errno_addr () = EINVAL;
        return -1;
    }
    ssize_t total = 0;
    for (int i = 0; i < iov_count; i++) {
        const uint8_t *data = iov[i].iov_base;
        size_t remaining = iov[i].iov_len;
        while (remaining) {
            size_t req = remaining;
            ssize_t rv = vclgo_write (fd, data, remaining);
            if (rv < 0) return total ? total : -1;
            total += rv;
            data += rv;
            remaining -= (size_t) rv;
            if ((size_t) rv < req) return total;
        }
    }
    return total;
}

/* Bounded, no allocation. Matches the retired seccomp preload's
 * dispatch_readv semantics. */
static ssize_t
dispatch_readv (int fd, const struct iovec *iov, int iov_count)
{
    if (iov == NULL || iov_count < 0 || iov_count > IOV_MAX) {
        *vclgo_errno_addr () = EINVAL;
        return -1;
    }
    ssize_t total = 0;
    for (int i = 0; i < iov_count; i++) {
        if (iov[i].iov_len == 0) continue;
        ssize_t rv = vclgo_read (fd, iov[i].iov_base, iov[i].iov_len);
        if (rv < 0) return total ? total : -1;
        if (rv == 0) return total;
        total += rv;
        if ((size_t) rv < iov[i].iov_len) return total;
    }
    return total;
}

/* THE dispatcher. Called from the asm shim (see section 2). All
 * arguments arrive by SysV C-ABI: rdi=nr, rsi=a0, rdx=a1, rcx=a2,
 * r8=a3, r9=a4. a5 is not passed (see section 2). Returns __int128
 * so the kernel's rdx side-value survives back to Syscall6's result-
 * translation block. */
/* Debug trace switch: `VCLGO_FASTPATH_TRACE=1` prints every dispatch to
 * fd 2. Very loud — only enable when hunting a specific bug. */
static gboolean g_trace;

static void
trace (const char *kind, long nr, long a0, long a1, long rv, long e)
{
    if (!g_trace) return;
    dprintf (2, "[vclgo/gum/T] nr=%ld a0=0x%lx a1=0x%lx %s -> rv=%ld errno=%ld\n",
             nr, (unsigned long) a0, (unsigned long) a1, kind, rv, e);
}

/* Actual dispatcher implementation. Runs on a per-pthread dedicated
 * "big" stack (see vclgo_dispatch below) so we do not overflow Go's
 * tiny goroutine stack when the C path descends into VLS/VPP.
 * Called from the naked asm in vclgo_dispatch, so mark 'used' to
 * suppress an unused-function warning.
 *
 * a5 is plumbed through so we can service the full 6-arg Linux syscall
 * ABI (sendto/recvfrom/sendmsg/recvmsg both need addrlen in a5). */
static __int128 __attribute__ ((sysv_abi, noinline, used))
vclgo_dispatch_impl (long nr, long a0, long a1, long a2, long a3, long a4,
                     long a5)
{
    atomic_fetch_add_explicit (&g_disp_total, 1, memory_order_relaxed);

    /* Special: process shutdown. Same rationale as the retired seccomp
     * preload — the dispatcher-side teardown must complete before we let
     * the kernel run do_exit on this thread, otherwise concurrent VCL
     * owner threads would race against exit_group and vppcom_app_destroy.
     */
    if (nr == __NR_exit_group) {
        atomic_fetch_add_explicit (&g_disp_exit_group, 1,
                                   memory_order_relaxed);
        vclgo_teardown ();
        long lo, hi;
        raw_syscall5 (nr, a0, a1, a2, a3, a4, &lo, &hi);
        /* raw exit_group does not return */
        return pack128 (lo, hi);
    }

    /* Special: socket creation. Only AF_INET/AF_INET6 SOCK_STREAM
     * lands in the VCL dispatcher; everything else is a raw syscall.
     *
     * In passthrough mode we skip the vclgo_socket route entirely
     * because it would return -ENOSYS via active_gate — the kernel
     * has to own this fd if VCL isn't running. */
    if (nr == __NR_socket) {
        int domain   = (int) a0;
        int type     = (int) a1;
        int protocol = (int) a2;
        if (g_passthrough || !should_route_socket (domain, type, protocol)) {
            atomic_fetch_add_explicit (&g_disp_socket_raw, 1,
                                       memory_order_relaxed);
            long lo, hi;
            raw_syscall5 (nr, a0, a1, a2, a3, a4, &lo, &hi);
            return pack128 (lo, hi);
        }
        atomic_fetch_add_explicit (&g_disp_socket_routed, 1,
                                   memory_order_relaxed);
        int rv = vclgo_socket (domain, type, protocol);
        return posix_to_kernel (rv);
    }

    /* For every other fd-first syscall: gate on ownership. Anything
     * not touching a VCL-owned fd goes straight to the kernel. */
    int fd = (int) a0;
    if (!vclgo_owns_fd (fd)) {
        atomic_fetch_add_explicit (&g_disp_raw, 1, memory_order_relaxed);
        long lo, hi;
        raw_syscall5 (nr, a0, a1, a2, a3, a4, &lo, &hi);
        trace ("raw", nr, a0, a1, lo, 0);
        return pack128 (lo, hi);
    }

    atomic_fetch_add_explicit (&g_disp_owned, 1, memory_order_relaxed);
    trace ("owned-enter", nr, a0, a1, 0, 0);

    long rv;
    switch (nr) {
    case __NR_read:
        rv = vclgo_read (fd, (void *) a1, (size_t) a2);
        break;
    case __NR_write:
        rv = vclgo_write (fd, (const void *) a1, (size_t) a2);
        break;
    case __NR_close:
        rv = vclgo_close (fd);
        break;
    case __NR_bind:
        rv = vclgo_bind (fd, (const struct sockaddr *) a1, (socklen_t) a2);
        break;
    case __NR_listen:
        rv = vclgo_listen (fd, (int) a1);
        break;
    case __NR_accept:
        rv = vclgo_accept (fd, (struct sockaddr *) a1, (socklen_t *) a2);
        break;
    case __NR_accept4:
        rv = vclgo_accept4 (fd, (struct sockaddr *) a1, (socklen_t *) a2,
                            (int) a3);
        break;
    case __NR_connect:
        rv = vclgo_connect (fd, (const struct sockaddr *) a1, (socklen_t) a2);
        break;
    case __NR_shutdown:
        rv = vclgo_shutdown (fd, (int) a1);
        break;
    case __NR_getsockname:
        rv = vclgo_getsockname (fd, (struct sockaddr *) a1,
                                (socklen_t *) a2);
        break;
    case __NR_getpeername:
        rv = vclgo_getpeername (fd, (struct sockaddr *) a1,
                                (socklen_t *) a2);
        break;
    case __NR_setsockopt:
        rv = vclgo_setsockopt (fd, (int) a1, (int) a2, (const void *) a3,
                               (socklen_t) a4);
        break;
    case __NR_getsockopt:
        rv = vclgo_getsockopt (fd, (int) a1, (int) a2, (void *) a3,
                               (socklen_t *) a4);
        break;
    case __NR_writev:
        rv = dispatch_writev (fd, (const struct iovec *) a1, (int) a2);
        break;
    case __NR_readv:
        rv = dispatch_readv (fd, (const struct iovec *) a1, (int) a2);
        break;
    case __NR_sendto:
        /* sendto(fd, buf, len, flags, addr, addrlen).
         * For connected sockets (TCP or connected UDP) a4/a5 are
         * NULL/0 and vclgo_sendto degenerates to a plain send. For
         * unconnected UDP we forward the destination address so VLS
         * can route the datagram to the correct peer per-packet. */
        rv = vclgo_sendto (fd, (const void *) a1, (size_t) a2, (int) a3,
                           (const struct sockaddr *) a4, (socklen_t) a5);
        break;
    case __NR_recvfrom:
        /* recvfrom(fd, buf, len, flags, addr, addrlen). For TCP the
         * per-datagram source is meaningless (the caller already knows
         * its peer); for UDP the caller depends on us filling addr
         * with the datagram's sender since it changes per packet. */
        rv = vclgo_recvfrom (fd, (void *) a1, (size_t) a2, (int) a3,
                             (struct sockaddr *) a4, (socklen_t *) a5);
        break;
    case __NR_sendmsg: {
        /* sendmsg(fd, msghdr*, flags). Take the destination address
         * from msg_name (needed for unconnected UDP). Also handle
         * multi-iov as concatenated segments; on TCP that's a plain
         * writev, on UDP most datagrams are single-iov but the same
         * flatten works for the small ones. */
        const struct msghdr *m = (const struct msghdr *) a1;
        if (m == NULL) {
            *vclgo_errno_addr () = EFAULT;
            rv = -1;
        } else if (m->msg_name && m->msg_namelen > 0 &&
                   m->msg_iovlen == 1 && m->msg_iov != NULL) {
            rv = vclgo_sendto (fd, m->msg_iov[0].iov_base,
                               m->msg_iov[0].iov_len, (int) a2,
                               (const struct sockaddr *) m->msg_name,
                               (socklen_t) m->msg_namelen);
        } else {
            rv = dispatch_writev (fd, m->msg_iov, (int) m->msg_iovlen);
        }
        break;
    }
    case __NR_recvmsg: {
        /* recvmsg(fd, msghdr*, flags). For UDP fill msg_name with
         * the sender (per packet). For TCP fall back to concatenated
         * readv, same as before. */
        struct msghdr *m = (struct msghdr *) a1;
        if (m == NULL) {
            *vclgo_errno_addr () = EFAULT;
            rv = -1;
        } else if (m->msg_name && m->msg_namelen > 0 &&
                   m->msg_iovlen == 1 && m->msg_iov != NULL) {
            socklen_t nl = m->msg_namelen;
            rv = vclgo_recvfrom (fd, m->msg_iov[0].iov_base,
                                 m->msg_iov[0].iov_len, (int) a2,
                                 (struct sockaddr *) m->msg_name, &nl);
            if (rv >= 0) {
                m->msg_namelen = nl;
                m->msg_controllen = 0;
                m->msg_flags = 0;
            }
        } else {
            rv = dispatch_readv (fd, m->msg_iov, (int) m->msg_iovlen);
            if (rv >= 0) {
                m->msg_flags = 0;
                m->msg_controllen = 0;
            }
        }
        break;
    }
    case __NR_fcntl: {
        int cmd = (int) a1;
        /* dup-family via fcntl breaks our exact-registry ownership
         * model; refuse the same way the retired seccomp preload did. */
        if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
            *vclgo_errno_addr () = EOPNOTSUPP;
            rv = -1;
        } else {
            /* Other fcntls (F_GETFL, F_SETFL, F_GETFD, ...) already
             * work against the kernel surrogate fd exposed by the
             * dispatcher, so pass them through to the kernel. */
            long lo, hi;
            raw_syscall5 (nr, a0, a1, a2, a3, a4, &lo, &hi);
            return pack128 (lo, hi);
        }
        break;
    }
    case __NR_dup:
    case __NR_dup2:
    case __NR_dup3:
        *vclgo_errno_addr () = EOPNOTSUPP;
        rv = -1;
        break;
    default: {
        /* Any other syscall that happens to touch an owned fd — we do
         * not know how to translate it, so fall back to a raw kernel
         * syscall against the surrogate fd. Same as the retired seccomp
         * preload's default: continued=1 (kernel-passthrough) behavior. */
        long lo, hi;
        raw_syscall5 (nr, a0, a1, a2, a3, a4, &lo, &hi);
        return pack128 (lo, hi);
    }
    }

    /* Trace what we're about to return so we can see rv + errno at exit. */
    trace ("owned-exit", nr, a0, a1, rv, rv < 0 ? vclgo_errno () : 0);
    return posix_to_kernel (rv);
}

/* ============================================================
 * Dispatcher stack switch
 *
 * Go goroutine stacks start at ~2KB and only grow when Go's own
 * function prologues call morestack. Our shim jumps into C code with
 * no such check, so we would silently overflow the goroutine stack the
 * moment the VLS/VPP call graph descended more than a few hundred
 * bytes. Under load we saw the corruption manifest ~150 syscalls
 * later as "traceback did not unwind completely".
 *
 * Fix: before calling vclgo_dispatch_impl, switch %rsp to a
 * per-pthread pre-allocated 512 KiB stack. This is what
 * runtime.cgocall does when Go code calls into C — it hops onto the
 * M's system stack so C's stack frames don't collide with the tiny
 * goroutine stack.
 *
 * The switch is safe because:
 *   - vclgo_dispatch_impl is fully self-contained C code and never
 *     returns to any Go PC directly; it always returns to the shim,
 *     which then returns to Go via the tramp's `ret` (which pops the
 *     Go PC we pushed in Syscall6-tramp).
 *   - We save/restore %rsp inside vclgo_dispatch_stub, so on return
 *     %rsp is back on the goroutine's stack and Go's unwinder is
 *     none the wiser.
 *   - The dispatcher stack is per-pthread (via __thread), so parallel
 *     goroutines can't collide.
 * ============================================================ */

#define VCLGO_DISP_STACK_SIZE (512 * 1024)

/* Per-pthread dispatcher stack top. Read from the fast path with a
 * single %fs:offset load. NULL means "not yet allocated for this
 * thread"; the slow path (disp_stack_alloc) fills it in. */
static __thread void *g_disp_stack_top;

/* Slow-path: allocate a per-thread dispatcher stack and register a
 * pthread destructor that frees it on thread exit.
 *
 * Called on the goroutine's tiny stack the first time this pthread
 * enters vclgo_dispatch. mmap uses very little stack (< 128 bytes) so
 * we survive here. On subsequent entries, disp_stack_top is already
 * cached in TLS and this slow path is skipped. */
static pthread_key_t g_disp_stack_key;
static pthread_once_t g_disp_stack_key_once = PTHREAD_ONCE_INIT;

static void
disp_stack_free (void *base)
{
    if (base) munmap (base, VCLGO_DISP_STACK_SIZE);
}

static void
disp_stack_key_init (void)
{
    (void) pthread_key_create (&g_disp_stack_key, disp_stack_free);
}

static void *
disp_stack_alloc_slow (void)
{
    (void) pthread_once (&g_disp_stack_key_once, disp_stack_key_init);

    void *base = mmap (NULL, VCLGO_DISP_STACK_SIZE,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (base == MAP_FAILED) {
        static const char msg[] =
            "vclgo/gum: FATAL: failed to allocate dispatcher stack\n";
        (void) !write (2, msg, sizeof (msg) - 1);
        _exit (128);
    }

    /* Top-of-stack is base+size; leave a 128-byte cushion for
     * red-zone / alignment. Also align down to 16. */
    uintptr_t top = (uintptr_t) base + VCLGO_DISP_STACK_SIZE - 128;
    top &= ~(uintptr_t) 15;
    g_disp_stack_top = (void *) top;
    (void) pthread_setspecific (g_disp_stack_key, base);
    return g_disp_stack_top;
}

/* C-callable helper: returns per-pthread dispatcher stack top,
 * allocating on first use. Runs on whatever stack we were on when
 * called; the slow path uses < 300 bytes of stack. Called from the
 * naked asm below, so mark 'used' to suppress unused-fn warning. */
static void * __attribute__ ((used))
disp_stack_get (void)
{
    void *top = g_disp_stack_top;
    if (__builtin_expect (top != NULL, 1))
        return top;
    return disp_stack_alloc_slow ();
}

/* Public dispatcher: called from the shim. Naked function so we have
 * exact control over %rsp; we cannot use ordinary C prologue because
 * it would push to the goroutine stack (defeating the whole point of
 * the switch).
 *
 * Signature: (nr, a0..a4) in regs (SysV rdi..r9), a5 on stack at
 * 8(%rsp) on entry (SysV first stack arg). The caller (shim) is
 * responsible for cleaning that stack slot after this call returns
 * (standard SysV caller-cleans-up rule). */
__attribute__ ((naked, sysv_abi, used)) __int128
vclgo_dispatch (long nr, long a0, long a1, long a2, long a3, long a4,
                long a5)
{
    (void) nr; (void) a0; (void) a1; (void) a2; (void) a3; (void) a4;
    (void) a5;
    __asm__ (
        "pushq  %%rbp                       \n\t"
        "movq   %%rsp, %%rbp                \n\t"
        /* On entry: caller pushed a5 as stack arg (SysV arg 7);
         * caller's CALL pushed the return address on top. With our
         * own `push %rbp` we now have layout:
         *   0(%rbp)  = saved rbp
         *   8(%rbp)  = return addr into shim
         *   16(%rbp) = a5 (the syscall's 6th arg)
         * a5 stays live at 16(%rbp) for the entire body — %rbp is
         * saved/restored around every C call below, so we can always
         * reach it. */
        /* Save all six SysV arg regs across the disp_stack_get call.
         * All are caller-saved in SysV so we push them manually. */
        "pushq  %%r9                        \n\t"
        "pushq  %%r8                        \n\t"
        "pushq  %%rcx                       \n\t"
        "pushq  %%rdx                       \n\t"
        "pushq  %%rsi                       \n\t"
        "pushq  %%rdi                       \n\t"
        /* 6 pushes + 1 rbp push = 56 bytes on entry. Stack was
         * 16-aligned before the CALL that landed us here (which
         * pushed the 8-byte return addr), so rsp is currently
         * misaligned by 8. Realign to 16 before the C call. */
        "subq   $8, %%rsp                   \n\t"
        "call   disp_stack_get              \n\t"
        "addq   $8, %%rsp                   \n\t"
        /* %rax now holds new stack top. Save it in %r11 (caller-saved,
         * not used by SysV arg passing). */
        "movq   %%rax, %%r11                \n\t"
        /* Restore SysV C-ABI args. */
        "popq   %%rdi                       \n\t"
        "popq   %%rsi                       \n\t"
        "popq   %%rdx                       \n\t"
        "popq   %%rcx                       \n\t"
        "popq   %%r8                        \n\t"
        "popq   %%r9                        \n\t"
        /* Swap: save current (Go goroutine) rsp on the NEW stack;
         * switch %rsp to the new stack. r10 is caller-saved and not
         * used for arg passing in SysV. */
        "movq   %%rsp, %%r10                \n\t"
        "movq   %%r11, %%rsp                \n\t"
        "pushq  %%r10                       \n\t"
        /* At this point: new stack top has goroutine rsp saved, rsp
         * is 8-mod-16 (16-aligned page - 8 push).
         *
         * We're about to CALL vclgo_dispatch_impl with 7 args (nr,
         * a0..a5). Args 1..6 are in rdi..r9 already; arg 7 (a5)
         * needs to go at 0(%rsp) at CALL time. Push it now (reads
         * from 16(%rbp) — the caller's stack, still reachable
         * because rbp is preserved across the switch).
         *
         * After the push, rsp is 16-aligned. CALL will push 8, so
         * callee sees rsp mis-by-8, which is standard. Good. */
        "pushq  16(%%rbp)                   \n\t"
        /* Call the real dispatcher. Returns __int128 in rax:rdx. */
        "call   vclgo_dispatch_impl         \n\t"
        /* Pop the a5 stack arg. */
        "addq   $8, %%rsp                   \n\t"
        /* Pop the saved goroutine rsp back into %rsp — this
         * atomically flips us back onto the goroutine stack. */
        "popq   %%rsp                       \n\t"
        /* rax:rdx already hold the __int128 return. */
        "popq   %%rbp                       \n\t"
        "ret                                \n\t"
        :
        :
        : "memory"
    );
}

/* Optional observability entry point. Read by tests via dlsym. */
void
vclgo_fastpath_stats (uint64_t *total, uint64_t *owned, uint64_t *raw,
                      uint64_t *sock_routed, uint64_t *sock_raw,
                      uint64_t *exit_group)
{
    if (total)       *total       = atomic_load (&g_disp_total);
    if (owned)       *owned       = atomic_load (&g_disp_owned);
    if (raw)         *raw         = atomic_load (&g_disp_raw);
    if (sock_routed) *sock_routed = atomic_load (&g_disp_socket_routed);
    if (sock_raw)    *sock_raw    = atomic_load (&g_disp_socket_raw);
    if (exit_group)  *exit_group  = atomic_load (&g_disp_exit_group);
}

/* ============================================================
 * Section 2: shared asm shim
 *
 * Called from both:
 *   - M2 per-site trampolines (via `jmp shim`, after `mov $NR, %eax`)
 *   - The Syscall6 wrapper trampoline (via `call shim`, after the
 *     4-mov Go-internal-ABI -> SysV-syscall-ABI conversion)
 *
 * On entry:  rax=NR, rdi/rsi/rdx/r10/r8/r9 = SysV syscall args a0..a5
 * On return: rax = kernel-style result (low 64 of dispatcher's int128)
 *            rdx = kernel-style result2 (high 64 of dispatcher's int128)
 *            All other regs preserved by SysV C ABI.
 *
 * For M2 sites: caller ignores rdx (verified against runtime.futex.abi0).
 * For Syscall6: tramp jumps to entry+14 which uses both rax and rdx.
 * ============================================================
 */

#define VCLGO_MAX_DISTANCE   ((gsize)(1u << 30))
#define VCLGO_PAGE_ALIGN     4096u

/* Shim / trampoline slot budgets, all upper bounds. */
#define VCLGO_SHIM_MAXLEN    128u
#define VCLGO_M2_TRAMP_SIZE  16u   /* mov $NR, %eax; jmp shim   */
#define VCLGO_S6_TRAMP_SIZE  64u   /* 4 movs; call shim; movabs; jmp *r11 */
#define VCLGO_MAX_M2_SITES   256u

/* Emit the shared shim starting at `dst`. Returns bytes written. */
static size_t
emit_shim (uint8_t *dst, void *dispatch_addr)
{
    size_t o = 0;
    /* push %rbp                                        */
    dst[o++] = 0x55;
    /* mov %rsp, %rbp                                   */
    dst[o++] = 0x48; dst[o++] = 0x89; dst[o++] = 0xE5;
    /* and $-16, %rsp                     align to 16   */
    dst[o++] = 0x48; dst[o++] = 0x83; dst[o++] = 0xE4; dst[o++] = 0xF0;
    /* sub $64, %rsp                                    */
    dst[o++] = 0x48; dst[o++] = 0x83; dst[o++] = 0xEC; dst[o++] = 0x40;

    /* Save syscall-arg regs to well-known slots. Positions have to
     * match the load sequence below because we overwrite %rdi/%rsi/%rdx
     * with C args before consuming them all. */
    /* mov %rdi, 0(%rsp)  [a0] */
    dst[o++] = 0x48; dst[o++] = 0x89; dst[o++] = 0x3C; dst[o++] = 0x24;
    /* mov %rsi, 8(%rsp)  [a1] */
    dst[o++] = 0x48; dst[o++] = 0x89; dst[o++] = 0x74; dst[o++] = 0x24; dst[o++] = 0x08;
    /* mov %rdx, 16(%rsp) [a2] */
    dst[o++] = 0x48; dst[o++] = 0x89; dst[o++] = 0x54; dst[o++] = 0x24; dst[o++] = 0x10;
    /* mov %r10, 24(%rsp) [a3] */
    dst[o++] = 0x4C; dst[o++] = 0x89; dst[o++] = 0x54; dst[o++] = 0x24; dst[o++] = 0x18;
    /* mov %r8,  32(%rsp) [a4] */
    dst[o++] = 0x4C; dst[o++] = 0x89; dst[o++] = 0x44; dst[o++] = 0x24; dst[o++] = 0x20;
    /* mov %r9,  40(%rsp) [a5, preserved but not passed to C]   */
    dst[o++] = 0x4C; dst[o++] = 0x89; dst[o++] = 0x4C; dst[o++] = 0x24; dst[o++] = 0x28;

    /* Marshal C ABI args for vclgo_dispatch(nr, a0..a5). NR was in %rax
     * on entry, so move it to %rdi first before we clobber later slots.
     *
     * SysV register mapping:
     *   arg1(nr)  -> rdi   arg4(a2) -> rcx
     *   arg2(a0)  -> rsi   arg5(a3) -> r8
     *   arg3(a1)  -> rdx   arg6(a4) -> r9
     * arg7 (a5) is passed on the stack at 0(%rsp) at CALL time (SysV
     * caller-cleans-up rule). We push it right before the CALL. */
    /* mov %rax, %rdi         nr -> C arg0 */
    dst[o++] = 0x48; dst[o++] = 0x89; dst[o++] = 0xC7;
    /* mov 0(%rsp), %rsi      a0 -> C arg1 */
    dst[o++] = 0x48; dst[o++] = 0x8B; dst[o++] = 0x34; dst[o++] = 0x24;
    /* mov 8(%rsp), %rdx      a1 -> C arg2 */
    dst[o++] = 0x48; dst[o++] = 0x8B; dst[o++] = 0x54; dst[o++] = 0x24; dst[o++] = 0x08;
    /* mov 16(%rsp), %rcx     a2 -> C arg3 */
    dst[o++] = 0x48; dst[o++] = 0x8B; dst[o++] = 0x4C; dst[o++] = 0x24; dst[o++] = 0x10;
    /* mov 24(%rsp), %r8      a3 -> C arg4 */
    dst[o++] = 0x4C; dst[o++] = 0x8B; dst[o++] = 0x44; dst[o++] = 0x24; dst[o++] = 0x18;
    /* mov 32(%rsp), %r9      a4 -> C arg5 */
    dst[o++] = 0x4C; dst[o++] = 0x8B; dst[o++] = 0x4C; dst[o++] = 0x24; dst[o++] = 0x20;

    /* pushq 40(%rsp)         a5 -> C arg6 (on stack). Reads a5 from
     * its spilled slot; the CPU snapshots the source before adjusting
     * rsp, so the offset 40 refers to the pre-push slot. Cost of one
     * push = rsp -= 8, so the following stack-relative offsets shift
     * accordingly. */
    dst[o++] = 0xFF; dst[o++] = 0x74; dst[o++] = 0x24; dst[o++] = 0x28;
    /* Before the push rsp was 16-aligned (we did sub $64). After the
     * push rsp is 8-mod-16. CALL will push 8 more, giving the callee
     * 0-mod-16 which is what SysV wants. */

    /* movabs $dispatch, %r11  (this .so is loaded far from .text) */
    dst[o++] = 0x49; dst[o++] = 0xBB;
    uint64_t da = (uint64_t) (uintptr_t) dispatch_addr;
    memcpy (dst + o, &da, 8); o += 8;
    /* call *%r11 */
    dst[o++] = 0x41; dst[o++] = 0xFF; dst[o++] = 0xD3;

    /* Pop the a5 stack arg (SysV caller-cleans-up). */
    /* add $8, %rsp */
    dst[o++] = 0x48; dst[o++] = 0x83; dst[o++] = 0xC4; dst[o++] = 0x08;

    /* rax:rdx now hold the __int128 return. Restore frame and go home. */
    /* mov %rbp, %rsp */
    dst[o++] = 0x48; dst[o++] = 0x89; dst[o++] = 0xEC;
    /* pop %rbp */
    dst[o++] = 0x5D;
    /* ret */
    dst[o++] = 0xC3;

    return o;
}

/* ============================================================
 * Section 3: M2 site discovery + patching
 *
 * Straight copy of gum_full.c's M2 half. Finds every
 *   `mov $NR, %eax|rax; SYSCALL` site inside the main executable's
 * .text and rewrites it as
 *   `CALL rel32 -> per_site_tramp; NOPs`.
 *
 * The per-site trampoline is now `mov $NR, %eax; jmp shared_shim`
 * (10 bytes; padded to 16 for alignment).
 * ============================================================
 */

typedef struct {
    uint8_t *syscall_addr;   /* points at the SYSCALL byte 0x0F           */
    uint32_t nr;
    uint8_t  mov_len;        /* bytes of the preceding `mov` (5 or 7)     */
} m2_site_t;

typedef struct {
    const uint8_t *text_lo;
    const uint8_t *text_hi;
    gboolean       text_found;
    m2_site_t      sites[VCLGO_MAX_M2_SITES];
    size_t         n_sites;
    size_t         n_disasm;
    size_t         n_skipped;
} m2_state_t;

typedef struct { const uint8_t *bytes; size_t len; } patch_payload_t;

static void
apply_patch (gpointer mem, gpointer user_data)
{
    const patch_payload_t *p = user_data;
    memcpy (mem, p->bytes, p->len);
}

static gboolean
on_text_section (const GumSectionDetails *d, gpointer ud)
{
    m2_state_t *st = ud;
    if (d->name == NULL || strcmp (d->name, ".text") != 0) return TRUE;
    st->text_lo = (const uint8_t *) (uintptr_t) d->address;
    st->text_hi = st->text_lo + d->size;
    st->text_found = TRUE;
    return FALSE;
}

static void
find_m2_sites (m2_state_t *st)
{
    csh handle;
    if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return;
    cs_option (handle, CS_OPT_DETAIL, CS_OPT_OFF);
    cs_insn *insn = cs_malloc (handle);
    const uint8_t *code = st->text_lo;
    size_t code_size = (size_t) (st->text_hi - st->text_lo);
    uint64_t address = (uint64_t) (uintptr_t) st->text_lo;
    while (cs_disasm_iter (handle, &code, &code_size, &address, insn)) {
        if (insn->id != X86_INS_SYSCALL) continue;
        st->n_disasm++;
        const uint8_t *sc = (const uint8_t *) (uintptr_t) insn->address;
        if (sc < st->text_lo + 7) { st->n_skipped++; continue; }
        uint8_t mov_len = 0;
        uint32_t nr = 0;
        if (sc[-5] == 0xB8) {                           /* mov $NR, %eax */
            mov_len = 5;
            memcpy (&nr, sc - 4, 4);
        } else if (sc[-7] == 0x48 && sc[-6] == 0xC7 &&
                   sc[-5] == 0xC0) {                    /* mov $NR, %rax */
            mov_len = 7;
            memcpy (&nr, sc - 4, 4);
        } else {
            st->n_skipped++; continue;
        }
        if (st->n_sites >= VCLGO_MAX_M2_SITES) { st->n_skipped++; continue; }
        st->sites[st->n_sites++] = (m2_site_t){
            .syscall_addr = (uint8_t *) sc, .nr = nr, .mov_len = mov_len
        };
    }
    cs_free (insn, 1);
    cs_close (&handle);
}

static void
emit_m2_site_tramp (uint8_t *dst, uint32_t nr, const uint8_t *shim_addr)
{
    memset (dst, 0xCC, VCLGO_M2_TRAMP_SIZE);
    dst[0] = 0xB8;                             /* mov $NR, %eax */
    memcpy (dst + 1, &nr, 4);
    dst[5] = 0xE9;                             /* jmp rel32     */
    int64_t rel = (int64_t) (uintptr_t) shim_addr -
                  ((int64_t) (uintptr_t) (dst + 5) + 5);
    int32_t rel32 = (int32_t) rel;
    memcpy (dst + 6, &rel32, 4);
}

static gboolean
patch_m2_site (m2_site_t *s, const uint8_t *tramp)
{
    uint8_t *start = s->syscall_addr - s->mov_len;
    size_t   len   = (size_t) s->mov_len + 2u;
    int64_t rel = (int64_t) (uintptr_t) tramp -
                  ((int64_t) (uintptr_t) start + 5);
    if (rel < INT32_MIN || rel > INT32_MAX) return FALSE;
    uint8_t bytes[9] = { 0xE8, 0, 0, 0, 0,
                         0x90, 0x90, 0x90, 0x90 };
    int32_t rel32 = (int32_t) rel;
    memcpy (&bytes[1], &rel32, 4);
    patch_payload_t pl = { .bytes = bytes, .len = len };
    return gum_memory_patch_code (start, len, apply_patch, &pl);
}

/* ============================================================
 * Section 4: M2.5 wrapper detour (identity for 2 of 3, dispatch for Syscall6)
 *
 * `Syscall6` gets the dispatch path (NEW for M3b).
 * `rawSyscallNoError` and `rawVforkSyscall` stay identity-passthrough
 * because they aren't on the network path.
 * ============================================================
 */

typedef struct {
    const char *symbol;
    uint8_t    *entry;
    uint8_t    *tramp;
    uint8_t     prologue_len;   /* bytes of prologue relocated (>= 5)   */
    uint8_t     syscall_off;    /* offset from entry to SYSCALL byte    */
    gboolean    is_syscall6;    /* dispatch (true) or identity (false)  */
} wrapper_t;

static wrapper_t g_wrappers[] = {
    { "internal/runtime/syscall/linux.Syscall6", NULL, NULL, 0, 0, TRUE  },
    { "syscall.rawSyscallNoError.abi0",          NULL, NULL, 0, 0, FALSE },
    { "syscall.rawVforkSyscall.abi0",            NULL, NULL, 0, 0, FALSE },
};
#define VCLGO_N_WRAPPERS (sizeof g_wrappers / sizeof g_wrappers[0])

/* Walk `entry` counting complete instructions until we've consumed at
 * least `min_bytes` and all consumed instructions are relocatable
 * (no relative branches, no RIP-relative memory operands). Returns
 * the number of bytes consumed, or 0 on unsafe / not-enough-bytes. */
static uint8_t
scan_prologue (const uint8_t *entry, uint8_t min_bytes)
{
    csh handle;
    if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return 0;
    cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insn = cs_malloc (handle);
    const uint8_t *code = entry;
    size_t code_size = 32;
    uint64_t address = (uint64_t) (uintptr_t) entry;
    uint8_t consumed = 0;
    while (consumed < min_bytes) {
        if (!cs_disasm_iter (handle, &code, &code_size, &address, insn))
            goto unsafe;
        for (int g = 0; g < insn->detail->groups_count; g++) {
            uint8_t grp = insn->detail->groups[g];
            if (grp == CS_GRP_JUMP || grp == CS_GRP_CALL ||
                grp == CS_GRP_RET || grp == CS_GRP_INT ||
                grp == CS_GRP_IRET || grp == CS_GRP_BRANCH_RELATIVE)
                goto unsafe;
        }
        for (uint8_t o = 0; o < insn->detail->x86.op_count; o++) {
            const cs_x86_op *op = &insn->detail->x86.operands[o];
            if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP)
                goto unsafe;
        }
        consumed += (uint8_t) insn->size;
        if (consumed > 15) goto unsafe;
    }
    cs_free (insn, 1);
    cs_close (&handle);
    return consumed;
unsafe:
    cs_free (insn, 1);
    cs_close (&handle);
    return 0;
}

/* Find the SYSCALL offset inside `entry`. Used only for Syscall6, to
 * compute the "post-SYSCALL" jump-back target. Returns 0 if not found
 * within `max_scan` bytes. */
static uint8_t
scan_syscall_offset (const uint8_t *entry, size_t max_scan)
{
    csh handle;
    if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return 0;
    cs_option (handle, CS_OPT_DETAIL, CS_OPT_OFF);
    cs_insn *insn = cs_malloc (handle);
    const uint8_t *code = entry;
    size_t code_size = max_scan;
    uint64_t address = (uint64_t) (uintptr_t) entry;
    uint8_t off = 0;
    while (cs_disasm_iter (handle, &code, &code_size, &address, insn)) {
        if (insn->id == X86_INS_SYSCALL) {
            off = (uint8_t) ((uintptr_t) insn->address -
                             (uintptr_t) entry + insn->size);
            break;
        }
    }
    cs_free (insn, 1);
    cs_close (&handle);
    return off;
}

/* Trampoline for identity wrappers (rawSyscallNoError, rawVforkSyscall):
 *   [copied prologue] + JMP rel32 to (entry + prologue_len)
 * Byte-for-byte semantic no-op. Same as gum_full.c / M2.5. */
static void
emit_identity_wrapper_tramp (uint8_t *tramp, const wrapper_t *w)
{
    memset (tramp, 0xCC, VCLGO_S6_TRAMP_SIZE);
    memcpy (tramp, w->entry, w->prologue_len);
    uint8_t *jmp_at = tramp + w->prologue_len;
    uint8_t *back = w->entry + w->prologue_len;
    int64_t rel = (int64_t) (uintptr_t) back -
                  ((int64_t) (uintptr_t) jmp_at + 5);
    jmp_at[0] = 0xE9;
    int32_t rel32 = (int32_t) rel;
    memcpy (jmp_at + 1, &rel32, 4);
}

/* Trampoline for Syscall6 (M3b).
 *
 * Layout:
 *
 *   mov %rsi, %r10       3    ; Go-internal a3 -> SysV syscall a3
 *   mov %rdi, %rdx       3    ; Go-internal a2 -> SysV syscall a2
 *   mov %rcx, %rsi       3    ; Go-internal a1 -> SysV syscall a1
 *   mov %rbx, %rdi       3    ; Go-internal a0 -> SysV syscall a0
 *   ; now: rax=NR, rdi/rsi/rdx/r10/r8/r9 = SysV syscall args
 *   movabs $post, %r11  10    ; post = entry + syscall_off
 *   push  %r11           2    ; masquerade `post` as our "return address"
 *   jmp   shim           5    ; NOT a call — dispatch will `ret` to post
 *                       = 29 bytes
 *
 * IMPORTANT: this deliberately uses `push+jmp` instead of `call shim;
 * jmp post`. A `call shim` would leave the address of `jmp post` (a PC
 * inside our tramp allocation) on the stack for the whole time the C
 * dispatcher runs. If Go's runtime walks that stack during signal
 * delivery — SIGURG preemption, SIGPROF profiling, or a nested SIGSEGV
 * from within a VLS/VPP callback — it does not know how to decode a PC
 * inside our anonymous mapping and aborts with "unexpected return pc",
 * exactly like it did with Frida's `Interceptor.attach`. Long-blocking
 * VLS-owned syscalls (connect, read, write on a routed socket) make
 * that window arbitrarily wide, so the crash was reliably reproducible.
 *
 * With push+jmp, every return address on the stack while the C dispatch
 * runs is a valid Go PC:
 *
 *   [rsp+0]   = post (= Syscall6+14, in the Go .text)
 *   [rsp+8]   = ret-to-caller (whoever called Syscall6, in the Go .text)
 *
 * Shim's own `ret` at the end pops `post`, jumping directly into
 * Syscall6+14's result-translation code (cmp/neg/mov/ret), which then
 * `ret`s back to the caller. The tramp never appears on the stack.
 *
 * Reuses Syscall6's own post-SYSCALL result-translation code (12+ bytes
 * of cmp/neg/mov + ret) so we do not have to re-implement the Go
 * internal-ABI return convention (rax=result, rbx=result2, rcx=errno).
 */
static void
emit_syscall6_tramp (uint8_t *tramp, const wrapper_t *w,
                     const uint8_t *shim_addr)
{
    memset (tramp, 0xCC, VCLGO_S6_TRAMP_SIZE);
    size_t o = 0;
    /* mov %rsi, %r10 */
    tramp[o++] = 0x49; tramp[o++] = 0x89; tramp[o++] = 0xF2;
    /* mov %rdi, %rdx */
    tramp[o++] = 0x48; tramp[o++] = 0x89; tramp[o++] = 0xFA;
    /* mov %rcx, %rsi */
    tramp[o++] = 0x48; tramp[o++] = 0x89; tramp[o++] = 0xCE;
    /* mov %rbx, %rdi */
    tramp[o++] = 0x48; tramp[o++] = 0x89; tramp[o++] = 0xDF;
    /* movabs $post, %r11 */
    tramp[o++] = 0x49; tramp[o++] = 0xBB;
    uint64_t post = (uint64_t) (uintptr_t) (w->entry + w->syscall_off);
    memcpy (tramp + o, &post, 8); o += 8;
    /* push %r11  (fake return address = post) */
    tramp[o++] = 0x41; tramp[o++] = 0x53;
    /* jmp rel32 shim  (NOT call — shim's ret will pop post) */
    tramp[o++] = 0xE9;
    int64_t rel = (int64_t) (uintptr_t) shim_addr -
                  ((int64_t) (uintptr_t) (tramp + o - 1) + 5);
    int32_t rel32 = (int32_t) rel;
    memcpy (tramp + o, &rel32, 4); o += 4;
}

static gboolean
patch_wrapper_entry (const wrapper_t *w)
{
    int64_t rel = (int64_t) (uintptr_t) w->tramp -
                  ((int64_t) (uintptr_t) w->entry + 5);
    if (rel < INT32_MIN || rel > INT32_MAX) return FALSE;
    /* JMP rel32 + NOPs padding out to prologue_len so the bytes AFTER
     * our patch are unchanged. */
    uint8_t bytes[16] = { 0xE9, 0, 0, 0, 0,
                          0x90, 0x90, 0x90, 0x90, 0x90,
                          0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    int32_t rel32 = (int32_t) rel;
    memcpy (&bytes[1], &rel32, 4);
    patch_payload_t pl = { .bytes = bytes, .len = w->prologue_len };
    return gum_memory_patch_code (w->entry, w->prologue_len,
                                  apply_patch, &pl);
}

/* ============================================================
 * Section 5: ctor / dtor
 * ============================================================
 */

static gboolean g_did_patch = FALSE;

__attribute__ ((constructor))
static void
vclgo_gum_ctor (void)
{
    /* Escape hatch for debugging. (Was also honored by the retired
     * seccomp preload.) */
    if (getenv ("VCLGO_DISABLE"))
        return;

    /* G-D2: DISCOVER FIRST, INITIALIZE ONLY IF WE'LL PATCH.
     *
     * The dispatcher's vclgo_init() registers this process as a VCL
     * application with VPP and spins up an owner-worker pthread pool.
     * That registration is heavyweight and observable inside VPP.
     *
     * Any process that inherits our LD_PRELOAD will run this ctor once —
     * including non-Go processes and Go-adjacent helpers like `timeout`,
     * `sudo`, `bash`, `ldd`, etc. Doing vclgo_init() unconditionally
     * would (a) leak a VPP application slot every time the shell forks,
     * (b) burn 4-8 owner pthreads per invocation, and (c) cause the
     * subprocess collision that made an earlier `timeout $CLIENT` wrap
     * segfault (the wrapper registered a session, then `execve`'d the
     * client, which tried to register another one on top of it).
     *
     * The correct sequence is:
     *   1. gum_init_embedded() — cheap, in-process.
     *   2. Enumerate `.text` and look for Go-shaped SYSCALL sites +
     *      the three generic Go syscall wrappers.
     *   3. If we found nothing, this is not a Go binary — deinit gum
     *      and return WITHOUT touching VPP.
     *   4. Only then vclgo_init() and patch.
     */
    gum_init_embedded ();

    GumModule *m = gum_process_get_main_module ();
    if (m == NULL) {
        fprintf (stderr, "[vclgo/gum] no main module — aborting patch\n");
        gum_deinit_embedded ();
        return;
    }
    fprintf (stderr, "[vclgo/gum] main module: %s\n", gum_module_get_name (m));

    /* --- M2 site discovery --- */
    m2_state_t st = { 0 };
    gum_module_enumerate_sections (m, on_text_section, &st);
    if (!st.text_found) {
        fprintf (stderr, "[vclgo/gum] no .text — aborting patch\n");
        gum_deinit_embedded ();
        return;
    }
    find_m2_sites (&st);
    fprintf (stderr,
             "[vclgo/gum] M2: disasm=%zu patchable=%zu skipped=%zu\n",
             st.n_disasm, st.n_sites, st.n_skipped);

    /* --- Wrapper discovery --- */
    size_t n_wrappers_resolved = 0;
    for (size_t i = 0; i < VCLGO_N_WRAPPERS; i++) {
        wrapper_t *w = &g_wrappers[i];
        GumAddress addr = gum_module_find_symbol_by_name (m, w->symbol);
        if (addr == 0) {
            fprintf (stderr,
                     "[vclgo/gum]   wrapper not found: %s\n", w->symbol);
            continue;
        }
        w->entry = (uint8_t *) (uintptr_t) addr;
        w->prologue_len = scan_prologue (w->entry, 5);
        if (w->prologue_len == 0) {
            fprintf (stderr,
                     "[vclgo/gum]   unsafe prologue for %s\n", w->symbol);
            w->entry = NULL;
            continue;
        }
        if (w->is_syscall6) {
            w->syscall_off = scan_syscall_offset (w->entry, 64);
            if (w->syscall_off == 0) {
                fprintf (stderr,
                         "[vclgo/gum]   no SYSCALL in %s within 64 bytes\n",
                         w->symbol);
                w->entry = NULL;
                continue;
            }
        }
        fprintf (stderr,
                 "[vclgo/gum]   %s @ 0x%" PRIxPTR
                 "  prologue=%u  syscall_off=%u  dispatch=%d\n",
                 w->symbol, (uintptr_t) w->entry,
                 w->prologue_len, w->syscall_off, w->is_syscall6);
        n_wrappers_resolved++;
    }

    if (st.n_sites == 0 && n_wrappers_resolved == 0) {
        fprintf (stderr,
                 "[vclgo/gum] nothing to patch — non-Go binary, "
                 "skipping vclgo_init (no VPP registration)\n");
        gum_deinit_embedded ();
        return;
    }

    /* --- Confirmed Go binary: bring up VCL + owner-worker pool. Safe if
     * VCL_CONFIG is unset — dispatcher enters kernel-passthrough mode and
     * vclgo_owns_fd always returns 0, so every dispatch decays to a raw
     * syscall. --- */
    if (vclgo_init ("vclgo-fastpath") != 0) {
        int e = errno;
        fprintf (stderr,
                 "[vclgo/gum] vclgo_init failed: %s — leaving app native\n",
                 strerror (e));
        gum_deinit_embedded ();
        return;
    }
    g_passthrough = vclgo_passthrough () ? TRUE : FALSE;
    g_trace = (getenv ("VCLGO_FASTPATH_TRACE") != NULL);
    fprintf (stderr,
             "[vclgo/gum] vclgo_init ok (workers=%d, passthrough=%d, trace=%d)\n",
             vclgo_worker_count (), (int) g_passthrough, (int) g_trace);

    /* --- Trampoline page: one page reachable from every patched site --- */
    const uint8_t *mid = st.text_lo + (st.text_hi - st.text_lo) / 2;
    GumAddressSpec spec = {
        .near_address = (gpointer) (uintptr_t) mid,
        .max_distance = VCLGO_MAX_DISTANCE,
    };
    gsize page_size = gum_query_page_size ();
    /* One page is easily enough:
     *   shim (~90B, budget 128B) + N_M2*16B + N_WRAPPERS*64B.
     * With MAX_M2_SITES=256 that's 128 + 256*16 + 3*64 = 4416 bytes,
     * i.e. slightly more than one 4K page. Double it to be safe. */
    gsize alloc_size = 2 * page_size;
    uint8_t *page = gum_memory_allocate_near (&spec, alloc_size, page_size,
                                              GUM_PAGE_RW);
    if (page == NULL) {
        fprintf (stderr, "[vclgo/gum] page allocation failed\n");
        gum_deinit_embedded ();
        return;
    }
    memset (page, 0xCC, alloc_size);
    fprintf (stderr,
             "[vclgo/gum] page: %p (%zu bytes)  dispatch: %p  shim.max: %uB\n",
             page, (size_t) alloc_size, (void *) &vclgo_dispatch,
             VCLGO_SHIM_MAXLEN);

    /* Layout inside the page:
     *   [0 .. VCLGO_SHIM_MAXLEN)                  shared shim
     *   [VCLGO_SHIM_MAXLEN .. +N_M2*16)           M2 per-site trampolines
     *   [after that ..)                            wrapper trampolines
     */
    uint8_t *shim = page;
    size_t shim_bytes = emit_shim (shim, (void *) &vclgo_dispatch);
    if (shim_bytes > VCLGO_SHIM_MAXLEN) {
        fprintf (stderr,
                 "[vclgo/gum] shim overflow: %zu > %u — aborting\n",
                 shim_bytes, VCLGO_SHIM_MAXLEN);
        gum_deinit_embedded ();
        return;
    }
    fprintf (stderr, "[vclgo/gum] shim: %p  (%zu bytes)\n", shim, shim_bytes);

    uint8_t *m2_tramps = page + VCLGO_SHIM_MAXLEN;
    for (size_t i = 0; i < st.n_sites; i++)
        emit_m2_site_tramp (m2_tramps + i * VCLGO_M2_TRAMP_SIZE,
                            st.sites[i].nr, shim);

    uint8_t *w_tramps = m2_tramps + st.n_sites * VCLGO_M2_TRAMP_SIZE;
    size_t w_slot = 0;
    for (size_t i = 0; i < VCLGO_N_WRAPPERS; i++) {
        wrapper_t *w = &g_wrappers[i];
        if (w->entry == NULL) continue;
        w->tramp = w_tramps + w_slot * VCLGO_S6_TRAMP_SIZE;
        if (w->is_syscall6)
            emit_syscall6_tramp (w->tramp, w, shim);
        else
            emit_identity_wrapper_tramp (w->tramp, w);
        w_slot++;
    }
    /* One-shot verification dump of Syscall6 tramp bytes so we can eyeball
     * the actual emitted code once at ctor time. Useful when investigating
     * ABI/stack invariants; safe to keep even in release since it fires
     * exactly once at process start. */
    for (size_t i = 0; i < VCLGO_N_WRAPPERS; i++) {
        wrapper_t *w = &g_wrappers[i];
        if (w->entry == NULL || !w->is_syscall6) continue;
        fprintf (stderr, "[vclgo/gum]   S6 tramp @ %p:", w->tramp);
        for (size_t k = 0; k < 32; k++)
            fprintf (stderr, " %02x", w->tramp[k]);
        fprintf (stderr, "\n");
    }
    gum_mprotect (page, alloc_size, GUM_PAGE_RX);

    /* --- Install patches --- */
    size_t n_m2_patched = 0;
    for (size_t i = 0; i < st.n_sites; i++) {
        const uint8_t *t = m2_tramps + i * VCLGO_M2_TRAMP_SIZE;
        if (patch_m2_site (&st.sites[i], t))
            n_m2_patched++;
    }
    size_t n_w_patched = 0;
    for (size_t i = 0; i < VCLGO_N_WRAPPERS; i++) {
        wrapper_t *w = &g_wrappers[i];
        if (w->entry == NULL) continue;
        if (patch_wrapper_entry (w))
            n_w_patched++;
    }
    fprintf (stderr,
             "[vclgo/gum] patched M2:%zu/%zu  wrappers:%zu/%zu\n",
             n_m2_patched, st.n_sites,
             n_w_patched, n_wrappers_resolved);

    g_did_patch = TRUE;
    gum_deinit_embedded ();
    fprintf (stderr, "[vclgo/gum] ctor done, handing off\n");
}

__attribute__ ((destructor))
static void
vclgo_gum_dtor (void)
{
    if (!g_did_patch) return;
    /* Same ordering rationale as the retired seccomp preload: teardown
     * VCL after all dispatch traffic has quiesced. The exit_group
     * interception in vclgo_dispatch already covers the normal exit
     * path; this dtor is a belt-and-braces net for abnormal exits
     * (dlclose, atexit ordering issues, etc.). */
    vclgo_teardown ();
}
