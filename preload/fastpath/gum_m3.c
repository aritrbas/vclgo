/*
 * gum_m3.c — M3a: route the 36 M2 immediate-NR SYSCALL sites through
 * a C dispatcher instead of doing the SYSCALL directly.
 *
 * At M2 the per-site trampoline was:
 *     mov $NR, %eax
 *     syscall
 *     ret
 * At M3a it becomes:
 *     mov $NR, %eax
 *     jmp <shared shim>
 *
 * where <shared shim> is a single asm routine emitted once per
 * trampoline page. The shim:
 *   1. saves the six SysV syscall-arg registers to the stack;
 *   2. marshals them plus %rax (the NR) into SysV C-arg registers;
 *   3. does an indirect CALL to vclgo_m3_dispatch(nr, a0..a4)
 *      through an absolute-address `movabs` (the .so is loaded far
 *      out of CALL rel32 reach from the trampoline page);
 *   4. leaves the C-call's return value in %rax, restores the stack
 *      frame and returns to Go.
 *
 * For M3a the dispatcher is identity — it just re-executes the
 * syscall via inline asm and returns the kernel result. Semantics
 * unchanged. The point is to validate:
 *   - a C round-trip out of Go's syscall path is safe on this Go
 *     version;
 *   - the register save/restore is correct;
 *   - the stack alignment for the SysV CALL is correct;
 *   - the shim's frame does not confuse Go's runtime (fatal
 *     "unexpected return pc" would fire on the first async
 *     preemption / signal delivery if it did).
 *
 * M3b will extend the dispatcher with an fd-ownership check and
 * dispatch to the vclgo native backend. M3b will ALSO modify the M2.5
 * wrapper trampoline (for Syscall6), which is where all of Go's
 * socket-family calls actually go — M2 sites are runtime-internal
 * (futex, clock_gettime, mmap, epoll_wait), not network. M3a is a
 * mechanism check on the cheaper of the two paths.
 *
 * Left identity-passthrough for M3a (same as gum_full.c):
 *   - M2.5 wrapper trampolines (Syscall6, rawSyscallNoError,
 *     rawVforkSyscall).
 */

#define _GNU_SOURCE

#include "frida-gum.h"

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define VCLGO_M3_MAX_DISTANCE ((gsize)(1u << 30))
#define VCLGO_M3_TRAMP_SIZE   16u  /* per-site slot; JMP-to-shim fits */
#define VCLGO_M3_MAX_SITES    256u

/* Where in the trampoline page the shared shim lives. Kept at the
 * start so per-site trampolines occupy the remainder in a predictable
 * grid. Rounded up so per-site slots stay 16-aligned. */
#define VCLGO_M3_SHIM_OFFSET  0u
#define VCLGO_M3_SHIM_MAXLEN  128u

/* ---------- observability counters ----------
 *
 * The dispatcher bumps these each time it is entered. `total_calls`
 * is the aggregate; `per_syscall` is a sparse array indexed by NR
 * (Linux amd64 numbers fit in ~500). Read by the smoke harness after
 * a workload finishes to check that the dispatcher was entered the
 * expected number of times.
 *
 * Non-atomic: our M2 sites are runtime-internal syscalls (futex,
 * mmap, clock_gettime, epoll_wait) that Go issues from multiple
 * OS threads without holding a lock. A racing increment could lose a
 * count but never crash. If we later care about exact counts we can
 * upgrade to atomic; for M3a "roughly the right number" is enough. */
#define VCLGO_M3_MAX_NR 512u
static uint64_t g_total_calls;
static uint64_t g_per_syscall[VCLGO_M3_MAX_NR];

/* ---------- C dispatcher, called from the asm shim ---------- */

/* Raw syscall — sits in this .so, therefore never patched by any of
 * our preloads (which only touch the main executable). Talks to the
 * kernel directly, bypassing libc's errno translation. Returns
 * kernel convention: negative errno on failure, non-negative on
 * success. */
static inline long
vclgo_m3_raw_syscall5 (long nr, long a0, long a1, long a2, long a3, long a4)
{
    long ret;
    register long r10 __asm__ ("r10") = a3;
    register long r8  __asm__ ("r8")  = a4;
    __asm__ volatile ("syscall"
                      : "=a" (ret)
                      : "0" (nr), "D" (a0), "S" (a1), "d" (a2),
                        "r" (r10), "r" (r8)
                      : "rcx", "r11", "memory");
    return ret;
}

/* Called from the asm shim. Signature must match what the shim
 * marshals: (nr, a0, a1, a2, a3, a4). a5 is not passed — none of the
 * M2 sites in Go binaries need it (Linux syscalls that take 6 args
 * are all called via Syscall6 through the wrapper, and that wrapper
 * is on the M2.5 path, not the M2 path). */
long
vclgo_m3_dispatch (long nr, long a0, long a1, long a2, long a3, long a4)
{
    g_total_calls++;
    if ((unsigned long)nr < VCLGO_M3_MAX_NR)
        g_per_syscall[nr]++;
    return vclgo_m3_raw_syscall5 (nr, a0, a1, a2, a3, a4);
}

/* Debug entry point: LD_PRELOAD user can dlsym this and read
 * counters. Not used in the shim path. */
void
vclgo_m3_stats (uint64_t *total, uint64_t *per_syscall_out, size_t max_nr)
{
    if (total != NULL) *total = g_total_calls;
    if (per_syscall_out != NULL) {
        size_t n = max_nr < VCLGO_M3_MAX_NR ? max_nr : VCLGO_M3_MAX_NR;
        memcpy (per_syscall_out, g_per_syscall, n * sizeof (uint64_t));
    }
}

/* ---------- shim & per-site trampoline emission ----------
 *
 * All bytes are hand-emitted here for auditability and because we
 * want the shim binary to be the SAME sequence every run (assembler
 * versions can emit slightly different bytes for the same asm
 * source, which complicates reproducing failures). If we grow past
 * ~100 bytes it becomes worth switching to gum_x86_writer.
 *
 * Bytes annotated with their meaning: an assembler mnemonic-only
 * comment plus the operand semantics. Prefer to change these
 * together with the byte edits.
 */

/* Emit the shared shim at `dst`. `dispatch_addr` is baked into a
 * `movabs $imm64, %r11` so the shim needs no relocation once
 * emitted. Returns the number of bytes written. */
static size_t
m3_emit_shim (uint8_t *dst, void *dispatch_addr)
{
    size_t o = 0;
    /* push %rbp                                        */
    dst[o++] = 0x55;
    /* mov %rsp, %rbp                                   */
    dst[o++] = 0x48; dst[o++] = 0x89; dst[o++] = 0xE5;
    /* and $-16, %rsp                    align to 16    */
    dst[o++] = 0x48; dst[o++] = 0x83; dst[o++] = 0xE4; dst[o++] = 0xF0;
    /* sub $64, %rsp                     6 slots + pad  */
    dst[o++] = 0x48; dst[o++] = 0x83; dst[o++] = 0xEC; dst[o++] = 0x40;

    /* Save the 6 syscall arg registers to well-known stack slots so
     * we can re-marshal them into SysV C-arg registers regardless of
     * evaluation order. Position matches vclgo_m3_dispatch's arg list. */
    /* mov %rdi, 0(%rsp)   [a0]  */
    dst[o++] = 0x48; dst[o++] = 0x89; dst[o++] = 0x3C; dst[o++] = 0x24;
    /* mov %rsi, 8(%rsp)   [a1]  */
    dst[o++] = 0x48; dst[o++] = 0x89; dst[o++] = 0x74; dst[o++] = 0x24; dst[o++] = 0x08;
    /* mov %rdx, 16(%rsp)  [a2]  */
    dst[o++] = 0x48; dst[o++] = 0x89; dst[o++] = 0x54; dst[o++] = 0x24; dst[o++] = 0x10;
    /* mov %r10, 24(%rsp)  [a3]  */
    dst[o++] = 0x4C; dst[o++] = 0x89; dst[o++] = 0x54; dst[o++] = 0x24; dst[o++] = 0x18;
    /* mov %r8, 32(%rsp)   [a4]  */
    dst[o++] = 0x4C; dst[o++] = 0x89; dst[o++] = 0x44; dst[o++] = 0x24; dst[o++] = 0x20;
    /* mov %r9, 40(%rsp)   [a5, not passed to C but preserved]  */
    dst[o++] = 0x4C; dst[o++] = 0x89; dst[o++] = 0x4C; dst[o++] = 0x24; dst[o++] = 0x28;

    /* Marshal C args: dispatch(nr=%rdi, a0=%rsi, a1=%rdx, a2=%rcx,
     * a3=%r8, a4=%r9). %rax on entry holds NR (set by per-site
     * tramp), so move it into %rdi first before we start clobbering
     * later. */
    /* mov %rax, %rdi                     nr -> C arg0 */
    dst[o++] = 0x48; dst[o++] = 0x89; dst[o++] = 0xC7;
    /* mov 0(%rsp), %rsi                  a0 -> C arg1 */
    dst[o++] = 0x48; dst[o++] = 0x8B; dst[o++] = 0x34; dst[o++] = 0x24;
    /* mov 8(%rsp), %rdx                  a1 -> C arg2 */
    dst[o++] = 0x48; dst[o++] = 0x8B; dst[o++] = 0x54; dst[o++] = 0x24; dst[o++] = 0x08;
    /* mov 16(%rsp), %rcx                 a2 -> C arg3 */
    dst[o++] = 0x48; dst[o++] = 0x8B; dst[o++] = 0x4C; dst[o++] = 0x24; dst[o++] = 0x10;
    /* mov 24(%rsp), %r8                  a3 -> C arg4 */
    dst[o++] = 0x4C; dst[o++] = 0x8B; dst[o++] = 0x44; dst[o++] = 0x24; dst[o++] = 0x18;
    /* mov 32(%rsp), %r9                  a4 -> C arg5 */
    dst[o++] = 0x4C; dst[o++] = 0x8B; dst[o++] = 0x4C; dst[o++] = 0x24; dst[o++] = 0x20;

    /* movabs $dispatch, %r11             load dispatcher absolute   */
    dst[o++] = 0x49; dst[o++] = 0xBB;
    uint64_t da = (uint64_t)(uintptr_t)dispatch_addr;
    memcpy (dst + o, &da, 8); o += 8;
    /* call *%r11                         C ABI, rsp is 16-aligned  */
    dst[o++] = 0x41; dst[o++] = 0xFF; dst[o++] = 0xD3;

    /* %rax holds the kernel-style return. Restore stack. */
    /* mov %rbp, %rsp                                   */
    dst[o++] = 0x48; dst[o++] = 0x89; dst[o++] = 0xEC;
    /* pop %rbp                                         */
    dst[o++] = 0x5D;
    /* ret                                              */
    dst[o++] = 0xC3;

    return o;
}

/* Emit one per-site trampoline into `dst` for syscall number `nr`.
 * Layout is `mov $NR, %eax; jmp shim` = 5 + 5 = 10 bytes, padded
 * with 0xCC guards up to VCLGO_M3_TRAMP_SIZE. */
static void
m3_emit_site_tramp (uint8_t *dst, uint32_t nr, const uint8_t *shim_addr)
{
    memset (dst, 0xCC, VCLGO_M3_TRAMP_SIZE);
    dst[0] = 0xB8;                              /* mov $NR, %eax */
    memcpy (dst + 1, &nr, 4);
    dst[5] = 0xE9;                              /* jmp rel32     */
    int64_t rel = (int64_t)(uintptr_t)shim_addr -
                  ((int64_t)(uintptr_t)(dst + 5) + 5);
    int32_t rel32 = (int32_t)rel;
    memcpy (dst + 6, &rel32, 4);
}

/* ---------- M2 site discovery (same shape as gum_full.c) ---------- */

typedef struct {
    uint8_t *syscall_addr;
    uint32_t nr;
    uint8_t  mov_len;
} vclgo_m3_site_t;

typedef struct {
    const uint8_t   *text_lo;
    const uint8_t   *text_hi;
    gboolean         text_found;
    vclgo_m3_site_t  sites[VCLGO_M3_MAX_SITES];
    size_t           n_sites;
    size_t           n_disasm;
    size_t           n_skipped;
} vclgo_m3_state_t;

typedef struct { const uint8_t *bytes; size_t len; } vclgo_m3_payload_t;

static void
m3_apply_patch (gpointer mem, gpointer user_data)
{
    const vclgo_m3_payload_t *p = user_data;
    memcpy (mem, p->bytes, p->len);
}

static gboolean
on_text_section (const GumSectionDetails *d, gpointer ud)
{
    vclgo_m3_state_t *st = ud;
    if (d->name == NULL || strcmp (d->name, ".text") != 0) return TRUE;
    st->text_lo = (const uint8_t *)(uintptr_t)d->address;
    st->text_hi = st->text_lo + d->size;
    st->text_found = TRUE;
    return FALSE;
}

static void
m3_find_sites (vclgo_m3_state_t *st)
{
    csh handle;
    if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return;
    cs_option (handle, CS_OPT_DETAIL, CS_OPT_OFF);
    cs_insn *insn = cs_malloc (handle);
    const uint8_t *code = st->text_lo;
    size_t code_size = (size_t)(st->text_hi - st->text_lo);
    uint64_t address = (uint64_t)(uintptr_t)st->text_lo;
    while (cs_disasm_iter (handle, &code, &code_size, &address, insn)) {
        if (insn->id != X86_INS_SYSCALL) continue;
        st->n_disasm++;
        const uint8_t *sc = (const uint8_t *)(uintptr_t)insn->address;
        if (sc < st->text_lo + 7) { st->n_skipped++; continue; }
        uint8_t mov_len = 0; uint32_t nr = 0;
        if (sc[-5] == 0xB8) {
            mov_len = 5;
            memcpy (&nr, sc - 4, 4);
        } else if (sc[-7] == 0x48 && sc[-6] == 0xC7 && sc[-5] == 0xC0) {
            mov_len = 7;
            memcpy (&nr, sc - 4, 4);
        } else { st->n_skipped++; continue; }
        if (st->n_sites >= VCLGO_M3_MAX_SITES) { st->n_skipped++; continue; }
        st->sites[st->n_sites++] = (vclgo_m3_site_t){
            .syscall_addr = (uint8_t *)sc, .nr = nr, .mov_len = mov_len
        };
    }
    cs_free (insn, 1);
    cs_close (&handle);
}

/* Rewrite the mov+SYSCALL pair at `s->syscall_addr - s->mov_len` with
 * `CALL rel32 -> per_site_tramp` + NOP padding. Same envelope as M2.  */
static gboolean
m3_patch_site (vclgo_m3_site_t *s, const uint8_t *tramp)
{
    uint8_t *patch_start = s->syscall_addr - s->mov_len;
    size_t   patch_len   = (size_t)s->mov_len + 2u;
    int64_t rel = (int64_t)(uintptr_t)tramp -
                  ((int64_t)(uintptr_t)patch_start + 5);
    if (rel < INT32_MIN || rel > INT32_MAX) return FALSE;
    uint8_t bytes[9] = { 0xE8, 0, 0, 0, 0,
                         0x90, 0x90, 0x90, 0x90 };
    int32_t rel32 = (int32_t)rel;
    memcpy (&bytes[1], &rel32, 4);
    vclgo_m3_payload_t pl = { .bytes = bytes, .len = patch_len };
    return gum_memory_patch_code (patch_start, patch_len, m3_apply_patch, &pl);
}

/* ---------- ctor ---------- */

__attribute__ ((constructor))
static void
vclgo_gum_m3_ctor (void)
{
    fprintf (stderr, "[vclgo/m3] gum_init_embedded()\n");
    gum_init_embedded ();

    GumModule *m = gum_process_get_main_module ();
    if (m == NULL) {
        fprintf (stderr, "[vclgo/m3] no main module — aborting\n");
        return;
    }
    fprintf (stderr, "[vclgo/m3] main module: %s\n", gum_module_get_name (m));

    vclgo_m3_state_t st = { 0 };
    gum_module_enumerate_sections (m, on_text_section, &st);
    if (!st.text_found) {
        fprintf (stderr, "[vclgo/m3] no .text — aborting\n");
        gum_deinit_embedded ();
        return;
    }
    m3_find_sites (&st);
    fprintf (stderr,
             "[vclgo/m3] disasm=%zu patchable=%zu skipped=%zu\n",
             st.n_disasm, st.n_sites, st.n_skipped);
    if (st.n_sites == 0) { gum_deinit_embedded (); return; }

    /* Trampoline page centered on .text so per-site CALL rel32 and
     * shim JMP rel32 both reach without effort. */
    const uint8_t *mid = st.text_lo + (st.text_hi - st.text_lo) / 2;
    GumAddressSpec spec = {
        .near_address = (gpointer)(uintptr_t)mid,
        .max_distance = VCLGO_M3_MAX_DISTANCE,
    };
    gsize page_size = gum_query_page_size ();
    uint8_t *tramp_page = gum_memory_allocate_near (&spec, page_size,
                                                    page_size, GUM_PAGE_RW);
    if (tramp_page == NULL) {
        fprintf (stderr, "[vclgo/m3] page alloc failed\n");
        gum_deinit_embedded ();
        return;
    }
    fprintf (stderr, "[vclgo/m3] page: %p  dispatch: %p\n",
             tramp_page, (void *)&vclgo_m3_dispatch);

    /* Fill with 0xCC guards so any accidental control transfer into
     * unused space raises SIGTRAP instead of running silent garbage. */
    memset (tramp_page, 0xCC, page_size);

    /* Emit the shim at the start of the page. */
    uint8_t *shim = tramp_page + VCLGO_M3_SHIM_OFFSET;
    size_t shim_bytes = m3_emit_shim (shim, (void *)&vclgo_m3_dispatch);
    if (shim_bytes > VCLGO_M3_SHIM_MAXLEN) {
        fprintf (stderr,
                 "[vclgo/m3] shim overflow: %zu > %u — aborting\n",
                 shim_bytes, VCLGO_M3_SHIM_MAXLEN);
        gum_deinit_embedded ();
        return;
    }
    fprintf (stderr, "[vclgo/m3] shim: %p (%zu bytes)\n", shim, shim_bytes);

    /* Emit per-site trampolines after the shim slot. */
    uint8_t *tramp_base = tramp_page + VCLGO_M3_SHIM_MAXLEN;
    for (size_t i = 0; i < st.n_sites; i++)
        m3_emit_site_tramp (tramp_base + i * VCLGO_M3_TRAMP_SIZE,
                            st.sites[i].nr, shim);

    /* Flip to RX and install patches. */
    gum_mprotect (tramp_page, page_size, GUM_PAGE_RX);

    size_t n_patched = 0;
    for (size_t i = 0; i < st.n_sites; i++) {
        const uint8_t *t = tramp_base + i * VCLGO_M3_TRAMP_SIZE;
        if (m3_patch_site (&st.sites[i], t))
            n_patched++;
    }
    fprintf (stderr,
             "[vclgo/m3] patched %zu / %zu sites\n", n_patched, st.n_sites);

    gum_deinit_embedded ();
    fprintf (stderr, "[vclgo/m3] ctor done, handing off\n");
}
