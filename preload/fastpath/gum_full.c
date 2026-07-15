/*
 * gum_full.c — combined M2 (immediate-NR site patcher) and M2.5
 * (generic-wrapper function-entry patcher) preload.
 *
 * The two separate libraries (gum_m2.c, gum_m25.c) exist for isolated
 * milestone testing. They cannot be LD_PRELOAD'd together because
 * gum_init_embedded() is not re-entrant — the second caller crashes
 * on frida-gum's already-initialised GLib state. This file merges
 * them into a single ctor that inits frida-gum once, applies both
 * patch families, and hands off.
 *
 * Correctness gate: an unmodified Go program run under this preload
 * covers ALL 39 SYSCALL sites (36 wide-patched, 3 entry-detoured)
 * and must behave byte-for-byte identically to the same program run
 * without the preload. If that holds, M3 (real VCL dispatch) is
 * unblocked: it needs only to replace the identity-passthrough
 * trampoline bodies emitted here with fd-inspection + dispatch
 * decisions.
 *
 * Nothing in this file is new logic; it is the intersection of
 * gum_m2.c and gum_m25.c with duplicated ctor scaffolding folded
 * together. When M3 is done, gum_m2.c and gum_m25.c can be deleted
 * and this file promoted to the top-level preload directory.
 */

#define _GNU_SOURCE

#include "frida-gum.h"

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ---------- shared tuning constants ---------- */

/* Reach bound for CALL/JMP rel32. Trampoline pages sit within 1 GiB
 * of the target so displacements fit in an int32. */
#define VCLGO_FULL_MAX_DISTANCE ((gsize)(1u << 30))

/* ---------- M2: immediate-NR SYSCALL sites ---------- */

#define VCLGO_M2_TRAMP_SIZE 16u
#define VCLGO_M2_MAX_SITES  256u

typedef struct {
    uint8_t *syscall_addr;
    uint32_t nr;
    uint8_t  mov_len;      /* 5 (b8) or 7 (48 c7 c0) */
} vclgo_m2_site_t;

typedef struct {
    const uint8_t   *text_lo;
    const uint8_t   *text_hi;
    gboolean         text_found;
    vclgo_m2_site_t  sites[VCLGO_M2_MAX_SITES];
    size_t           n_sites;
    size_t           n_disasm_syscalls;
    size_t           n_skipped_no_mov;
    size_t           n_skipped_overflow;
} vclgo_m2_state_t;

typedef struct {
    const uint8_t *bytes;
    size_t         len;
} vclgo_patch_payload_t;

static void
apply_patch_generic (gpointer mem, gpointer user_data)
{
    const vclgo_patch_payload_t *p = user_data;
    memcpy (mem, p->bytes, p->len);
}

static void
m2_record_site (vclgo_m2_state_t *st, const uint8_t *sc)
{
    if (sc < st->text_lo + 7) return;
    uint8_t mov_len = 0;
    uint32_t nr = 0;
    if (sc[-5] == 0xB8) {
        mov_len = 5;
        memcpy (&nr, sc - 4, 4);
    } else if (sc[-7] == 0x48 && sc[-6] == 0xC7 && sc[-5] == 0xC0) {
        mov_len = 7;
        memcpy (&nr, sc - 4, 4);
    } else {
        st->n_skipped_no_mov++;
        return;
    }
    if (st->n_sites >= VCLGO_M2_MAX_SITES) {
        st->n_skipped_overflow++;
        return;
    }
    st->sites[st->n_sites++] = (vclgo_m2_site_t){
        .syscall_addr = (uint8_t *)sc, .nr = nr, .mov_len = mov_len
    };
}

static void
m2_find_sites (vclgo_m2_state_t *st)
{
    csh handle;
    if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return;
    cs_option (handle, CS_OPT_DETAIL, CS_OPT_OFF);
    cs_insn *insn = cs_malloc (handle);
    const uint8_t *code = st->text_lo;
    size_t code_size = (size_t)(st->text_hi - st->text_lo);
    uint64_t address = (uint64_t)(uintptr_t)st->text_lo;
    while (cs_disasm_iter (handle, &code, &code_size, &address, insn)) {
        if (insn->id == X86_INS_SYSCALL) {
            st->n_disasm_syscalls++;
            m2_record_site (st, (const uint8_t *)(uintptr_t)insn->address);
        }
    }
    cs_free (insn, 1);
    cs_close (&handle);
}

static gboolean
on_text_section (const GumSectionDetails *d, gpointer ud)
{
    vclgo_m2_state_t *st = ud;
    if (d->name == NULL || strcmp (d->name, ".text") != 0) return TRUE;
    st->text_lo = (const uint8_t *)(uintptr_t)d->address;
    st->text_hi = st->text_lo + d->size;
    st->text_found = TRUE;
    return FALSE;
}

static void
m2_emit_trampoline (uint8_t *dst, const vclgo_m2_site_t *s)
{
    memset (dst, 0x90, VCLGO_M2_TRAMP_SIZE);
    if (s->mov_len == 5) {
        dst[0] = 0xB8;
        memcpy (dst + 1, &s->nr, 4);
        dst[5] = 0x0F; dst[6] = 0x05; dst[7] = 0xC3;
    } else {
        dst[0] = 0x48; dst[1] = 0xC7; dst[2] = 0xC0;
        memcpy (dst + 3, &s->nr, 4);
        dst[7] = 0x0F; dst[8] = 0x05; dst[9] = 0xC3;
    }
}

static gboolean
m2_patch_one (vclgo_m2_site_t *s, const uint8_t *tramp)
{
    uint8_t *patch_start = s->syscall_addr - s->mov_len;
    size_t   patch_len   = (size_t)s->mov_len + 2u;
    int64_t rel = (int64_t)(uintptr_t)tramp -
                  ((int64_t)(uintptr_t)patch_start + 5);
    if (rel < INT32_MIN || rel > INT32_MAX) return FALSE;
    uint8_t replacement[9] = { 0xE8, 0, 0, 0, 0,
                               0x90, 0x90, 0x90, 0x90 };
    int32_t rel32 = (int32_t)rel;
    memcpy (&replacement[1], &rel32, 4);
    vclgo_patch_payload_t payload = { .bytes = replacement, .len = patch_len };
    return gum_memory_patch_code (patch_start, patch_len,
                                  apply_patch_generic, &payload);
}

/* ---------- M2.5: generic-wrapper function-entry detour ---------- */

#define VCLGO_M25_TRAMP_SIZE 32u

typedef struct {
    const char *symbol;
    uint8_t    *entry;
    uint8_t    *tramp;
    uint8_t     prologue_len;
} vclgo_m25_wrapper_t;

static vclgo_m25_wrapper_t g_m25_wrappers[] = {
    { "internal/runtime/syscall/linux.Syscall6", NULL, NULL, 0 },
    { "syscall.rawSyscallNoError.abi0",          NULL, NULL, 0 },
    { "syscall.rawVforkSyscall.abi0",            NULL, NULL, 0 },
};
#define VCLGO_M25_N_WRAPPERS \
    (sizeof g_m25_wrappers / sizeof g_m25_wrappers[0])

static uint8_t
m25_scan_prologue (const uint8_t *entry, uint8_t min_bytes)
{
    csh handle;
    if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return 0;
    cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insn = cs_malloc (handle);
    const uint8_t *code = entry;
    size_t code_size = 32;
    uint64_t address = (uint64_t)(uintptr_t)entry;
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
        consumed += (uint8_t)insn->size;
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

static void
m25_emit_trampoline (uint8_t *tramp, const vclgo_m25_wrapper_t *w)
{
    memset (tramp, 0xCC, VCLGO_M25_TRAMP_SIZE);
    memcpy (tramp, w->entry, w->prologue_len);
    uint8_t *jmp_at = tramp + w->prologue_len;
    uint8_t *back = w->entry + w->prologue_len;
    int64_t rel = (int64_t)(uintptr_t)back -
                  ((int64_t)(uintptr_t)jmp_at + 5);
    jmp_at[0] = 0xE9;
    int32_t rel32 = (int32_t)rel;
    memcpy (jmp_at + 1, &rel32, 4);
}

static gboolean
m25_patch_entry (const vclgo_m25_wrapper_t *w)
{
    int64_t rel = (int64_t)(uintptr_t)w->tramp -
                  ((int64_t)(uintptr_t)w->entry + 5);
    if (rel < INT32_MIN || rel > INT32_MAX) return FALSE;
    uint8_t bytes[16] = { 0xE9, 0, 0, 0, 0,
                          0x90, 0x90, 0x90, 0x90, 0x90,
                          0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    int32_t rel32 = (int32_t)rel;
    memcpy (&bytes[1], &rel32, 4);
    vclgo_patch_payload_t p = { .bytes = bytes, .len = w->prologue_len };
    return gum_memory_patch_code (w->entry, w->prologue_len,
                                  apply_patch_generic, &p);
}

/* ---------- combined ctor ---------- */

__attribute__ ((constructor))
static void
vclgo_gum_full_ctor (void)
{
    fprintf (stderr, "[vclgo/full] gum_init_embedded()\n");
    gum_init_embedded ();

    GumModule *m = gum_process_get_main_module ();
    if (m == NULL) {
        fprintf (stderr, "[vclgo/full] no main module — aborting\n");
        return;
    }
    fprintf (stderr, "[vclgo/full] main module: %s\n", gum_module_get_name (m));

    /* ----- M2 pass ----- */
    vclgo_m2_state_t m2 = { 0 };
    gum_module_enumerate_sections (m, on_text_section, &m2);
    if (!m2.text_found) {
        fprintf (stderr, "[vclgo/full] no .text section — skipping M2\n");
    } else {
        fprintf (stderr, "[vclgo/full] .text: %p .. %p\n",
                 m2.text_lo, m2.text_hi);
        m2_find_sites (&m2);
        fprintf (stderr,
                 "[vclgo/full] m2: disasm=%zu patchable=%zu no_mov=%zu\n",
                 m2.n_disasm_syscalls, m2.n_sites, m2.n_skipped_no_mov);
    }

    /* ----- M2.5 pass: resolve symbols + prologue lengths ----- */
    size_t n_m25 = 0;
    uintptr_t m25_lo = UINTPTR_MAX, m25_hi = 0;
    for (size_t i = 0; i < VCLGO_M25_N_WRAPPERS; i++) {
        vclgo_m25_wrapper_t *w = &g_m25_wrappers[i];
        GumAddress a = gum_module_find_symbol_by_name (m, w->symbol);
        if (a == 0) continue;
        w->entry = (uint8_t *)(uintptr_t)a;
        w->prologue_len = m25_scan_prologue (w->entry, 5);
        if (w->prologue_len == 0) { w->entry = NULL; continue; }
        if ((uintptr_t)w->entry < m25_lo) m25_lo = (uintptr_t)w->entry;
        if ((uintptr_t)w->entry > m25_hi) m25_hi = (uintptr_t)w->entry;
        n_m25++;
    }
    fprintf (stderr,
             "[vclgo/full] m25: resolved=%zu / %zu wrappers\n",
             n_m25, VCLGO_M25_N_WRAPPERS);

    /* ----- allocate the two trampoline pages ----- */
    gsize page_size = gum_query_page_size ();
    uint8_t *m2_page = NULL, *m25_page = NULL;

    if (m2.n_sites > 0) {
        const uint8_t *mid = m2.text_lo + (m2.text_hi - m2.text_lo) / 2;
        GumAddressSpec spec = {
            .near_address = (gpointer)(uintptr_t)mid,
            .max_distance = VCLGO_FULL_MAX_DISTANCE,
        };
        m2_page = gum_memory_allocate_near (&spec, page_size, page_size,
                                            GUM_PAGE_RW);
        if (m2_page == NULL) {
            fprintf (stderr, "[vclgo/full] m2 page alloc failed\n");
        }
    }
    if (n_m25 > 0) {
        uintptr_t center = m25_lo + (m25_hi - m25_lo) / 2;
        GumAddressSpec spec = {
            .near_address = (gpointer)center,
            .max_distance = VCLGO_FULL_MAX_DISTANCE,
        };
        m25_page = gum_memory_allocate_near (&spec, page_size, page_size,
                                             GUM_PAGE_RW);
        if (m25_page == NULL) {
            fprintf (stderr, "[vclgo/full] m25 page alloc failed\n");
        }
    }

    /* ----- emit trampolines ----- */
    if (m2_page != NULL) {
        for (size_t i = 0; i < m2.n_sites; i++)
            m2_emit_trampoline (m2_page + i * VCLGO_M2_TRAMP_SIZE,
                                &m2.sites[i]);
        gum_mprotect (m2_page, page_size, GUM_PAGE_RX);
    }
    if (m25_page != NULL) {
        size_t slot = 0;
        for (size_t i = 0; i < VCLGO_M25_N_WRAPPERS; i++) {
            vclgo_m25_wrapper_t *w = &g_m25_wrappers[i];
            if (w->entry == NULL) continue;
            w->tramp = m25_page + slot * VCLGO_M25_TRAMP_SIZE;
            m25_emit_trampoline (w->tramp, w);
            slot++;
        }
        gum_mprotect (m25_page, page_size, GUM_PAGE_RX);
    }

    /* ----- install patches ----- */
    size_t n_m2_installed = 0;
    if (m2_page != NULL) {
        for (size_t i = 0; i < m2.n_sites; i++) {
            const uint8_t *t = m2_page + i * VCLGO_M2_TRAMP_SIZE;
            if (m2_patch_one (&m2.sites[i], t))
                n_m2_installed++;
        }
    }
    size_t n_m25_installed = 0;
    if (m25_page != NULL) {
        for (size_t i = 0; i < VCLGO_M25_N_WRAPPERS; i++) {
            vclgo_m25_wrapper_t *w = &g_m25_wrappers[i];
            if (w->entry == NULL) continue;
            if (m25_patch_entry (w))
                n_m25_installed++;
        }
    }
    fprintf (stderr,
             "[vclgo/full] installed: m2=%zu/%zu sites, m25=%zu/%zu wrappers\n",
             n_m2_installed, m2.n_sites, n_m25_installed, n_m25);

    gum_deinit_embedded ();
    fprintf (stderr, "[vclgo/full] ctor done, handing off to target\n");
}
