/*
 * gum_m2.c — M2: identity-passthrough SYSCALL patcher.
 *
 * Rewrites every Go SYSCALL site whose preceding instruction is
 *   mov $NR, %eax    (5 bytes: B8 XX XX XX XX)          or
 *   mov $NR, %rax    (7 bytes: 48 C7 C0 XX XX XX XX)
 * with a CALL rel32 into a per-site trampoline that replays the same
 * syscall unchanged. Semantics of the target process are unchanged: a
 * Go program run under this preload should behave byte-for-byte
 * identically to the same program run without it. This is the
 * correctness gate; if M2 breaks anything, M3 (real VCL dispatch) is
 * not attempted.
 *
 * Deliberately NOT handled here (deferred to M2.5):
 *   - The three generic wrappers (Syscall6, rawSyscallNoError,
 *     rawVforkSyscall) whose SYSCALL slots have no preceding
 *     immediate-NR mov and are therefore only 2 bytes wide, too small
 *     to hold a CALL rel32. Those require function-entry patching
 *     (jump the wrapper's first instruction) rather than site-level
 *     patching. Because M2's semantics is "replay unchanged", not
 *     patching those three sites is functionally equivalent to
 *     patching them; we skip them to keep the M2 mechanism minimal
 *     and testable in isolation.
 *
 * Not handled at any milestone:
 *   - Any module other than the main executable. libc, ld, libm and
 *     our own library have SYSCALL sites too (libc alone has ~565),
 *     but we never want to intercept those; libc functions used by
 *     the target (e.g. dlsym at startup) must continue to talk to
 *     the real kernel. Symbol interposition is the right mechanism
 *     for libc-mediated network calls, and it does not need to
 *     rewrite bytes.
 *
 * On failure, we log and hand control to the target program with no
 * patches applied. It is by design that failure to patch is
 * transparent (the target still works), unlike failure during
 * patching (which could leave .text in an inconsistent state).
 */

#define _GNU_SOURCE

#include "frida-gum.h"

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

/* Per-site trampoline. Padded to 16 bytes so a page fits 256 sites
 * regardless of whether the site's original mov was 5 or 7 bytes. Real
 * Go binaries hit 30-40 patchable sites so this is comfortably
 * over-provisioned; if a binary ever needs more, allocate multiple
 * pages. */
#define VCLGO_TRAMP_SIZE 16u

/* Cap the number of patchable sites we will collect. Reserved
 * generously: 4 KiB page / 16-byte trampoline = 256. */
#define VCLGO_MAX_SITES 256u

/* Reach constraint for CALL rel32: signed 32-bit displacement. We
 * allocate the trampoline page within 1 GiB of .text to be safely
 * inside that window. */
#define VCLGO_TRAMP_MAX_DISTANCE ((gsize)(1u << 30))

typedef struct {
    uint8_t *syscall_addr; /* address of the 0F 05 opcode */
    uint32_t nr;           /* syscall number extracted from preceding mov */
    uint8_t  mov_len;      /* 5 or 7 (length of preceding mov instruction) */
} vclgo_m2_site_t;

typedef struct {
    /* Byte range of the main executable's .text. Used both to bound
     * the disassembly walk and (later) to reject candidate SYSCALL
     * bytes whose addresses fall outside the section. */
    const uint8_t *text_lo;
    const uint8_t *text_hi;
    gboolean       text_found;

    vclgo_m2_site_t sites[VCLGO_MAX_SITES];
    size_t          n_sites;

    /* Counts for the summary line. */
    size_t n_disasm_syscalls;   /* real SYSCALL insns Capstone found */
    size_t n_skipped_no_mov;    /* SYSCALLs with no immediate-NR mov */
    size_t n_skipped_overflow;  /* SYSCALLs beyond VCLGO_MAX_SITES */
} vclgo_m2_state_t;

/* Called during .text disassembly. If the SYSCALL is preceded by a
 * recognizable immediate-NR mov, register the site for patching. */
static void
record_site_if_patchable (vclgo_m2_state_t *st, const uint8_t *syscall_addr)
{
    /* Bounds: need at least 5 bytes of pre-context for the b8 form,
     * 7 for the 48-c7-c0 form. Anything closer to text start than
     * that cannot possibly be a patchable site. */
    if (syscall_addr < st->text_lo + 7)
        return;

    uint8_t  mov_len = 0;
    uint32_t nr = 0;

    /* Prefer the shorter (b8) form when both patterns could match: it
     * is by far the more common encoding Go's assembler emits. */
    if (syscall_addr[-5] == 0xB8) {
        mov_len = 5;
        memcpy (&nr, syscall_addr - 4, 4);
    } else if (syscall_addr[-7] == 0x48 &&
               syscall_addr[-6] == 0xC7 &&
               syscall_addr[-5] == 0xC0) {
        mov_len = 7;
        memcpy (&nr, syscall_addr - 4, 4);
    } else {
        st->n_skipped_no_mov++;
        return;
    }

    if (st->n_sites >= VCLGO_MAX_SITES) {
        st->n_skipped_overflow++;
        return;
    }

    st->sites[st->n_sites++] = (vclgo_m2_site_t){
        .syscall_addr = (uint8_t *)syscall_addr,
        .nr = nr,
        .mov_len = mov_len,
    };
}

/* Walk the range [base, base+size) with Capstone; record every real
 * SYSCALL instruction that qualifies for patching. */
static void
find_sites_in_text (vclgo_m2_state_t *st)
{
    csh handle;
    if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf (stderr, "[vclgo/m2] cs_open failed\n");
        return;
    }
    cs_option (handle, CS_OPT_DETAIL, CS_OPT_OFF);

    cs_insn *insn = cs_malloc (handle);
    const uint8_t *code = st->text_lo;
    size_t code_size = (size_t)(st->text_hi - st->text_lo);
    uint64_t address = (uint64_t)(uintptr_t)st->text_lo;

    while (cs_disasm_iter (handle, &code, &code_size, &address, insn)) {
        if (insn->id != X86_INS_SYSCALL)
            continue;
        st->n_disasm_syscalls++;
        record_site_if_patchable (st, (const uint8_t *)(uintptr_t)insn->address);
    }

    cs_free (insn, 1);
    cs_close (&handle);
}

static gboolean
on_text_section (const GumSectionDetails *details, gpointer user_data)
{
    vclgo_m2_state_t *st = user_data;
    if (details->name == NULL || strcmp (details->name, ".text") != 0)
        return TRUE;
    st->text_lo = (const uint8_t *)(uintptr_t)details->address;
    st->text_hi = st->text_lo + details->size;
    st->text_found = TRUE;
    return FALSE;
}

/* Build the trampoline for one site.
 *
 *   5-byte mov form:
 *     b8 NN NN NN NN   mov  $NR, %eax
 *     0f 05            syscall
 *     c3               ret
 *     90 x 8           padding
 *   7-byte mov form:
 *     48 c7 c0 NN NN NN NN   mov  $NR, %rax
 *     0f 05                  syscall
 *     c3                     ret
 *     90 x 6                 padding
 *
 * SYSCALL clobbers %rcx and %r11 whether we intercept or not, so
 * neither the caller-saved regs nor the stack alignment need any
 * further care. RET consumes the return address that our CALL rel32
 * pushed, taking control back to the instruction immediately after
 * the original SYSCALL.
 */
static void
emit_trampoline (uint8_t *dst, const vclgo_m2_site_t *s)
{
    memset (dst, 0x90, VCLGO_TRAMP_SIZE);
    if (s->mov_len == 5) {
        dst[0] = 0xB8;
        memcpy (dst + 1, &s->nr, 4);
        dst[5] = 0x0F;
        dst[6] = 0x05;
        dst[7] = 0xC3;
        /* dst[8..15] already 0x90 from memset above */
    } else {
        dst[0] = 0x48;
        dst[1] = 0xC7;
        dst[2] = 0xC0;
        memcpy (dst + 3, &s->nr, 4);
        dst[7] = 0x0F;
        dst[8] = 0x05;
        dst[9] = 0xC3;
    }
}

/* Payload for gum_memory_patch_code: the 7-or-9-byte replacement plus
 * its length. The apply callback runs against a writable alias of the
 * target page, so a plain memcpy is safe. */
typedef struct {
    const uint8_t *bytes;
    size_t         len;
} vclgo_patch_payload_t;

static void
apply_patch (gpointer mem, gpointer user_data)
{
    const vclgo_patch_payload_t *p = user_data;
    memcpy (mem, p->bytes, p->len);
}

/* Emit the CALL rel32 (+ trailing NOPs) that overwrites one site's
 * mov+syscall pair. Total bytes written = 5 (CALL) + (2 for b8 form, 4
 * for 48-c7-c0 form) = 7 or 9 bytes. */
static gboolean
patch_one_site (vclgo_m2_site_t *s, const uint8_t *tramp)
{
    uint8_t *patch_start = s->syscall_addr - s->mov_len;
    size_t   patch_len   = (size_t)s->mov_len + 2u;

    int64_t rel = (int64_t)(uintptr_t)tramp -
                  ((int64_t)(uintptr_t)patch_start + 5);
    if (rel < INT32_MIN || rel > INT32_MAX) {
        fprintf (stderr,
                 "[vclgo/m2] site %p unreachable via CALL rel32 (rel=%" PRId64
                 ")\n",
                 patch_start, rel);
        return FALSE;
    }
    int32_t rel32 = (int32_t)rel;

    /* 5-byte CALL rel32 then NOPs pad to patch_len. */
    uint8_t replacement[9] = { 0xE8, 0, 0, 0, 0,
                               0x90, 0x90, 0x90, 0x90 };
    memcpy (&replacement[1], &rel32, 4);

    vclgo_patch_payload_t payload = { .bytes = replacement, .len = patch_len };
    return gum_memory_patch_code (patch_start, patch_len, apply_patch,
                                  &payload);
}

__attribute__ ((constructor))
static void
vclgo_gum_m2_ctor (void)
{
    fprintf (stderr, "[vclgo/m2] gum_init_embedded()\n");
    gum_init_embedded ();

    vclgo_m2_state_t st = { 0 };

    GumModule *main_mod = gum_process_get_main_module ();
    if (main_mod == NULL) {
        fprintf (stderr, "[vclgo/m2] no main module — aborting patcher\n");
        gum_deinit_embedded ();
        return;
    }
    fprintf (stderr, "[vclgo/m2] main module: %s (%s)\n",
             gum_module_get_name (main_mod), gum_module_get_path (main_mod));

    gum_module_enumerate_sections (main_mod, on_text_section, &st);
    if (!st.text_found) {
        fprintf (stderr, "[vclgo/m2] main module has no .text section — "
                         "aborting patcher\n");
        gum_deinit_embedded ();
        return;
    }
    fprintf (stderr, "[vclgo/m2] .text: %p .. %p  (%zu bytes)\n",
             st.text_lo, st.text_hi, (size_t)(st.text_hi - st.text_lo));

    find_sites_in_text (&st);
    fprintf (stderr,
             "[vclgo/m2] disasm_syscalls=%zu  patchable_sites=%zu  "
             "skipped_no_mov=%zu  skipped_overflow=%zu\n",
             st.n_disasm_syscalls, st.n_sites, st.n_skipped_no_mov,
             st.n_skipped_overflow);
    if (st.n_sites == 0) {
        gum_deinit_embedded ();
        return;
    }

    /* Trampoline page must be reachable from every site via CALL rel32.
     * We pin it near the middle of .text to maximise headroom. */
    const uint8_t *text_mid = st.text_lo + (st.text_hi - st.text_lo) / 2;
    GumAddressSpec spec = {
        .near_address = (gpointer)(uintptr_t)text_mid,
        .max_distance = VCLGO_TRAMP_MAX_DISTANCE,
    };
    gsize page_size = gum_query_page_size ();
    uint8_t *tramp_page = gum_memory_allocate_near (&spec, page_size,
                                                    page_size, GUM_PAGE_RW);
    if (tramp_page == NULL) {
        fprintf (stderr, "[vclgo/m2] gum_memory_allocate_near failed near %p "
                         "(distance=%zu) — aborting patcher\n",
                 text_mid, (size_t)VCLGO_TRAMP_MAX_DISTANCE);
        gum_deinit_embedded ();
        return;
    }
    fprintf (stderr,
             "[vclgo/m2] trampoline page: %p  (offset from .text mid = %+" PRId64
             ")\n",
             tramp_page,
             (int64_t)(uintptr_t)tramp_page - (int64_t)(uintptr_t)text_mid);

    /* Emit trampolines while the page is still RW. */
    for (size_t i = 0; i < st.n_sites; i++)
        emit_trampoline (tramp_page + i * VCLGO_TRAMP_SIZE, &st.sites[i]);

    /* Flip trampolines to RX before any patched site could reach them. */
    gum_mprotect (tramp_page, page_size, GUM_PAGE_RX);

    /* Now rewrite each site in place. Because gum_memory_patch_code
     * synchronises D-cache / I-cache internally, a Go goroutine on
     * another thread could in principle observe half the replacement
     * — but we run in the LD_PRELOAD constructor, before Go's runtime
     * has spawned any user goroutines, so there is no concurrency to
     * worry about. */
    size_t n_patched = 0;
    for (size_t i = 0; i < st.n_sites; i++) {
        const uint8_t *tramp = tramp_page + i * VCLGO_TRAMP_SIZE;
        if (patch_one_site (&st.sites[i], tramp))
            n_patched++;
    }
    fprintf (stderr, "[vclgo/m2] patched %zu / %zu sites\n",
             n_patched, st.n_sites);

    gum_deinit_embedded ();
    fprintf (stderr, "[vclgo/m2] ctor done, handing off to target\n");
}
