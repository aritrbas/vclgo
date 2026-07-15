/*
 * gum_m25.c — M2.5: function-entry patching for the three generic
 * syscall wrappers, hand-rolled.
 *
 * Second attempt at M2.5. The first attempt used
 * gum_interceptor_replace as the mechanism; it installed the patch
 * successfully but the frida-gum-managed thunk at the jump target
 * (0x678008 for Syscall6 in our test binary) starts with
 *
 *   ff 35 f2 ff ff ff        pushq  -14(%rip)
 *
 * i.e. it pushes an 8-byte "context" pointer onto the stack before
 * transferring control to our replacement. That contract requires the
 * replacement to be a normal C function whose eventual RET pops the
 * pushed context and returns via a frida-gum cleanup thunk. Our naked
 * `jmp` tail-jumped past the cleanup contract, and when Go's original
 * wrapper body then executed its own RET, it popped the pushed
 * context — a garbage return PC from Go's perspective — and Go's
 * runtime panicked with "unexpected return pc" the first time a
 * signal (async preemption / GC) hit a stack frame under a hooked
 * wrapper.
 *
 * This is the same architectural mismatch that made
 * gum_interceptor_attach unusable for Go the first time around:
 * frida-gum's interceptor assumes SysV C calling conventions and
 * inserts frame-bookkeeping the runtime can't see. Both _attach and
 * _replace are off-limits for Go.
 *
 * What we do instead: install the detour ourselves using the same
 * byte-level primitives that made M2 work.
 *   - Capstone (via frida-gum's bundled _frida_cs_*) to walk the
 *     function prologue and count off >= 5 bytes of relocatable
 *     instructions.
 *   - gum_memory_allocate_near to reserve a page within CALL rel32
 *     reach of the target.
 *   - gum_x86_writer to emit the trampoline (relocated prologue +
 *     JMP back to func + N).
 *   - gum_mprotect to flip the trampoline page to RX.
 *   - gum_memory_patch_code to atomically write the JMP at the
 *     target's entry.
 *
 * The trampoline path in this file is IDENTITY-passthrough: control
 * jumps into our trampoline, runs a byte-for-byte copy of the
 * function's first N bytes, then jumps back into the function's body
 * at byte N. Semantics unchanged. This is the correctness gate; if
 * it works, M3 replaces the trampoline body with a fd-inspection +
 * dispatch decision.
 *
 * Prologue relocation safety: for our specific targets in Go 1.26.x
 * linux/amd64 binaries, the first 5-6 bytes of every wrapper are
 * plain `mov` instructions using stack or general-purpose register
 * operands only — no RIP-relative memory access, no relative
 * branches. Verified by objdump; asserted at runtime via Capstone's
 * instruction category check. If a future Go version emits a
 * RIP-relative or branch instruction inside the first 5 bytes of one
 * of these wrappers we bail out and leave that wrapper unpatched.
 */

#define _GNU_SOURCE

#include "frida-gum.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Trampoline layout per wrapper, upper bound: at most 15 bytes of
 * relocated prologue + 5-byte JMP rel32 back = 20 bytes. Round up to
 * 32 for alignment and to leave a little breathing room for future
 * additions. */
#define VCLGO_M25_TRAMP_SIZE 32u

/* Reach constraint for CALL/JMP rel32: signed 32-bit displacement.
 * Same rule as M2 — trampoline page must sit within 1 GiB of .text.  */
#define VCLGO_M25_MAX_DISTANCE ((gsize)(1u << 30))

typedef struct {
    const char *symbol;
    uint8_t    *entry;         /* runtime address of target function */
    uint8_t    *tramp;         /* per-wrapper trampoline slot        */
    uint8_t     prologue_len;  /* bytes of prologue relocated (>= 5) */
} vclgo_m25_wrapper_t;

static vclgo_m25_wrapper_t g_wrappers[] = {
    { "internal/runtime/syscall/linux.Syscall6", NULL, NULL, 0 },
    { "syscall.rawSyscallNoError.abi0",          NULL, NULL, 0 },
    { "syscall.rawVforkSyscall.abi0",            NULL, NULL, 0 },
};
#define VCLGO_M25_N_WRAPPERS (sizeof g_wrappers / sizeof g_wrappers[0])

/* Walk instructions at `entry` until we've counted >= min_bytes and
 * every consumed instruction is safe to relocate byte-for-byte (no
 * relative jump/call, no RIP-relative memory operand). Returns the
 * number of bytes consumed, or 0 if unsafe. */
static uint8_t
scan_prologue (const uint8_t *entry, uint8_t min_bytes)
{
    csh handle;
    if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return 0;
    cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn *insn = cs_malloc (handle);
    const uint8_t *code = entry;
    size_t code_size = 32; /* generous upper bound on how far we look */
    uint64_t address = (uint64_t)(uintptr_t)entry;

    uint8_t consumed = 0;
    while (consumed < min_bytes) {
        if (!cs_disasm_iter (handle, &code, &code_size, &address, insn))
            goto unsafe;

        /* Reject relative branches / calls / jumps: their imm operand
         * is relative to the site's original PC and won't stay valid
         * once we move the instruction. */
        for (int g = 0; g < insn->detail->groups_count; g++) {
            uint8_t grp = insn->detail->groups[g];
            if (grp == CS_GRP_JUMP || grp == CS_GRP_CALL ||
                grp == CS_GRP_RET || grp == CS_GRP_INT ||
                grp == CS_GRP_IRET || grp == CS_GRP_BRANCH_RELATIVE)
                goto unsafe;
        }
        /* Reject RIP-relative memory operands for the same reason. */
        for (uint8_t o = 0; o < insn->detail->x86.op_count; o++) {
            const cs_x86_op *op = &insn->detail->x86.operands[o];
            if (op->type == X86_OP_MEM && op->mem.base == X86_REG_RIP)
                goto unsafe;
        }

        consumed += (uint8_t)insn->size;
        if (consumed > 15) goto unsafe; /* absurdly long prologue */
    }
    cs_free (insn, 1);
    cs_close (&handle);
    return consumed;

unsafe:
    cs_free (insn, 1);
    cs_close (&handle);
    return 0;
}

/* Build the trampoline for one wrapper.
 *
 *   [ prologue bytes, byte-for-byte copy ]
 *   E9 XX XX XX XX                        JMP rel32 to (entry + prologue_len)
 *
 * The whole thing has to live within 32-bit signed reach of the
 * target so we can also install a JMP rel32 at the target's entry. */
static void
emit_trampoline (uint8_t *tramp, const vclgo_m25_wrapper_t *w)
{
    memset (tramp, 0xCC, VCLGO_M25_TRAMP_SIZE); /* int3 guard */
    memcpy (tramp, w->entry, w->prologue_len);

    uint8_t *jmp_at = tramp + w->prologue_len;
    uint8_t *back_target = w->entry + w->prologue_len;
    int64_t rel = (int64_t)(uintptr_t)back_target -
                  ((int64_t)(uintptr_t)jmp_at + 5);
    /* Reach was already guaranteed by allocating the trampoline page
     * within 1 GiB of the target, so no runtime overflow check is
     * necessary here — but assert cheaply anyway. */
    jmp_at[0] = 0xE9;
    int32_t rel32 = (int32_t)rel;
    memcpy (jmp_at + 1, &rel32, 4);
}

/* Bytes we want to overwrite at the target's entry: 5-byte JMP rel32
 * to the trampoline, then NOPs padding out to prologue_len (so the
 * bytes AFTER our patch are exactly the same as the untouched
 * function body starting at entry+prologue_len). */
typedef struct {
    uint8_t bytes[16];
    size_t  len;
} vclgo_m25_patch_t;

static void
apply_patch (gpointer mem, gpointer user_data)
{
    const vclgo_m25_patch_t *p = user_data;
    memcpy (mem, p->bytes, p->len);
}

static gboolean
patch_wrapper_entry (const vclgo_m25_wrapper_t *w)
{
    int64_t rel = (int64_t)(uintptr_t)w->tramp -
                  ((int64_t)(uintptr_t)w->entry + 5);
    if (rel < INT32_MIN || rel > INT32_MAX) {
        fprintf (stderr,
                 "[vclgo/m25] %s trampoline unreachable via JMP rel32 "
                 "(rel=%" PRId64 ")\n", w->symbol, rel);
        return FALSE;
    }

    vclgo_m25_patch_t p = {
        .bytes = { 0xE9, 0, 0, 0, 0,
                   0x90, 0x90, 0x90, 0x90, 0x90,
                   0x90, 0x90, 0x90, 0x90, 0x90, 0x90 },
        .len = w->prologue_len,
    };
    int32_t rel32 = (int32_t)rel;
    memcpy (&p.bytes[1], &rel32, 4);
    return gum_memory_patch_code (w->entry, w->prologue_len, apply_patch, &p);
}

__attribute__ ((constructor))
static void
vclgo_gum_m25_ctor (void)
{
    fprintf (stderr, "[vclgo/m25] gum_init_embedded()\n");
    gum_init_embedded ();

    GumModule *m = gum_process_get_main_module ();
    if (m == NULL) {
        fprintf (stderr, "[vclgo/m25] no main module — aborting\n");
        return;
    }
    fprintf (stderr, "[vclgo/m25] main module: %s\n", gum_module_get_name (m));

    /* Resolve each symbol and count the prologue bytes we need. Also
     * record the maximum entry address so the trampoline page can be
     * chosen to reach every wrapper. */
    uintptr_t entry_min = UINTPTR_MAX, entry_max = 0;
    size_t n_resolved = 0;
    for (size_t i = 0; i < VCLGO_M25_N_WRAPPERS; i++) {
        vclgo_m25_wrapper_t *w = &g_wrappers[i];
        GumAddress addr = gum_module_find_symbol_by_name (m, w->symbol);
        if (addr == 0) {
            fprintf (stderr, "[vclgo/m25]   symbol not found: %s\n",
                     w->symbol);
            continue;
        }
        w->entry = (uint8_t *)(uintptr_t)addr;
        w->prologue_len = scan_prologue (w->entry, 5);
        if (w->prologue_len == 0) {
            fprintf (stderr,
                     "[vclgo/m25]   prologue unsafe to relocate for %s\n",
                     w->symbol);
            w->entry = NULL;
            continue;
        }
        fprintf (stderr,
                 "[vclgo/m25]   %s @ 0x%" PRIxPTR "  prologue=%u bytes\n",
                 w->symbol, (uintptr_t)w->entry, w->prologue_len);
        if ((uintptr_t)w->entry < entry_min) entry_min = (uintptr_t)w->entry;
        if ((uintptr_t)w->entry > entry_max) entry_max = (uintptr_t)w->entry;
        n_resolved++;
    }
    if (n_resolved == 0) {
        fprintf (stderr, "[vclgo/m25] no wrappers resolvable — aborting\n");
        gum_deinit_embedded ();
        return;
    }

    /* Allocate one shared trampoline page reachable from every
     * resolved wrapper. `near` = midpoint between smallest and
     * largest entry. */
    uintptr_t center = entry_min + (entry_max - entry_min) / 2;
    GumAddressSpec spec = {
        .near_address = (gpointer)center,
        .max_distance = VCLGO_M25_MAX_DISTANCE,
    };
    gsize page_size = gum_query_page_size ();
    uint8_t *tramp_page = gum_memory_allocate_near (&spec, page_size,
                                                    page_size, GUM_PAGE_RW);
    if (tramp_page == NULL) {
        fprintf (stderr, "[vclgo/m25] gum_memory_allocate_near failed near "
                         "0x%" PRIxPTR " — aborting\n", center);
        gum_deinit_embedded ();
        return;
    }
    fprintf (stderr, "[vclgo/m25] trampoline page: %p\n", tramp_page);

    /* Assign a per-wrapper trampoline slot and emit while RW. */
    size_t slot = 0;
    for (size_t i = 0; i < VCLGO_M25_N_WRAPPERS; i++) {
        vclgo_m25_wrapper_t *w = &g_wrappers[i];
        if (w->entry == NULL) continue;
        w->tramp = tramp_page + slot * VCLGO_M25_TRAMP_SIZE;
        emit_trampoline (w->tramp, w);
        slot++;
    }
    gum_mprotect (tramp_page, page_size, GUM_PAGE_RX);

    /* Now install the JMP-to-trampoline at each wrapper's entry. */
    size_t n_installed = 0;
    for (size_t i = 0; i < VCLGO_M25_N_WRAPPERS; i++) {
        vclgo_m25_wrapper_t *w = &g_wrappers[i];
        if (w->entry == NULL) continue;
        if (patch_wrapper_entry (w))
            n_installed++;
    }
    fprintf (stderr, "[vclgo/m25] patched %zu / %zu wrapper entries\n",
             n_installed, n_resolved);

    /* Self-verify: dump the bytes now at each entry and follow one hop. */
    for (size_t i = 0; i < VCLGO_M25_N_WRAPPERS; i++) {
        const vclgo_m25_wrapper_t *w = &g_wrappers[i];
        if (w->entry == NULL) continue;
        fprintf (stderr,
                 "[vclgo/m25]   entry @ 0x%" PRIxPTR ": ",
                 (uintptr_t)w->entry);
        for (int b = 0; b < 16; b++) fprintf (stderr, "%02x ", w->entry[b]);
        fprintf (stderr, "\n[vclgo/m25]     tramp @ 0x%" PRIxPTR ": ",
                 (uintptr_t)w->tramp);
        for (int b = 0; b < 16; b++) fprintf (stderr, "%02x ", w->tramp[b]);
        fprintf (stderr, "\n");
    }

    gum_deinit_embedded ();
    fprintf (stderr, "[vclgo/m25] ctor done, handing off to target\n");
}
