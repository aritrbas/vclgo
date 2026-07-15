/*
 * gum_probe.c — frida-gum-based smoke test for the M2 pipeline.
 *
 * This is an LD_PRELOAD library that only observes: on ctor, it uses
 * frida-gum's low-level APIs to enumerate loaded modules and scan the
 * target's executable ranges for the SYSCALL (0F 05) opcode, then
 * shuts frida-gum back down. It does not patch anything, does not
 * install any Interceptor.attach hooks, and returns control to the
 * target program in the same state it found it (except for a printed
 * report on stderr).
 *
 * Purpose: prove that frida-gum
 *   (a) links cleanly into an LD_PRELOAD library,
 *   (b) initializes inside another process before that process's main()
 *       runs (Go, in our case),
 *   (c) can enumerate the target's loaded modules and executable
 *       ranges at ctor time,
 *   (d) tears itself back down without disturbing the target.
 *
 * This is a strict prerequisite to M2 (real patching). If any of the
 * above fails, we need to understand why before we start rewriting
 * bytes in Go's .text.
 *
 * Explicitly not used:
 *   - gum_interceptor_attach / GumInterceptor at all — that's the API
 *     that broke Approach 2 for Go (patches function entries under SysV
 *     ABI, skips Go's runtime.entersyscall/exitsyscall bookkeeping,
 *     bridges through V8 callbacks). We use frida-gum as a byte-level
 *     patching library only, per the design discussion in this chat.
 *
 * Build via Makefile: `make gum_probe`. LD_PRELOAD it into any dynamic
 * binary and observe stderr:
 *
 *   LD_PRELOAD=$PWD/build/libvclgo_gum_probe.so /bin/true
 */

#define _GNU_SOURCE

#include "frida-gum.h"

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Cap the number of modules we print detail for. Any real Go binary has
 * just a handful of loaded modules at ctor time (main + ld + libc +
 * libpthread + libdl + libm + libgcc); more than that means we're
 * running late enough that dlopen has fired for us, which is a bug in
 * how we injected. */
#define VCLGO_PROBE_MAX_MODULE_DETAIL 32

/* Cap the total bytes we will byte-scan per module. .text sections are
 * usually well under 4 MiB even for large Go binaries; a generous 32 MiB
 * cap protects us from a runaway scan on an unexpected module. */
#define VCLGO_PROBE_MAX_SCAN_BYTES ((size_t)32 * 1024 * 1024)

typedef struct {
    size_t total_modules;
    size_t detailed_modules;

    /* Aggregated across all modules we scanned. */
    size_t total_exec_ranges;
    size_t total_exec_bytes;
    size_t total_raw_hits;
    size_t total_filtered_hits;
} vclgo_probe_stats_t;

typedef struct {
    const char *module_name;
    const uint8_t *module_base;  /* virtual address of module base */
    size_t range_index;
    size_t raw_hits;
    size_t filtered_hits;
    vclgo_probe_stats_t *stats;
} vclgo_range_ctx_t;

/* Approach: use frida-gum's bundled Capstone (renamed internally to
 * _frida_cs_*, but exposed under the canonical cs_* names via macros in
 * frida-gum.h) to walk the range instruction by instruction. Any 0F 05
 * bytes that don't land at an instruction boundary are ignored by
 * definition; any that decode as the mnemonic "syscall" are real.
 *
 * We tried a byte-prologue heuristic first (see git log): it correctly
 * rejected all 6 mid-instruction 0F-05 false positives across four Go
 * binaries, but it also rejected 3 real sites — precisely the ones
 * whose syscall number is loaded from a function argument rather than
 * an immediate (`internal/runtime/syscall/linux.Syscall6`,
 * `syscall.rawSyscallNoError.abi0`, `syscall.rawVforkSyscall.abi0`).
 * Those three wrappers are the load-bearing sites for the socket
 * family, so a heuristic that misses them defeats the purpose. Proper
 * disassembly costs a few ms of scan time per module and eliminates
 * both classes of error.
 *
 * We linear-decode from the range base. Go binaries have no inline
 * data in .text (verified via objdump on echo_server / http_server),
 * so linear decoding stays synchronized end to end. If a range turns
 * out to be C-side (libc, ld.so), linear decode is still safe because
 * those compilers also emit properly aligned code with no inline
 * data; occasional decode failures at padding are handled by
 * cs_disasm_iter itself by resyncing on the next byte.
 */
static void
scan_range_for_syscall (vclgo_range_ctx_t *ctx, const uint8_t *base,
                        size_t size)
{
    if (size < 2) return;

    csh handle;
    if (cs_open (CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf (stderr,
                 "[vclgo/probe]     cs_open failed for range at %p\n", base);
        return;
    }
    /* We only need mnemonics, not operand detail, so leave detail off:
     * that keeps memory usage down for large ranges (libc = 1.6 MiB). */
    cs_option (handle, CS_OPT_DETAIL, CS_OPT_OFF);

    cs_insn *insn = cs_malloc (handle);
    const uint8_t *code = base;
    size_t code_size = size;
    uint64_t address = (uint64_t)(uintptr_t)base;

    size_t disasm_syscalls = 0;
    while (cs_disasm_iter (handle, &code, &code_size, &address, insn)) {
        if (insn->id == X86_INS_SYSCALL) {
            disasm_syscalls++;
        }
    }

    /* Report raw byte hits (unchanged) and disassembler-confirmed hits.
     * "filtered" is now correctness-preserving, not heuristic. */
    size_t raw = 0;
    for (size_t i = 0; i + 1 < size; i++) {
        if (base[i] == 0x0F && base[i + 1] == 0x05)
            raw++;
    }
    ctx->raw_hits += raw;
    ctx->filtered_hits += disasm_syscalls;

    cs_free (insn, 1);
    cs_close (&handle);
}

/* Callback for gum_module_enumerate_sections. Called once per ELF
 * section in the module. We record only the ".text" section address
 * range so the caller can disassemble that range without tripping over
 * the ELF header (which lives at the start of the first PT_LOAD in
 * Go binaries and would desync a byte-linear disassembly). */
typedef struct {
    const uint8_t *base;
    size_t size;
    gboolean found;
} vclgo_text_section_t;

static gboolean
on_section (const GumSectionDetails *details, gpointer user_data)
{
    vclgo_text_section_t *t = user_data;
    if (details->name == NULL) return TRUE;
    if (strcmp (details->name, ".text") != 0) return TRUE;
    t->base = (const uint8_t *)(uintptr_t)details->address;
    t->size = (size_t)details->size;
    t->found = TRUE;
    return FALSE;
}

/* Callback for gum_module_enumerate_ranges. Fallback path for modules
 * that don't expose ELF sections (linux-vdso, some stripped shared
 * libraries). Same disassembly-based scan, just applied to the whole
 * executable range. */
static gboolean
on_range (const GumRangeDetails *details, gpointer user_data)
{
    vclgo_range_ctx_t *ctx = user_data;
    const GumMemoryRange *r = details->range;

    ctx->range_index++;
    ctx->stats->total_exec_ranges++;

    size_t size = (size_t)r->size;
    if (size == 0) return TRUE;
    if (size > VCLGO_PROBE_MAX_SCAN_BYTES) {
        fprintf (stderr,
                 "[vclgo/probe]     range %zu skipped (too large: %zu bytes)\n",
                 ctx->range_index, size);
        return TRUE;
    }

    const uint8_t *base = (const uint8_t *)(uintptr_t)r->base_address;
    ctx->stats->total_exec_bytes += size;

    /* We are reading executable pages that are already mapped in this
     * process (frida-gum enumerated them from /proc/self/maps). No
     * mprotect needed. */
    size_t before_raw = ctx->raw_hits;
    size_t before_filtered = ctx->filtered_hits;
    scan_range_for_syscall (ctx, base, size);
    size_t added_raw = ctx->raw_hits - before_raw;
    size_t added_filtered = ctx->filtered_hits - before_filtered;

    ctx->stats->total_raw_hits += added_raw;
    ctx->stats->total_filtered_hits += added_filtered;

    fprintf (stderr,
             "[vclgo/probe]     range %zu: %p+%zu  raw=%zu filtered=%zu\n",
             ctx->range_index, base, size, added_raw, added_filtered);
    return TRUE;
}

/* Callback for gum_process_enumerate_modules. Called once per loaded
 * module in the target process. */
static gboolean
on_module (GumModule *module, gpointer user_data)
{
    vclgo_probe_stats_t *stats = user_data;
    stats->total_modules++;

    const gchar *name = gum_module_get_name (module);
    const gchar *path = gum_module_get_path (module);
    const GumMemoryRange *range = gum_module_get_range (module);

    if (stats->detailed_modules >= VCLGO_PROBE_MAX_MODULE_DETAIL)
        return TRUE;
    stats->detailed_modules++;

    fprintf (stderr,
             "[vclgo/probe] module: %s  base=0x%" G_GINT64_MODIFIER "x  "
             "size=%" G_GSIZE_FORMAT "  path=%s\n",
             name, range->base_address, (gsize)range->size, path);

    /* Prefer the .text section when the module exposes it (via ELF
     * section headers). This is essential for Go binaries: their first
     * PT_LOAD segment starts at 0x400000 with the ELF header, and
     * disassembling from there desyncs Capstone before it ever reaches
     * real code. For modules without a queryable .text (linux-vdso,
     * some stripped .so files), fall back to executable-range scan. */
    vclgo_range_ctx_t ctx = {
        .module_name = name,
        .module_base = (const uint8_t *)(uintptr_t)range->base_address,
        .range_index = 0,
        .raw_hits = 0,
        .filtered_hits = 0,
        .stats = stats,
    };

    vclgo_text_section_t t = { .base = NULL, .size = 0, .found = FALSE };
    gum_module_enumerate_sections (module, on_section, &t);

    if (t.found) {
        ctx.range_index++;
        stats->total_exec_ranges++;
        stats->total_exec_bytes += t.size;

        size_t before_raw = ctx.raw_hits;
        size_t before_filtered = ctx.filtered_hits;
        scan_range_for_syscall (&ctx, t.base, t.size);
        size_t added_raw = ctx.raw_hits - before_raw;
        size_t added_filtered = ctx.filtered_hits - before_filtered;
        stats->total_raw_hits += added_raw;
        stats->total_filtered_hits += added_filtered;

        fprintf (stderr,
                 "[vclgo/probe]     .text: %p+%zu  raw=%zu filtered=%zu\n",
                 t.base, t.size, added_raw, added_filtered);
    } else {
        gum_module_enumerate_ranges (module, GUM_PAGE_EXECUTE, on_range, &ctx);
    }

    fprintf (stderr,
             "[vclgo/probe]   %s totals: ranges=%zu raw_hits=%zu "
             "filtered_hits=%zu\n",
             name, ctx.range_index, ctx.raw_hits, ctx.filtered_hits);
    return TRUE;
}

/* Constructor: runs before the target's main() executes. */
__attribute__ ((constructor))
static void
vclgo_gum_probe_ctor (void)
{
    fprintf (stderr, "[vclgo/probe] gum_init_embedded()\n");
    gum_init_embedded ();

    vclgo_probe_stats_t stats = { 0 };
    gum_process_enumerate_modules (on_module, &stats);

    fprintf (stderr,
             "[vclgo/probe] summary: modules=%zu  exec_ranges=%zu  "
             "exec_bytes=%zu  raw_hits=%zu  filtered_hits=%zu\n",
             stats.total_modules,
             stats.total_exec_ranges,
             stats.total_exec_bytes,
             stats.total_raw_hits,
             stats.total_filtered_hits);

    fprintf (stderr, "[vclgo/probe] gum_deinit_embedded()\n");
    gum_deinit_embedded ();

    fprintf (stderr, "[vclgo/probe] ctor done, handing off to target\n");
}
