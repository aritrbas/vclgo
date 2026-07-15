/* probe_sites: locate every SYSCALL (0F 05) instruction in a Go/x86-64
 * ELF binary and classify each hit by containing symbol.
 *
 * M1 of the fastpath prototype: read-only reconnaissance. Answers three
 * questions we need before we start rewriting bytes:
 *
 *   1. Does raw byte scanning of .text agree with objdump's disassembly?
 *      (Any disagreement is a false positive we must handle at patch
 *       time so we do not corrupt embedded immediate data.)
 *   2. Which functions do the SYSCALL sites live in? Runtime-only sites
 *      (futex, mmap, raise, exit, clone) must remain replayed to the
 *      kernel; only the syscalls that Go's net package emits should be
 *      redirected to VCL.
 *   3. How many sites are there per binary, so we can size the patcher's
 *      work and reason about I-cache behavior at process start.
 *
 * Usage:
 *
 *     probe_sites [--all-sites | --unknown-only] <elf>
 *
 * Options:
 *   --all-sites       print one line per SYSCALL site (default: summarize)
 *   --unknown-only    print only sites not inside a known function symbol
 *   -v                verbose (per-symbol counts)
 *
 * Exit codes:
 *   0  success
 *   1  file I/O or ELF parse error
 *   2  usage error
 */

#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* SYSCALL opcode on x86-64: two bytes, 0F 05. */
static const uint8_t SYSCALL_OPCODE[2] = { 0x0F, 0x05 };

typedef struct {
    uint64_t addr;   /* virtual address of the SYSCALL instruction */
    uint64_t offset; /* file offset of the SYSCALL instruction */
    /* Best-effort classification. sym_name is a pointer into the parsed
     * ELF's .strtab / .dynstr region; ELF stays mmapped for the whole run,
     * so the pointer is stable. NULL means "no covering symbol found". */
    const char *sym_name;
    uint64_t sym_addr;
    uint64_t sym_size;
} site_t;

typedef struct {
    uint64_t addr;
    uint64_t size;
    const char *name;
} sym_t;

typedef struct {
    const uint8_t *base;   /* mmap base of the ELF file */
    size_t         length; /* file length */
    const Elf64_Ehdr *eh;
    const Elf64_Shdr *sh;
    const char *shstr;

    /* .text virtual-address range and its backing file bytes. Guaranteed
     * contiguous by ELF. We only look at .text; SYSCALL bytes in .rodata
     * (constant data) would never be executed, so we do not care. */
    uint64_t text_vaddr;
    uint64_t text_size;
    uint64_t text_offset;

    /* Function symbol table, sorted by addr for binary search. */
    sym_t *syms;
    size_t sym_count;
} elf_view_t;

/* --- utility ---------------------------------------------------------- */

static void
die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("probe_sites: error: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

static void
usage(void)
{
    fputs("usage: probe_sites [--all-sites | --unknown-only] [-v] <elf>\n",
          stderr);
    exit(2);
}

/* Standard qsort comparator on sym_t.addr. Ties broken by size so wider
 * symbols come first (matters for the covering-symbol lookup below when
 * multiple symbols alias the same address). */
static int
cmp_syms(const void *a, const void *b)
{
    const sym_t *sa = a;
    const sym_t *sb = b;
    if (sa->addr < sb->addr) return -1;
    if (sa->addr > sb->addr) return 1;
    if (sa->size > sb->size) return -1;
    if (sa->size < sb->size) return 1;
    return 0;
}

/* --- ELF parsing ------------------------------------------------------ */

static void
elf_view_open(elf_view_t *v, const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        die("open(%s): %s", path, strerror(errno));

    struct stat st;
    if (fstat(fd, &st) < 0)
        die("fstat(%s): %s", path, strerror(errno));
    if ((size_t)st.st_size < sizeof(Elf64_Ehdr))
        die("%s: too small to be an ELF file", path);

    void *m = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED)
        die("mmap(%s): %s", path, strerror(errno));
    close(fd);

    v->base = m;
    v->length = st.st_size;
    v->eh = (const Elf64_Ehdr *)m;

    if (memcmp(v->eh->e_ident, ELFMAG, SELFMAG) != 0)
        die("%s: not an ELF file", path);
    if (v->eh->e_ident[EI_CLASS] != ELFCLASS64)
        die("%s: not ELFCLASS64 (only x86-64 is supported)", path);
    if (v->eh->e_machine != EM_X86_64)
        die("%s: not EM_X86_64", path);

    v->sh = (const Elf64_Shdr *)(v->base + v->eh->e_shoff);
    const Elf64_Shdr *shstrshdr = &v->sh[v->eh->e_shstrndx];
    v->shstr = (const char *)(v->base + shstrshdr->sh_offset);
}

static const Elf64_Shdr *
elf_find_section(const elf_view_t *v, const char *name)
{
    for (size_t i = 0; i < v->eh->e_shnum; i++) {
        const char *sname = v->shstr + v->sh[i].sh_name;
        if (strcmp(sname, name) == 0)
            return &v->sh[i];
    }
    return NULL;
}

static void
elf_find_text(elf_view_t *v)
{
    const Elf64_Shdr *text = elf_find_section(v, ".text");
    if (!text)
        die("no .text section in ELF");
    v->text_vaddr = text->sh_addr;
    v->text_size = text->sh_size;
    v->text_offset = text->sh_offset;

    if (v->text_offset + v->text_size > v->length)
        die(".text extends past end of file");
}

static void
elf_load_symbols(elf_view_t *v)
{
    /* Go binaries usually retain the symbol table (.symtab) even when
     * "stripped" by convention, because Go's own tooling and the runtime
     * depend on it for stack traces. We use it if present; if truly
     * stripped, we fall back to .dynsym (much smaller). Either way we
     * only care about STT_FUNC entries. */
    const Elf64_Shdr *symtab = elf_find_section(v, ".symtab");
    const Elf64_Shdr *strtab_shdr = NULL;
    const char *strtab = NULL;
    if (symtab) {
        strtab_shdr = &v->sh[symtab->sh_link];
    } else {
        symtab = elf_find_section(v, ".dynsym");
        if (symtab)
            strtab_shdr = &v->sh[symtab->sh_link];
    }
    if (!symtab || !strtab_shdr) {
        v->syms = NULL;
        v->sym_count = 0;
        return;
    }
    strtab = (const char *)(v->base + strtab_shdr->sh_offset);

    const Elf64_Sym *entries =
        (const Elf64_Sym *)(v->base + symtab->sh_offset);
    size_t nentries = symtab->sh_size / sizeof(Elf64_Sym);

    /* First pass: count STT_FUNC entries with non-zero size (Go emits
     * some zero-size markers we don't want in the covering-symbol
     * search — they'd never cover a SYSCALL). */
    size_t nfunc = 0;
    for (size_t i = 0; i < nentries; i++) {
        if (ELF64_ST_TYPE(entries[i].st_info) == STT_FUNC &&
            entries[i].st_size > 0 &&
            entries[i].st_value != 0)
            nfunc++;
    }

    sym_t *syms = calloc(nfunc, sizeof(sym_t));
    if (!syms)
        die("out of memory allocating %zu function symbols", nfunc);

    size_t out = 0;
    for (size_t i = 0; i < nentries; i++) {
        if (ELF64_ST_TYPE(entries[i].st_info) != STT_FUNC ||
            entries[i].st_size == 0 ||
            entries[i].st_value == 0)
            continue;
        syms[out].addr = entries[i].st_value;
        syms[out].size = entries[i].st_size;
        syms[out].name = strtab + entries[i].st_name;
        out++;
    }
    qsort(syms, out, sizeof(sym_t), cmp_syms);

    v->syms = syms;
    v->sym_count = out;
}

/* Binary search for the widest symbol covering `addr`. Because our sort
 * ties widest-first when addresses match, the first hit in the natural
 * lower_bound position is the correct covering symbol. */
static const sym_t *
sym_covering(const elf_view_t *v, uint64_t addr)
{
    if (v->sym_count == 0)
        return NULL;
    /* Standard upper_bound: largest index whose addr <= addr. */
    size_t lo = 0, hi = v->sym_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (v->syms[mid].addr <= addr)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo == 0)
        return NULL;
    const sym_t *s = &v->syms[lo - 1];
    if (addr >= s->addr && addr < s->addr + s->size)
        return s;
    return NULL;
}

/* --- scanning --------------------------------------------------------- */

typedef struct {
    site_t *v;
    size_t count;
    size_t cap;
} sites_t;

static void
sites_push(sites_t *s, site_t site)
{
    if (s->count == s->cap) {
        size_t ncap = s->cap ? s->cap * 2 : 128;
        site_t *nv = realloc(s->v, ncap * sizeof(site_t));
        if (!nv)
            die("out of memory growing sites array");
        s->v = nv;
        s->cap = ncap;
    }
    s->v[s->count++] = site;
}

/* Scan .text for the exact byte pattern 0F 05. We do NOT try to be a
 * disassembler here — the point of M1 is precisely to compare a naive
 * byte scan against ground truth (objdump) so we know how many false
 * positives to expect at patch time. */
static void
scan_text(const elf_view_t *v, sites_t *out)
{
    const uint8_t *p = v->base + v->text_offset;
    const uint8_t *end = p + v->text_size;
    for (const uint8_t *q = p; q + 2 <= end; q++) {
        if (q[0] != SYSCALL_OPCODE[0] || q[1] != SYSCALL_OPCODE[1])
            continue;
        uint64_t off_in_text = (uint64_t)(q - p);
        site_t site = {
            .addr = v->text_vaddr + off_in_text,
            .offset = v->text_offset + off_in_text,
            .sym_name = NULL,
            .sym_addr = 0,
            .sym_size = 0,
        };
        const sym_t *sym = sym_covering(v, site.addr);
        if (sym) {
            site.sym_name = sym->name;
            site.sym_addr = sym->addr;
            site.sym_size = sym->size;
        }
        sites_push(out, site);
    }
}

/* --- reporting -------------------------------------------------------- */

typedef enum {
    MODE_SUMMARY,
    MODE_ALL,
    MODE_UNKNOWN_ONLY,
} report_mode_t;

static int
cmp_by_symaddr(const void *a, const void *b)
{
    const site_t *sa = a;
    const site_t *sb = b;
    /* Sites with no covering symbol sort to the end so per-symbol grouping
     * is not polluted. */
    if (!sa->sym_name && sb->sym_name) return 1;
    if (sa->sym_name && !sb->sym_name) return -1;
    if (!sa->sym_name && !sb->sym_name) {
        if (sa->addr < sb->addr) return -1;
        if (sa->addr > sb->addr) return 1;
        return 0;
    }
    if (sa->sym_addr < sb->sym_addr) return -1;
    if (sa->sym_addr > sb->sym_addr) return 1;
    if (sa->addr < sb->addr) return -1;
    if (sa->addr > sb->addr) return 1;
    return 0;
}

static void
print_hex_context(const elf_view_t *v, uint64_t offset, size_t before,
                  size_t after)
{
    size_t start_off =
        (offset > before) ? (offset - before) : 0;
    size_t end_off = offset + 2 + after;
    if (end_off > v->text_offset + v->text_size)
        end_off = v->text_offset + v->text_size;
    printf("    bytes:");
    for (size_t o = start_off; o < end_off; o++) {
        if (o == offset)
            printf(" [%02x", v->base[o]);
        else if (o == offset + 1)
            printf(" %02x]", v->base[o]);
        else
            printf(" %02x", v->base[o]);
    }
    fputc('\n', stdout);
}

static void
report(const elf_view_t *v, const sites_t *sites, report_mode_t mode,
       bool verbose, const char *path)
{
    size_t known = 0;
    for (size_t i = 0; i < sites->count; i++)
        if (sites->v[i].sym_name)
            known++;

    printf("== %s ==\n", path);
    printf(".text: vaddr=0x%" PRIx64 " size=%" PRIu64 " bytes  "
           "(file offset 0x%" PRIx64 ")\n",
           v->text_vaddr, v->text_size, v->text_offset);
    printf("symbol table: %zu STT_FUNC entries\n", v->sym_count);
    printf("SYSCALL sites found: %zu  (in known function: %zu, "
           "unknown: %zu)\n",
           sites->count, known, sites->count - known);

    if (verbose || mode != MODE_SUMMARY) {
        /* Sort for grouping. */
        site_t *sorted = malloc(sites->count * sizeof(site_t));
        if (!sorted)
            die("out of memory sorting sites");
        memcpy(sorted, sites->v, sites->count * sizeof(site_t));
        qsort(sorted, sites->count, sizeof(site_t), cmp_by_symaddr);

        if (verbose) {
            /* Per-symbol count histogram, most syscalls first. */
            printf("\n-- per-symbol counts (ranked) --\n");
            size_t i = 0;
            struct rank { const char *name; size_t count; };
            struct rank *ranks = calloc(sites->count, sizeof(*ranks));
            size_t rank_count = 0;
            while (i < sites->count) {
                if (!sorted[i].sym_name) break;
                size_t j = i;
                while (j < sites->count && sorted[j].sym_name &&
                       sorted[j].sym_addr == sorted[i].sym_addr)
                    j++;
                ranks[rank_count].name = sorted[i].sym_name;
                ranks[rank_count].count = j - i;
                rank_count++;
                i = j;
            }
            /* naive sort: rank_count is at most ~30 in practice */
            for (size_t a = 0; a < rank_count; a++)
                for (size_t b = a + 1; b < rank_count; b++)
                    if (ranks[b].count > ranks[a].count) {
                        struct rank t = ranks[a];
                        ranks[a] = ranks[b];
                        ranks[b] = t;
                    }
            for (size_t r = 0; r < rank_count; r++)
                printf("    %6zu  %s\n", ranks[r].count, ranks[r].name);
            free(ranks);
        }

        if (mode == MODE_ALL) {
            printf("\n-- all sites --\n");
            for (size_t i = 0; i < sites->count; i++) {
                const site_t *s = &sorted[i];
                printf("  0x%08" PRIx64 "  %s\n", s->addr,
                       s->sym_name ? s->sym_name : "(no symbol)");
            }
        } else if (mode == MODE_UNKNOWN_ONLY) {
            printf("\n-- sites not covered by any function symbol "
                   "(potential false positives) --\n");
            size_t shown = 0;
            for (size_t i = 0; i < sites->count; i++) {
                const site_t *s = &sorted[i];
                if (s->sym_name) continue;
                printf("  0x%08" PRIx64 " (file 0x%08" PRIx64 ")\n",
                       s->addr, s->offset);
                print_hex_context(v, s->offset, 8, 4);
                shown++;
            }
            if (shown == 0)
                printf("  (none)\n");
        }

        free(sorted);
    }
}

/* --- main ------------------------------------------------------------- */

int
main(int argc, char **argv)
{
    report_mode_t mode = MODE_SUMMARY;
    bool verbose = false;
    const char *path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--all-sites") == 0)
            mode = MODE_ALL;
        else if (strcmp(argv[i], "--unknown-only") == 0)
            mode = MODE_UNKNOWN_ONLY;
        else if (strcmp(argv[i], "-v") == 0)
            verbose = true;
        else if (argv[i][0] == '-')
            usage();
        else if (!path)
            path = argv[i];
        else
            usage();
    }
    if (!path)
        usage();

    elf_view_t v = {0};
    elf_view_open(&v, path);
    elf_find_text(&v);
    elf_load_symbols(&v);

    sites_t sites = {0};
    scan_text(&v, &sites);
    report(&v, &sites, mode, verbose, path);

    free(sites.v);
    free(v.syms);
    munmap((void *)v.base, v.length);
    return 0;
}
