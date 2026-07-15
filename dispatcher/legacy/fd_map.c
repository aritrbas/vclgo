/*
 * fd_map.c — tracking metadata for open VCL sessions keyed by the fake FD
 * that vclgo hands back to Go. Provides an O(1) address-family / v6only /
 * datagram lookup so the fast path (accept/listen/read/write) does not
 * incur VLS attr calls for information we already know.
 *
 * VLS handles are dense small integers (essentially pool indices), and
 * VCLGO_VLSH_MASK is 24 bits, so a direct array of that size is by far the
 * cheapest structure. The whole table is a fixed 4 MiB allocation that is
 * only paged in as sessions actually get created.
 */

#include "internal.h"

#define TABLE_SIZE (VCLGO_VLSH_MASK + 1u)

static vclgo_sock_meta_t *g_meta;   /* size = TABLE_SIZE */
static uint8_t           *g_valid;  /* 1 = live entry; 0 = free */
static pthread_mutex_t    g_lock = PTHREAD_MUTEX_INITIALIZER;

/* S3-1: pthread_once guarantees the allocation happens exactly once
 * across concurrent vclgo_init callers. The original `if (g_meta) return`
 * was safe only because Phase-1 Frida injection serialises init; Phase-2
 * or any explicit re-init call would race. */
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;

static void fdmap_init_once(void)
{
    g_meta  = calloc(TABLE_SIZE, sizeof(vclgo_sock_meta_t));
    g_valid = calloc(TABLE_SIZE, sizeof(uint8_t));
    if (!g_meta || !g_valid) {
        fprintf(stderr, "[vclgo] fd_map init: OOM\n");
        abort();
    }
}

void vclgo_fdmap_init(void)
{
    pthread_once(&g_init_once, fdmap_init_once);
}

void vclgo_fdmap_destroy(void)
{
    free(g_meta);  g_meta  = NULL;
    free(g_valid); g_valid = NULL;
}

int vclgo_fdmap_track(int fd, const vclgo_sock_meta_t *meta)
{
    if (!vclgo_fd_is_vcl(fd)) return -1;
    unsigned idx = (unsigned)vclgo_fd_to_vlsh(fd);
    if (idx >= TABLE_SIZE) return -1;

    pthread_mutex_lock(&g_lock);
    g_meta[idx]  = *meta;
    g_valid[idx] = 1;
    pthread_mutex_unlock(&g_lock);
    return 0;
}

int vclgo_fdmap_untrack(int fd)
{
    if (!vclgo_fd_is_vcl(fd)) return -1;
    unsigned idx = (unsigned)vclgo_fd_to_vlsh(fd);
    if (idx >= TABLE_SIZE) return -1;

    pthread_mutex_lock(&g_lock);
    int was_live = g_valid[idx];
    g_valid[idx] = 0;
    memset(&g_meta[idx], 0, sizeof(g_meta[idx]));
    pthread_mutex_unlock(&g_lock);
    return was_live ? 0 : -1;
}

int vclgo_fdmap_lookup(int fd, vclgo_sock_meta_t *out)
{
    if (!vclgo_fd_is_vcl(fd)) return -1;
    unsigned idx = (unsigned)vclgo_fd_to_vlsh(fd);
    if (idx >= TABLE_SIZE) return -1;

    pthread_mutex_lock(&g_lock);
    int ok = g_valid[idx];
    if (ok && out) *out = g_meta[idx];
    pthread_mutex_unlock(&g_lock);
    return ok ? 0 : -1;
}

int vclgo_fdmap_update(int fd, const vclgo_sock_meta_t *meta)
{
    if (!vclgo_fd_is_vcl(fd)) return -1;
    unsigned idx = (unsigned)vclgo_fd_to_vlsh(fd);
    if (idx >= TABLE_SIZE) return -1;

    pthread_mutex_lock(&g_lock);
    if (!g_valid[idx]) {
        pthread_mutex_unlock(&g_lock);
        return -1;
    }
    g_meta[idx] = *meta;
    pthread_mutex_unlock(&g_lock);
    return 0;
}
