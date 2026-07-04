/*
 * dedup.c — FNV-1a hash dedup table with atomic spinlock per bucket
 */
#include <string.h>
#include <time.h>
#include <stdatomic.h>
#include "obd.h"

#define PROBE_LIMIT 8

typedef struct {
    char     request_id[128];
    time_t   expires;
} DedupEntry;

typedef struct {
    DedupEntry      entries[PROBE_LIMIT];
    atomic_flag     lock;
} DedupBucket;

static DedupBucket g_dedup[OBD_DEDUP_BUCKETS];

/* FNV-1a hash */
static uint32_t fnv1a(const char *s)
{
    uint32_t h = 2166136261u;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 16777619u;
    }
    return h;
}

void dedup_init(void)
{
    memset(g_dedup, 0, sizeof(g_dedup));
    for (int i = 0; i < OBD_DEDUP_BUCKETS; i++)
        atomic_flag_clear(&g_dedup[i].lock);
}

/* Returns 1 if duplicate (already seen), 0 if new (and sets it) */
int dedup_check_and_set(const char *request_id)
{
    uint32_t idx = fnv1a(request_id) & (OBD_DEDUP_BUCKETS - 1);
    DedupBucket *b = &g_dedup[idx];
    time_t now = time(NULL);

    /* Spinlock acquire */
    while (atomic_flag_test_and_set_explicit(&b->lock, memory_order_acquire))
        ;

    int found = 0;
    int free_slot = -1;

    for (int i = 0; i < PROBE_LIMIT; i++) {
        if (b->entries[i].request_id[0] == '\0' || b->entries[i].expires <= now) {
            if (free_slot < 0) free_slot = i;
            if (b->entries[i].request_id[0] == '\0') continue;
            /* Expired — clear it */
            if (b->entries[i].expires <= now) {
                b->entries[i].request_id[0] = '\0';
                if (free_slot < 0) free_slot = i;
                continue;
            }
        }
        if (strcmp(b->entries[i].request_id, request_id) == 0) {
            found = 1;
            break;
        }
    }

    if (!found && free_slot >= 0) {
        strncpy(b->entries[free_slot].request_id, request_id,
                sizeof(b->entries[free_slot].request_id) - 1);
        b->entries[free_slot].expires = now + OBD_DEDUP_TTL_SEC;
    }

    /* Spinlock release */
    atomic_flag_clear_explicit(&b->lock, memory_order_release);

    return found;
}

void dedup_cleanup(void)
{
    /* Nothing to free — static allocation */
}
