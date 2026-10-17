#ifndef BLACKPILL_ADIANTUM_H
#define BLACKPILL_ADIANTUM_H
#include "vendor/primitives.h"

#define ADIANTUM_KEY_BYTES 32u
#define ADIANTUM_SECTOR_BYTES 512u
#define ADIANTUM_MAX_BYTES 4096u
#define ADIANTUM_MAX_TWEAK_BYTES 32u
/* Treat fields as private. Zero initialize before first use; clear after use.
 * Context must not alias any argument. Caller serializes init/clear/crypt.
 * No allocation, hardware access, authentication, or wrong-key detection. */
typedef struct {
    struct chacha_ctx stream;
    struct poly1305_key polyt, polym;
    uint32_t nh[268];
    uint32_t aes[120];
    uint32_t ready;
} adiantum_ctx;

/* 0 success; -1 invalid argument/state. Invalid crypt calls leave dst intact.
 * Source and destination can be identical or disjoint, never partially overlap.
 * Data length 16..4096; tweak length 0..32; NULL tweak only for zero length.
 * Buffers must actually hold their declared lengths. Byte alignment is enough
 * for key, tweak and data; ctx requires its natural alignment. */
int adiantum_init(adiantum_ctx *ctx, const uint8_t *key, size_t key_len);
void adiantum_clear(adiantum_ctx *ctx);
int adiantum_crypt(const adiantum_ctx *ctx, uint8_t *dst, size_t dst_size,
                   const uint8_t *src, size_t len, const uint8_t *tweak,
                   size_t tweak_len, int decrypt);
/* Tweak = uint64 little-endian logical LBA followed by 24 zero bytes. */
int adiantum_sector(const adiantum_ctx *ctx, uint8_t *dst, size_t dst_size,
                    const uint8_t *src, uint64_t lba, int decrypt);
#endif
