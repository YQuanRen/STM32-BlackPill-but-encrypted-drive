/* Adiantum-XChaCha12-AES256 glue, based on Google's MIT HBSH specification
 * and reference implementation. See vendor/LICENSE.Google and README.md. */
#include "adiantum.h"

#define READY UINT32_C(0x41444932)

static int overlaps(const void *a, size_t an, const void *b, size_t bn)
{
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    if (!an || !bn) return 0;
    return x <= y ? y - x < an : x - y < bn;
}

void adiantum_clear(adiantum_ctx *ctx)
{
    if (ctx) crypto_wipe(ctx, sizeof(*ctx));
}

int adiantum_init(adiantum_ctx *ctx, const uint8_t *key, size_t key_len)
{
    uint8_t material[1136] = {0}, iv[32] = {1};
    uint32_t compact[60];
    if (!ctx) return -1;
    if (!key || key_len != 32 || overlaps(ctx, sizeof(*ctx), key, key_len)) {
        adiantum_clear(ctx);
        return -1;
    }
    adiantum_clear(ctx);
    chacha_setkey(&ctx->stream, key, 12);
    xchacha(&ctx->stream, material, material, sizeof(material), iv, false);
    br_aes_ct_keysched(compact, material, 32);
    br_aes_ct_skey_expand(ctx->aes, 14, compact);
    poly1305_setkey(&ctx->polyt, material + 32);
    poly1305_setkey(&ctx->polym, material + 48);
    for (unsigned i = 0; i < 268; ++i)
        ctx->nh[i] = get_unaligned_le32(material + 64 + i * 4);
    ctx->ready = READY;
    crypto_wipe(material, sizeof(material));
    crypto_wipe(compact, sizeof(compact));
    return 0;
}

/* Addition/subtraction in Z/(2^128), with no data-dependent branches. */
static void add128(uint8_t a[16], const uint8_t b[16], int subtract)
{
    unsigned carry = (unsigned)subtract;
    unsigned mask = 0u - (unsigned)subtract;
    for (unsigned i = 0; i < 16; ++i) {
        carry += a[i] + ((b[i] ^ mask) & 255u);
        a[i] = (uint8_t)carry;
        carry >>= 8;
    }
}

static void poly_tail(const struct poly1305_key *key,
                      struct poly1305_state *s, const uint8_t *p, size_t n)
{
    uint8_t tail[16] = {0};
    poly1305_blocks_generic(key, s, p, n / 16, 1u << 24);
    if (n % 16) {
        memcpy(tail, p + n - n % 16, n % 16);
        tail[n % 16] = 1;
        poly1305_blocks_generic(key, s, tail, 1, 0);
    }
    crypto_wipe(tail, sizeof(tail));
}

static void header_hash(const adiantum_ctx *ctx, const uint8_t *t, size_t tn,
                        size_t n, le128 *out)
{
    struct poly1305_state s = {{0}};
    uint8_t header[16] = {0};
    put_unaligned_le64((uint64_t)n * 8, header);
    poly_tail(&ctx->polyt, &s, header, sizeof(header));
    poly_tail(&ctx->polyt, &s, t, tn);
    poly1305_emit_generic(&s, out);
    crypto_wipe(&s, sizeof(s));
}

static void message_hash(const adiantum_ctx *ctx, const uint8_t *p, size_t n,
                         const le128 *header, le128 *out)
{
    struct poly1305_state s = {{0}};
    uint8_t nhout[32], part[16];
    /* NH resets its key offset every 1024 bytes; each output is 32 bytes. */
    while (n) {
        size_t chunk = n > 1024 ? 1024 : n;
        size_t full = chunk - chunk % 16;
        memset(nhout, 0, sizeof(nhout));
        if (full) nh_generic(ctx->nh, p, full, nhout);
        if (chunk % 16) {
            uint8_t extra[32];
            memset(part, 0, sizeof(part));
            memcpy(part, p + full, chunk % 16);
            nh_generic(ctx->nh + full / 4, part, 16, extra);
            for (unsigned j = 0; j < 4; ++j) {
                uint64_t a = get_unaligned_le32(nhout + 8*j) |
                    (uint64_t)get_unaligned_le32(nhout + 8*j + 4) << 32;
                uint64_t b = get_unaligned_le32(extra + 8*j) |
                    (uint64_t)get_unaligned_le32(extra + 8*j + 4) << 32;
                put_unaligned_le64(a + b, nhout + 8*j);
            }
            crypto_wipe(extra, sizeof(extra));
        }
        poly_tail(&ctx->polym, &s, nhout, sizeof(nhout));
        p += chunk;
        n -= chunk;
    }
    poly1305_emit_generic(&s, out);
    add128(out->bytes, header->bytes, 0);
    crypto_wipe(&s, sizeof(s));
    crypto_wipe(nhout, sizeof(nhout));
    crypto_wipe(part, sizeof(part));
}

static void aes_block(const adiantum_ctx *ctx, uint8_t b[16], int decrypt)
{
    uint32_t q[8] = {0};
    for (unsigned i = 0; i < 4; ++i) q[2*i] = get_unaligned_le32(b + 4*i);
    br_aes_ct_ortho(q);
    if (decrypt) br_aes_ct_bitslice_decrypt(14, ctx->aes, q);
    else br_aes_ct_bitslice_encrypt(14, ctx->aes, q);
    br_aes_ct_ortho(q);
    for (unsigned i = 0; i < 4; ++i) put_unaligned_le32(q[2*i], b + 4*i);
    crypto_wipe(q, sizeof(q));
}

int adiantum_crypt(const adiantum_ctx *ctx, uint8_t *dst, size_t dst_size,
                   const uint8_t *src, size_t len, const uint8_t *tweak,
                   size_t tweak_len, int decrypt)
{
    le128 header, digest;
    uint8_t iv[32] = {0};
    size_t bulk;
    if (!ctx || !dst || !src || (!tweak && tweak_len) ||
        len < 16 || len > ADIANTUM_MAX_BYTES || dst_size < len ||
        tweak_len > ADIANTUM_MAX_TWEAK_BYTES || (decrypt != 0 && decrypt != 1) ||
        ctx->ready != READY ||
        (dst != src && overlaps(dst, len, src, len)) ||
        overlaps(ctx, sizeof(*ctx), dst, len) ||
        overlaps(ctx, sizeof(*ctx), src, len) ||
        overlaps(ctx, sizeof(*ctx), tweak, tweak_len) ||
        overlaps(dst, len, tweak, tweak_len)) return -1;
    bulk = len - 16;
    header_hash(ctx, tweak, tweak_len, bulk, &header);
    message_hash(ctx, src, bulk, &header, &digest);
    memcpy(iv, src + bulk, 16);
    add128(iv, digest.bytes, 0);
    iv[16] = 1;
    if (!decrypt) aes_block(ctx, iv, 0);
    xchacha(&ctx->stream, dst, src, (unsigned)bulk, iv, false);
    if (decrypt) aes_block(ctx, iv, 1);
    message_hash(ctx, dst, bulk, &header, &digest);
    add128(iv, digest.bytes, 1);
    memcpy(dst + bulk, iv, 16);
    crypto_wipe(iv, sizeof(iv));
    crypto_wipe(&header, sizeof(header));
    crypto_wipe(&digest, sizeof(digest));
    return 0;
}

int adiantum_sector(const adiantum_ctx *ctx, uint8_t *dst, size_t dst_size,
                    const uint8_t *src, uint64_t lba, int decrypt)
{
    uint8_t tweak[32] = {0};
    put_unaligned_le64(lba, tweak);
    return adiantum_crypt(ctx, dst, dst_size, src, 512, tweak, 32, decrypt);
}
