/* Local portable declarations for the trimmed MIT primitive sources. */
#ifndef ADIANTUM_PRIMITIVES_H
#define ADIANTUM_PRIMITIVES_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint32_t __le32;
typedef union { u8 bytes[16]; u32 w32[4]; } le128;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define BUILD_BUG_ON(c) ((void)sizeof(char[1-2*!!(c)]))
#define CHACHA_KEY_SIZE 32
#define CHACHA_BLOCK_SIZE 64
#define NH_PAIR_STRIDE 2
#define NH_NUM_PASSES 4
#define NH_MESSAGE_UNIT 16
#define POLY1305_BLOCK_SIZE 16
struct chacha_ctx { u32 key[8]; int nrounds; };
struct poly1305_key { u32 r[5]; };
struct poly1305_state { u32 h[5]; };
static inline void crypto_wipe(void *p, size_t n) {
    volatile u8 *v = (volatile u8 *)p;
    while (n--) *v++ = 0;
}
static inline u32 get_unaligned_le32(const void *p) {
    const u8 *b = (const u8 *)p;
    return (u32)b[0] | (u32)b[1]<<8 | (u32)b[2]<<16 | (u32)b[3]<<24;
}
static inline void put_unaligned_le32(u32 x, void *p) {
    u8 *b = (u8 *)p;
    for (unsigned i=0; i<4; ++i) b[i]=(u8)(x>>(8*i));
}
static inline void put_unaligned_le64(u64 x, void *p) {
    u8 *b = (u8 *)p;
    for (unsigned i=0; i<8; ++i) b[i]=(u8)(x>>(8*i));
}
static inline u32 rol32(u32 x, unsigned n) { return (x<<n)|(x>>(32-n)); }
static inline void xor(u8 *d, const u8 *s, const void *k, size_t n) {
    const u8 *b=(const u8 *)k;
    for (size_t i=0;i<n;++i) d[i]=s[i]^b[i];
}
#define br_dec32le get_unaligned_le32
void br_aes_ct_ortho(u32 *q);
void br_aes_ct_bitslice_Sbox(u32 *q);
unsigned br_aes_ct_keysched(u32 *sk, const void *key, size_t len);
void br_aes_ct_skey_expand(u32 *sk, unsigned rounds, const u32 *compact);
void br_aes_ct_bitslice_encrypt(unsigned rounds, const u32 *sk, u32 *q);
void br_aes_ct_bitslice_decrypt(unsigned rounds, const u32 *sk, u32 *q);
void chacha_setkey(struct chacha_ctx *, const u8 *, int);
void xchacha(const struct chacha_ctx *, u8 *, const u8 *, unsigned, const u8 *, bool);
void poly1305_setkey(struct poly1305_key *, const u8 *);
void poly1305_blocks_generic(const struct poly1305_key *, struct poly1305_state *, const u8 *, size_t, u32);
void poly1305_emit_generic(struct poly1305_state *, le128 *);
void nh_generic(const u32 *, const u8 *, size_t, u8 *);
#endif
