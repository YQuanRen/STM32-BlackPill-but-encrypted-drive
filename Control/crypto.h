#ifndef BP_CONTROL_CRYPTO_H
#define BP_CONTROL_CRYPTO_H
#include <stddef.h>
#include <stdint.h>
void bp_wipe(void *, size_t);
int bp_equal(const void *, const void *, size_t);
void bp_sha(const void *, size_t, uint8_t[32]);
void bp_mac(const uint8_t[32], const char *, const void *, size_t, uint8_t[32]);
void bp_kdf(const void *, size_t, const void *, size_t, const void *, size_t, void *, size_t);
/* Decryption failure wipes plaintext. Caller must not act before success. */
int bp_gcm(const uint8_t[32], const uint8_t[12], const void *, size_t,
           void *, size_t, uint8_t[16], int);
static inline uint32_t bp_u32(const uint8_t *p) {
    return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;
}
static inline uint64_t bp_u64(const uint8_t *p) { return bp_u32(p)|(uint64_t)bp_u32(p+4)<<32; }
static inline unsigned bp_u16(const uint8_t *p) { return p[0]|(unsigned)p[1]<<8; }
static inline void bp_put(uint8_t *p, uint64_t v, unsigned n) {
    for (unsigned i=0;i<n;++i) p[i]=(uint8_t)(v>>(8*i));
}
#endif
