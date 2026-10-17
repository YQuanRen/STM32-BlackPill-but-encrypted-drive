#include "adiantum.h"
/* Force archive members into the host test DLL. No test code in firmware. */
size_t test_context_size(void) { return sizeof(adiantum_ctx); }
int test_init(adiantum_ctx *c, const uint8_t *k, size_t n)
{ return adiantum_init(c, k, n); }
void test_clear(adiantum_ctx *c) { adiantum_clear(c); }
int test_crypt(const adiantum_ctx *c, uint8_t *d, size_t cap,
               const uint8_t *s, size_t n, const uint8_t *t, size_t tn, int dec)
{ return adiantum_crypt(c,d,cap,s,n,t,tn,dec); }
int test_sector(const adiantum_ctx *c, uint8_t *d, size_t cap,
                const uint8_t *s, uint64_t lba, int dec)
{ return adiantum_sector(c,d,cap,s,lba,dec); }
