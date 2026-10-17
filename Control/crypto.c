#include "crypto.h"
#include "bearssl.h"
#include <string.h>
void bp_wipe(void *p,size_t n) { volatile uint8_t *b=p; while(n--) *b++=0; }
int bp_equal(const void *a,const void *b,size_t n) {
    const uint8_t *x=a,*y=b; unsigned d=0;
    for(size_t i=0;i<n;++i) d|=x[i]^y[i];
    return d==0;
}
void bp_sha(const void *p,size_t n,uint8_t out[32]) {
    br_sha256_context c; br_sha256_init(&c); br_sha256_update(&c,p,n);
    br_sha256_out(&c,out); bp_wipe(&c,sizeof(c));
}
void bp_mac(const uint8_t key[32],const char *label,const void *p,size_t n,uint8_t out[32]) {
    br_hmac_key_context k; br_hmac_context c;
    br_hmac_key_init(&k,&br_sha256_vtable,key,32); br_hmac_init(&c,&k,32);
    br_hmac_update(&c,label,strlen(label)); br_hmac_update(&c,p,n);
    br_hmac_out(&c,out); bp_wipe(&k,sizeof(k)); bp_wipe(&c,sizeof(c));
}
void bp_kdf(const void *salt,size_t sn,const void *ikm,size_t kn,const void *info,size_t in,void *out,size_t n) {
    br_hkdf_context c; br_hkdf_init(&c,&br_sha256_vtable,salt,sn);
    br_hkdf_inject(&c,ikm,kn); br_hkdf_flip(&c); br_hkdf_produce(&c,info,in,out,n);
    bp_wipe(&c,sizeof(c));
}
int bp_gcm(const uint8_t key[32],const uint8_t nonce[12],const void *aad,size_t an,
           void *data,size_t n,uint8_t tag[16],int decrypt) {
    br_aes_ct_ctr_keys k; br_gcm_context g; uint8_t actual[16]; int ok=1;
    br_aes_ct_ctr_init(&k,key,32); br_gcm_init(&g,&k.vtable,br_ghash_ctmul32);
    br_gcm_reset(&g,nonce,12); br_gcm_aad_inject(&g,aad,an); br_gcm_flip(&g);
    br_gcm_run(&g,!decrypt,data,n); br_gcm_get_tag(&g,actual);
    if(decrypt) { ok=bp_equal(actual,tag,16); if(!ok) bp_wipe(data,n); }
    else memcpy(tag,actual,16);
    bp_wipe(&k,sizeof(k)); bp_wipe(&g,sizeof(g)); bp_wipe(actual,sizeof(actual)); return ok;
}
