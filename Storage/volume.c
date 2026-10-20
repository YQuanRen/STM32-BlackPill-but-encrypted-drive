#include "volume.h"
#include <string.h>

static int zero(const uint8_t *p,size_t n) {unsigned x=0;while(n--)x|=*p++;return x==0;}
static int fail(bp_volume *v,int code) {
    adiantum_clear(&v->cipher);bp_wipe(v->stage,sizeof(v->stage));v->staged=0;
    bp_wipe(v->scratch,512);bp_wipe(v->verify,512);v->unlocked=0;v->state=3;return code;
}
void bp_volume_init(bp_volume *v,bp_journal *j,const bp_disk *io) {
    memset(v,0,sizeof(*v));v->io=*io;v->journal=j;
}
void bp_volume_reset(bp_volume *v) {
    fail(v,BP_OK);bp_wipe(v->header,256);v->state=0;v->done=v->physical=v->mode=0;
}
static int describe(bp_volume *v,uint8_t cid[16],uint32_t *count) {
    return v->io.describe(v->io.user,cid,count)&&*count>16;
}
static void tag(bp_volume *v,uint8_t h[256]) {bp_mac(v->journal->auth,"BP1/header",h,224,h+224);}
static void aad(const uint8_t h[256],uint8_t out[124]) {memcpy(out,h,12);memcpy(out+12,h+16,112);}
static int key_ok(const uint8_t h[256],const uint8_t key[32]) {
    uint8_t a[124],t[32];aad(h,a);bp_mac(key,"BP1/data-check",a,124,t);
    int ok=bp_equal(t,h+176,32);bp_wipe(t,32);return ok;
}
static int valid(bp_volume *v,const uint8_t h[256],int proposal) {
    uint8_t mac[32],cid[16];uint32_t physical;
    bp_mac(v->journal->auth,"BP1/header",h,224,mac);
    if(!bp_equal(mac,h+224,32))return BP_HEADER;
    unsigned mode=bp_u32(h+80),state=bp_u32(h+12);
    if(memcmp(h,"BPVOL001",8)||bp_u32(h+8)!=1||
       !bp_equal(h+16,v->journal->identity,16)||zero(h+32,16)||
       (mode!=1&&mode!=2)||bp_u32(h+84)!=512||!zero(h+208,16)||
       (state!=1&&state!=2))return BP_HEADER;
    if(!describe(v,cid,&physical))return BP_IO;
    if(!bp_equal(cid,h+48,16)||bp_u64(h+64)!=physical||bp_u64(h+72)!=physical-16)return BP_HEADER;
    if(mode==1) {if(!zero(h+88,120))return BP_HEADER;}
    else if(bp_u32(h+88)!=65536||bp_u32(h+92)!=3||bp_u32(h+96)!=1)return BP_HEADER;
    if(proposal) {
        if(state!=1||bp_equal(h+32,v->journal->volume,16))return BP_STATE;
    } else if(state!=2||mode!=v->journal->mode||!bp_equal(h+32,v->journal->volume,16))return BP_HEADER;
    return BP_OK;
}
int bp_volume_load(bp_volume *v) {
    if(v->unlocked||v->state==1)return BP_BUSY;
    if(v->journal->state!=1)return BP_STATE;
    for(unsigned i=0;i<16;++i) {
        if(!v->io.read(v->io.user,i,v->scratch))return fail(v,BP_IO);
        if(i==0)memcpy(v->header,v->scratch,256);
        if(i%8==0) {
            if(!bp_equal(v->header,v->scratch,256)||!zero(v->scratch+256,256))return fail(v,BP_HEADER);
        } else if(!zero(v->scratch,512))return fail(v,BP_HEADER);
    }
    int status=valid(v,v->header,0);if(status)return fail(v,status);
    v->physical=(uint32_t)bp_u64(v->header+64);v->mode=bp_u32(v->header+80);v->state=2;
    return BP_OK;
}
static int same_card(bp_volume *v) {
    uint8_t cid[16];uint32_t n;
    if(!describe(v,cid,&n)||n!=v->physical||!bp_equal(cid,v->header+48,16))return fail(v,BP_IO);
    return BP_OK;
}
static int write_verified(bp_volume *v,uint32_t lba,const uint8_t *data) {
    if(!v->io.write(v->io.user,lba,data)||!v->io.read(v->io.user,lba,v->verify)||
       !bp_equal(data,v->verify,512))return fail(v,BP_IO);
    return BP_OK;
}
static int headers_write(bp_volume *v,unsigned state) {
    bp_put(v->header+12,state,4);tag(v,v->header);
    /* Verify all padding first; the two state-bearing sectors commit last. */
    static const uint8_t order[16]={1,2,3,4,5,6,7,9,10,11,12,13,14,15,0,8};
    for(unsigned k=0;k<16;++k) {
        unsigned i=order[k];
        memset(v->scratch,0,512);if(i%8==0)memcpy(v->scratch,v->header,256);
        if(same_card(v)||write_verified(v,i,v->scratch))return BP_IO;
    }
    return BP_OK;
}
int bp_volume_authorize(void *user,unsigned mode,const uint8_t *key) {
    bp_volume *v=user;int status=bp_volume_load(v);if(status)return status;
    if(mode!=v->mode)return BP_STATE;
    if(mode==2) {
        if(!key||!key_ok(v->header,key))return BP_AUTH;
        if(adiantum_init(&v->cipher,key,32))return fail(v,BP_AUTH);
    }
    v->unlocked=1;return BP_OK;
}
int bp_volume_command(void *user,unsigned operation,const uint8_t *p,size_t n,uint8_t *out,size_t *outn) {
    bp_volume *v=user;*outn=0;
    if(!n)return BP_FORMAT;
    if(v->unlocked)return BP_STATE;
    if(p[0]==4) {
        if(operation!=2)return BP_STATE;
        if(v->state==1)return BP_BUSY;
        if(n<4||n>131||bp_u16(p+1)!=v->staged||n-3>288-v->staged) {
            bp_wipe(v->stage,288);v->staged=0;return BP_FORMAT;
        }
        memcpy(v->stage+v->staged,p+3,n-3);v->staged+=(unsigned)n-3;return BP_OK;
    }
    if(p[0]==5) {
        if(operation!=2)return BP_STATE;
        if(n!=1||v->staged!=288)return BP_FORMAT;
        if(v->state==1)return BP_BUSY;
        int status=valid(v,v->stage,1);if(status)return fail(v,status);
        unsigned mode=bp_u32(v->stage+80);
        if((mode==2&&!key_ok(v->stage,v->stage+256))||(mode==1&&!zero(v->stage+256,32)))return fail(v,BP_AUTH);
        if(!bp_journal_bind(v->journal,mode,v->stage+32))return fail(v,BP_FAULT);
        memcpy(v->header,v->stage,256);v->mode=mode;v->physical=(uint32_t)bp_u64(v->header+64);
        if(mode==2&&adiantum_init(&v->cipher,v->stage+256,32))return fail(v,BP_AUTH);
        bp_wipe(v->stage,288);v->staged=0;v->done=0;v->state=1;
        return headers_write(v,1);
    }
    if(p[0]==6) {
        if(n!=1)return BP_FORMAT;
        uint8_t cid[16];uint32_t physical;
        if(!describe(v,cid,&physical))return fail(v,BP_IO);
        if(v->state==1&&same_card(v))return BP_IO;
        out[0]=(uint8_t)v->state;out[1]=(uint8_t)v->mode;bp_put(out+2,v->done,4);
        bp_put(out+6,physical-16,4);memcpy(out+10,cid,16);bp_put(out+26,physical,4);*outn=30;return BP_OK;
    }
    if(p[0]==7) {
        if(n!=4||!p[3]||p[3]>128||bp_u16(p+1)>256u-p[3])return BP_FORMAT;
        int status=bp_volume_load(v);if(status)return status;
        memcpy(out,v->header+bp_u16(p+1),p[3]);*outn=p[3];return BP_OK;
    }
    return BP_FORMAT;
}
void bp_volume_step(bp_volume *v) {
    if(v->state!=1)return;
    if(same_card(v))return;
    if(v->done<v->physical-16) {
        memset(v->scratch,0,512);
        if(v->mode==2&&adiantum_sector(&v->cipher,v->scratch,512,v->scratch,v->done,0)) {fail(v,BP_AUTH);return;}
        if(write_verified(v,v->done+16,v->scratch))return;
        v->done++;return;
    }
    if(headers_write(v,2))return;
    adiantum_clear(&v->cipher);bp_wipe(v->scratch,512);bp_wipe(v->verify,512);v->state=2;
}
int bp_volume_ready(bp_volume *v) {return v->unlocked&&v->state==2&&same_card(v)==BP_OK;}
static int bounds(bp_volume *v,uint32_t lba,uint32_t n) {
    return n&&n<=SIZE_MAX/512&&v->physical>16&&lba<v->physical-16&&n<=v->physical-16-lba;
}
int bp_volume_read(bp_volume *v,uint32_t lba,uint8_t *dst,uint32_t n) {
    if(!dst||!bounds(v,lba,n)||!bp_volume_ready(v))return 0;
    for(uint32_t i=0;i<n;++i) {
        if(!v->io.read(v->io.user,lba+i+16,v->scratch)) {fail(v,BP_IO);return 0;}
        if(v->mode==2) {
            if(adiantum_sector(&v->cipher,dst,512,v->scratch,lba+i,1)){fail(v,BP_AUTH);return 0;}
        } else memcpy(dst,v->scratch,512);
        dst+=512;
    }
    bp_wipe(v->scratch,512);return 1;
}
int bp_volume_write(bp_volume *v,uint32_t lba,const uint8_t *src,uint32_t n) {
    if(!src||!bounds(v,lba,n)||!bp_volume_ready(v))return 0;
    for(uint32_t i=0;i<n;++i) {
        if(v->mode==2) {
            if(adiantum_sector(&v->cipher,v->scratch,512,src,lba+i,0)){fail(v,BP_AUTH);return 0;}
        } else memcpy(v->scratch,src,512);
        if(!v->io.write(v->io.user,lba+i+16,v->scratch)) {fail(v,BP_IO);return 0;}
        src+=512;
    }
    bp_wipe(v->scratch,512);return 1;
}
