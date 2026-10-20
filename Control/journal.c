#include "journal.h"
#include <string.h>
static int erased(const uint8_t *p,size_t n) { while(n--) if(*p++!=255) return 0; return 1; }
static int fault(bp_journal *j) { j->state=2; bp_wipe(j->auth,32); return 0; }
static int append(bp_journal *j) {
    uint8_t r[128]={0},check[128]; unsigned bank=j->bank,slot=j->next;
    if(j->epoch==UINT64_MAX) return fault(j);
    if(slot>=BP_BANK_SIZE/128) {
        bank^=1; slot=0;
        if(!j->io.erase(j->io.user,bank)) return fault(j);
        for(unsigned off=0;off<BP_BANK_SIZE;off+=128)
            if(!j->io.read(j->io.user,bank,off,check,128)||!erased(check,128)) return fault(j);
    }
    memcpy(r,"BPJ1",4); bp_put(r+4,2,4); memcpy(r+8,j->identity,16);
    memcpy(r+24,j->auth,32); bp_put(r+56,j->mode,4); bp_put(r+60,j->epoch+1,8);
    memcpy(r+68,j->volume,16);
    bp_sha(r,92,r+92); memset(r+124,255,4);
    int ok=j->io.program(j->io.user,bank,slot*128,r,124);
    if(ok) ok=j->io.read(j->io.user,bank,slot*128,check,128)&&bp_equal(r,check,128);
    memset(r+124,0,4);
    if(ok) ok=j->io.program(j->io.user,bank,slot*128+124,r+124,4);
    if(ok) ok=j->io.read(j->io.user,bank,slot*128,check,128)&&bp_equal(r,check,128);
    bp_wipe(r,sizeof(r)); bp_wipe(check,sizeof(check));
    if(!ok) return fault(j);
    j->bank=bank; j->next=slot+1; j->epoch++; j->state=1; return 1;
}
int bp_journal_boot(bp_journal *j,const bp_flash *io,const uint8_t id[16]) {
    uint8_t r[128],hash[32]; unsigned next[2]={0}; int nonempty=0,found=0;
    memset(j,0,sizeof(*j)); j->io=*io; memcpy(j->identity,id,16);
    for(unsigned bank=0;bank<2;++bank) for(unsigned slot=0;slot<BP_BANK_SIZE/128;++slot) {
        if(!io->read(io->user,bank,slot*128,r,128)) return fault(j);
        if(erased(r,128)) continue;
        nonempty=1; next[bank]=slot+1;
        if(erased(r+124,4)) continue; /* Interrupted pre-commit record, never reused. */
        bp_sha(r,92,hash);
        unsigned version=bp_u32(r+4);
        if(bp_u32(r+124)!=0||memcmp(r,"BPJ1",4)||(version!=1&&version!=2)||
           !bp_equal(r+8,id,16)||!bp_equal(hash,r+92,32)||
           (bp_u32(r+56)!=1&&bp_u32(r+56)!=2)||bp_u64(r+60)==0) return fault(j);
        for(unsigned i=version==1?68:84;i<92;++i) if(r[i]) return fault(j);
        if(found && !bp_equal(j->auth,r+24,32)) return fault(j);
        if(found && j->epoch==bp_u64(r+60)) return fault(j);
        if(!found||bp_u64(r+60)>j->epoch) {
            found=1; j->epoch=bp_u64(r+60); j->mode=bp_u32(r+56);
            j->bank=bank; memcpy(j->auth,r+24,32);
            memcpy(j->volume,r+68,16);
        }
    }
    bp_wipe(r,sizeof(r)); bp_wipe(hash,sizeof(hash));
    if(!found) { if(nonempty) return fault(j); return 1; }
    j->next=next[j->bank]; j->state=1; return append(j);
}
int bp_journal_bind(bp_journal *j,unsigned mode,const uint8_t volume[16]) {
    uint8_t zero[16]={0};
    if(j->state!=1||(mode!=1&&mode!=2)||bp_equal(volume,zero,16)||bp_equal(volume,j->volume,16))return 0;
    j->mode=mode;memcpy(j->volume,volume,16);return append(j);
}
int bp_journal_enroll(bp_journal *j,unsigned mode,const uint8_t auth[32]) {
    if(j->state!=0||(mode!=1&&mode!=2)) return 0;
    j->mode=mode; memcpy(j->auth,auth,32); return append(j);
}
