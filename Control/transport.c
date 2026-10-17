#include "transport.h"
#include <string.h>
void bp_transport_reset(bp_transport *t) {bp_wipe(t,sizeof(*t));}
static int discard(bp_transport *t) {bp_wipe(t->input,256);t->total=t->offset=0;t->ready=0;return 0;}
int bp_transport_receive(bp_transport *t,const uint8_t *r,size_t n,uint32_t now) {
    if(t->out_total||t->ready||t->processing) return 0;
    if(t->total&&(uint32_t)(now-t->started)>=1000) discard(t);
    if(n!=64||r[0]!=1||r[1]!=1)return discard(t);
    unsigned total=bp_u16(r+4),off=bp_u16(r+6),id=bp_u16(r+2);
    if(total<8||total>256||off>=total)return discard(t);
    if(!t->total) {if(off)return discard(t);t->total=total;t->id=id;t->started=now;}
    if(total!=t->total||id!=t->id||off!=t->offset)return discard(t);
    unsigned bytes=total-off;if(bytes>56)bytes=56;
    for(unsigned i=8+bytes;i<64;++i)if(r[i])return discard(t);
    memcpy(t->input+off,r+8,bytes);t->offset+=bytes;
    if(t->offset==t->total)t->ready=1;
    return 1;
}
size_t bp_transport_take(bp_transport *t,uint8_t out[256],unsigned *id,uint32_t now) {
    if(t->total&&(uint32_t)(now-t->started)>=1000)discard(t);
    if(!t->ready)return 0;
    size_t n=t->total;*id=t->id;memcpy(out,t->input,n);discard(t);t->processing=1;return n;
}
void bp_transport_publish(bp_transport *t,const uint8_t *p,size_t n,unsigned id) {
    if(n<8||n>256){t->processing=0;return;}
    memcpy(t->output,p,n);t->out_total=(unsigned)n;t->out_offset=0;t->out_id=id;
}
void bp_transport_get(bp_transport *t,uint8_t r[64]) {
    memset(r,0,64);r[0]=1;r[1]=1;
    if(!t->out_total)return;
    bp_put(r+2,t->out_id,2);bp_put(r+4,t->out_total,2);bp_put(r+6,t->out_offset,2);
    unsigned n=t->out_total-t->out_offset;if(n>56)n=56;
    memcpy(r+8,t->output+t->out_offset,n);t->out_offset+=n;
    if(t->out_offset==t->out_total){bp_wipe(t->output,256);t->out_total=t->out_offset=0;t->processing=0;}
}
