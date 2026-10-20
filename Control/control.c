#include "control.h"
#include <string.h>
#define T_LEN 73u
static void end_session(bp_control *c) {
    if(c->clear_user&&!c->media)c->clear_user(c->user);
    bp_wipe(c->transcript,sizeof(c->transcript)); bp_wipe(c->in_key,32); bp_wipe(c->out_key,32);
    c->pending=c->session=0; c->rx=c->tx=0;
}
void bp_control_init(bp_control *c,bp_journal *j,bp_authorize_fn f,void *u) {
    memset(c,0,sizeof(*c)); c->journal=j;c->authorize=f;c->user=u;
}
void bp_control_reset(bp_control *c) {
    end_session(c);c->media=0;if(c->clear_user)c->clear_user(c->user);
}
void bp_control_tick(bp_control *c,uint32_t now) {
    if(c->session&&(uint32_t)(now-c->activity)>=60000)end_session(c);
}
static size_t reply(uint8_t *out,const uint8_t *in,int status,const void *data,size_t n) {
    memcpy(out,in,8); out[0]=1;out[1]|=128;bp_put(out+6,n+1,2);out[8]=(uint8_t)status;
    if(n) memcpy(out+9,data,n);
    return n+9;
}
size_t bp_control_request(bp_control *c,const uint8_t *in,size_t len,uint8_t out[256],uint32_t now) {
    uint8_t tmp[160]={0},tag[32],nonce[12]={0},salt[32]; size_t result=0;
    bp_journal *j=c->journal;
    if(!in||!out||len<8||len>256) return 0;
    if(in[0]!=1||in[1]&128||bp_u16(in+6)!=len-8) return reply(out,in,BP_FORMAT,0,0);
    unsigned cmd=in[1];const uint8_t *p=in+8;size_t n=len-8;
    bp_control_tick(c,now);
    if(cmd==1) {
        if(n) return reply(out,in,BP_FORMAT,0,0);
        memcpy(tmp,j->identity,16);tmp[16]=(uint8_t)j->state;tmp[17]=(uint8_t)j->mode;bp_put(tmp+18,j->epoch,8);
        return reply(out,in,BP_OK,tmp,26);
    }
    if(j->state==2) return reply(out,in,BP_FAULT,0,0);
    if(cmd==2) {
        if(n!=49||!bp_equal(p,j->identity,16)||(p[16]!=1&&p[16]!=2)) return reply(out,in,BP_FORMAT,0,0);
        if(j->state!=0) return reply(out,in,BP_STATE,0,0);
        if(!bp_journal_enroll(j,p[16],p+17)) return reply(out,in,BP_FAULT,0,0);
        bp_mac(j->auth,"BP1/enrolled",p,17,tag);
        result=reply(out,in,BP_OK,tag,32);goto done;
    }
    if(j->state!=1) return reply(out,in,BP_STATE,0,0);
    if(cmd==3) {
        if(c->media) return reply(out,in,BP_STATE,0,0);
        end_session(c);
        if(n!=33||(p[0]!=1&&p[0]!=2)) return reply(out,in,BP_FORMAT,0,0);
        if(c->challenge_counter==UINT64_MAX) return reply(out,in,BP_FAULT,0,0);
        c->challenge_counter++;c->operation=p[0];c->started=now;c->pending=1;
        memcpy(c->transcript,"BP1",3);memcpy(c->transcript+3,j->identity,16);
        c->transcript[19]=(uint8_t)j->mode;c->transcript[20]=p[0];
        bp_put(c->transcript+21,j->epoch,8);bp_put(c->transcript+29,c->challenge_counter,8);
        memcpy(c->transcript+37,p+1,32);memcpy(c->transcript+69,in+2,4);
        bp_mac(j->auth,"BP1/challenge",c->transcript,T_LEN,c->transcript+T_LEN);
        memcpy(tmp,c->transcript+21,16);memcpy(tmp+16,c->transcript+T_LEN,32);
        return reply(out,in,BP_OK,tmp,48);
    }
    if(cmd==4) {
        int pending=c->pending;c->pending=0;
        if(!pending) return reply(out,in,BP_STATE,0,0);
        if((uint32_t)(now-c->started)>=10000) {end_session(c);return reply(out,in,BP_EXPIRED,0,0);}
        bp_mac(j->auth,"BP1/host",c->transcript,T_LEN+32,tag);
        if(n!=32||!bp_equal(tag,p,32)) {end_session(c);result=reply(out,in,BP_AUTH,0,0);goto done;}
        memcpy(c->transcript+T_LEN+32,p,32);
        bp_mac(j->auth,"BP1/device",c->transcript,sizeof(c->transcript),tag);
        bp_sha(c->transcript,sizeof(c->transcript),salt);
        bp_kdf(salt,32,j->auth,32,"BP1/host-to-device",18,c->in_key,32);
        bp_kdf(salt,32,j->auth,32,"BP1/device-to-host",18,c->out_key,32);
        c->session=1;c->activity=now;
        result=reply(out,in,BP_OK,tag,32);bp_wipe(c->transcript,sizeof(c->transcript));goto done;
    }
    if(cmd==5) {
        if(!c->session) return reply(out,in,BP_STATE,0,0);
        if(n<25||n>sizeof(tmp)+24||bp_u64(p)!=c->rx||c->rx==UINT64_MAX||c->tx==UINT64_MAX) {
            end_session(c);return reply(out,in,BP_AUTH,0,0);
        }
        size_t plain=n-24;memcpy(tmp,p+8,plain);memcpy(tag,p+8+plain,16);memcpy(nonce+4,p,8);
        if(!bp_gcm(c->in_key,nonce,in,16,tmp,plain,tag,1)) {
            end_session(c);result=reply(out,in,BP_AUTH,0,0);goto done;
        }
        c->rx++;c->activity=now;int status=BP_UNSUPPORTED;size_t rn=1;unsigned op=tmp[0];
        if(op==1&&plain==1) {status=BP_OK;memcpy(tmp+1,"BP1",3);rn=4;}
        else if((op==2&&plain==1&&j->mode==1)||(op==3&&plain==33&&j->mode==2)) {
            if(c->operation!=1||c->media) status=BP_STATE;
            else {status=c->authorize?c->authorize(c->user,j->mode,op==3?tmp+1:NULL):BP_UNSUPPORTED;
                  if(status==BP_OK)c->media=1;}
        } else if(op>=4&&op<=7&&c->storage) {
            if(c->media)status=BP_STATE;
            else {
                uint8_t response[128];size_t response_n=0;
                status=c->storage(c->user,c->operation,tmp,plain,response,&response_n);
                if(response_n>sizeof(response)){status=BP_FORMAT;response_n=0;}
                memcpy(tmp+1,response,response_n);rn=1+response_n;bp_wipe(response,sizeof(response));
            }
        } else if(op==4) status=c->operation==2?BP_UNSUPPORTED:BP_STATE;
        else status=BP_FORMAT;
        bp_wipe(tmp+rn,sizeof(tmp)-rn);tmp[0]=(uint8_t)status;
        memcpy(out,in,8);out[1]|=128;bp_put(out+6,rn+24,2);bp_put(out+8,c->tx,8);
        memcpy(nonce+4,out+8,8);memcpy(out+16,tmp,rn);
        bp_gcm(c->out_key,nonce,out,16,out+16,rn,out+16+rn,0);
        c->tx++;result=rn+32;goto done;
    }
    return reply(out,in,BP_UNSUPPORTED,0,0);
done:
    bp_wipe(tmp,sizeof(tmp));bp_wipe(tag,sizeof(tag));bp_wipe(salt,sizeof(salt));bp_wipe(nonce,sizeof(nonce));return result;
}
