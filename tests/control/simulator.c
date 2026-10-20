#include "control.h"
#include "transport.h"
#include "usbd_storage_if.h"
#include <string.h>
static uint8_t flash[2][BP_BANK_SIZE];
static bp_journal j;
static bp_control c;
static bp_transport t;
static uint8_t identity[16]={1,2,3,4,5,6,7,8,9,10,11,12,0,0,0,0};
static int cut=-1,erase_cut=-1,allow,raw_calls,sd_fail;
static uint32_t now;
static int read_flash(void *u,unsigned b,size_t o,void *p,size_t n) {
    (void)u;memcpy(p,flash[b]+o,n);return 1;
}
static int program(void *u,unsigned b,size_t o,const void *p,size_t n) {
    (void)u;const uint8_t *v=p;
    for(size_t i=0;i<n;++i) {
        if(cut==0)return 0;
        if((flash[b][o+i]&v[i])!=v[i])return 0;
        flash[b][o+i]&=v[i];if(cut>0)cut--;
    }
    return 1;
}
static int erase(void *u,unsigned b) {
    (void)u;
    if(erase_cut>=0){memset(flash[b],255,(unsigned)erase_cut);return 0;}
    memset(flash[b],255,BP_BANK_SIZE);return 1;
}
static int authorize(void *u,unsigned mode,const uint8_t *key) {
    (void)u;if(!allow)return BP_UNSUPPORTED;
    if(mode==2){uint8_t expected[32];memset(expected,0x42,32);return key&&bp_equal(key,expected,32)?BP_OK:BP_AUTH;}
    return BP_OK;
}
int sim_boot(void) {
    bp_flash io={NULL,read_flash,program,erase};
    int r=bp_journal_boot(&j,&io,identity);bp_control_init(&c,&j,authorize,NULL);
    bp_transport_reset(&t);return r;
}
void sim_fresh(void) {memset(flash,255,sizeof(flash));cut=erase_cut=-1;allow=sd_fail=raw_calls=0;now=0;sim_boot();}
void sim_cut(int n) {cut=n;}
void sim_erase_cut(int n) {erase_cut=n;}
void sim_snapshot(void *p) {memcpy(p,flash,sizeof(flash));}
void sim_restore(const void *p) {memcpy(flash,p,sizeof(flash));cut=erase_cut=-1;}
void sim_corrupt(unsigned off,uint8_t v) {if(off<sizeof(flash))((uint8_t *)flash)[off]^=v;}
void sim_allow(int n) {allow=n;}
void sim_sd_fail(int n) {sd_fail=n;}
void sim_time(uint32_t n) {now=n;}
void sim_counter(uint64_t n) {c.challenge_counter=n;}
void sim_counts(uint64_t rx,uint64_t tx) {c.rx=rx;c.tx=tx;}
void sim_reset(void) {bp_control_reset(&c);bp_transport_reset(&t);}
int sim_clean(void) {
    uint8_t zero[137]={0};return !c.session&&!c.pending&&!c.media&&bp_equal(c.transcript,zero,137)&&bp_equal(c.in_key,zero,32)&&bp_equal(c.out_key,zero,32);
}
int sim_state(void) {return j.state;}
uint64_t sim_epoch(void) {return j.epoch;}
size_t sim_request(const uint8_t *in,size_t n,uint8_t *out) {return bp_control_request(&c,in,n,out,now);}
int sim_receive(const uint8_t *p,size_t n) {return bp_transport_receive(&t,p,n,now);}
void sim_get(uint8_t *r) {bp_transport_get(&t,r);}
void sim_task(void) {
    uint8_t in[256],out[256];unsigned id;
    size_t n=bp_transport_take(&t,in,&id,now);if(n){size_t rn=bp_control_request(&c,in,n,out,now);bp_transport_publish(&t,out,rn,id);}
    bp_wipe(in,sizeof(in));bp_wipe(out,sizeof(out));
}
int BP_MediaReady(void) {return c.media;}
void BP_StorageFault(void) {sim_reset();}
void BP_USB_Reset(void) {sim_reset();}
void BP_Receive(const uint8_t *p,size_t n) {sim_receive(p,n);}
void BP_GetReport(uint8_t r[64]) {sim_get(r);}
int SD_SPI_IsReady(void) {return !sd_fail;}
uint32_t SD_SPI_GetBlockCount(void) {raw_calls++;return 1024;}
int SD_SPI_ReadBlocks(uint32_t a,uint8_t *p,uint16_t n) {(void)a;(void)p;(void)n;raw_calls++;return !sd_fail;}
int SD_SPI_WriteBlocks(uint32_t a,const uint8_t *p,uint16_t n) {(void)a;(void)p;(void)n;raw_calls++;return !sd_fail;}
uint32_t BP_StorageCapacity(void) {return c.media?SD_SPI_GetBlockCount()-16:0;}
int BP_StorageRead(uint32_t a,uint8_t *p,uint16_t n) {return c.media&&SD_SPI_ReadBlocks(a+16,p,n);}
int BP_StorageWrite(uint32_t a,const uint8_t *p,uint16_t n) {return c.media&&SD_SPI_WriteBlocks(a+16,p,n);}
int sim_storage(void) {
    uint8_t data[512]={0};uint32_t blocks;uint16_t size;int mask=0;
    if(USBD_Storage_Interface_fops_FS.Init(0)==0)mask|=1;
    if(USBD_Storage_Interface_fops_FS.GetCapacity(0,&blocks,&size)==0)mask|=2;
    if(USBD_Storage_Interface_fops_FS.IsReady(0)==0)mask|=4;
    if(USBD_Storage_Interface_fops_FS.Read(0,data,0,1)==0)mask|=8;
    if(USBD_Storage_Interface_fops_FS.Write(0,data,0,1)==0)mask|=16;
    return mask;
}
int sim_raw_calls(void) {return raw_calls;}
