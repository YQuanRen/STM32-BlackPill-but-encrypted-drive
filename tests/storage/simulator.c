#include "volume.h"
#include "usbd_storage_if.h"
#include <string.h>
#define SECTORS 64
static uint8_t flash[2][BP_BANK_SIZE],disk[SECTORS][512];
static bp_journal j;
static bp_control c;
static bp_volume v;
static uint8_t identity[16]={1,2,3,4,5,6,7,8,9,10,11,12},cid[16];
static int cut=-1,rd_fail,corrupt_write,present=1,writes,reads;
static uint32_t now;
static uint32_t capacity=SECTORS;
static int flash_cut=-1;
static int fr(void *u,unsigned b,size_t o,void *p,size_t n){(void)u;memcpy(p,flash[b]+o,n);return 1;}
static int fp(void *u,unsigned b,size_t o,const void *p,size_t n){(void)u;const uint8_t *s=p;for(size_t i=0;i<n;i++){if(flash_cut==0)return 0;if(flash_cut>0)flash_cut--;flash[b][o+i]&=s[i];}return 1;}
static int fe(void *u,unsigned b){(void)u;memset(flash[b],255,BP_BANK_SIZE);return 1;}
static int describe(void *u,uint8_t *p,uint32_t *n){(void)u;memcpy(p,cid,16);*n=capacity;return present;}
static int dr(void *u,uint32_t a,uint8_t *p){(void)u;reads++;if(!present||rd_fail||a>=SECTORS)return 0;memcpy(p,disk[a],512);return 1;}
static int dw(void *u,uint32_t a,const uint8_t *p){(void)u;if(!present||cut==0||a>=SECTORS)return 0;if(cut>0)cut--;writes++;memcpy(disk[a],p,512);if(corrupt_write)disk[a][99]^=1;return 1;}
static void clear(void *u){bp_volume_reset(u);}
int sim_boot(void){bp_flash f={0,fr,fp,fe};bp_disk d={0,describe,dr,dw};int r=bp_journal_boot(&j,&f,identity);bp_volume_init(&v,&j,&d);bp_control_init(&c,&j,bp_volume_authorize,&v);c.storage=bp_volume_command;c.clear_user=clear;return r;}
void sim_fresh(void){memset(flash,255,sizeof(flash));memset(disk,0xa5,sizeof(disk));memset(cid,0x31,16);cut=flash_cut=-1;capacity=SECTORS;rd_fail=corrupt_write=writes=reads=now=0;present=1;sim_boot();}
void sim_geometry(uint32_t n){capacity=n;}
void sim_flash_cut(int n){flash_cut=n;}
size_t sim_request(const uint8_t *p,size_t n,uint8_t *o){return bp_control_request(&c,p,n,o,now);}
void sim_reset(void){bp_control_reset(&c);}
void sim_step(void){bp_control_tick(&c,now);bp_volume_step(&v);}
void sim_time(uint32_t n){now=n;}
void sim_fault(int w,int r,int corrupt){cut=w;rd_fail=r;corrupt_write=corrupt;}
void sim_card(int exists,int different){present=exists;memset(cid,different?0x32:0x31,16);}
void sim_raw(void *p){memcpy(p,disk,sizeof(disk));}
void sim_raw_restore(const void *p){memcpy(disk,p,sizeof(disk));}
void sim_flash(void *p){memcpy(p,flash,sizeof(flash));}
int sim_writes(void){return writes;}
int sim_reads(void){return reads;}
int sim_state(void){return v.state;}
int sim_clean(void){uint8_t zero[sizeof(v.cipher)]={0};return !v.unlocked&&!v.staged&&bp_equal(&v.cipher,zero,sizeof(v.cipher))&&bp_equal(v.stage,zero,sizeof(v.stage));}
int BP_MediaReady(void){if(!c.media)return 0;if(!bp_volume_ready(&v)){sim_reset();return 0;}return 1;}
void BP_StorageFault(void){sim_reset();}
int SD_SPI_IsReady(void){return present;}
uint32_t BP_StorageCapacity(void){return BP_MediaReady()?v.physical-16:0;}
int BP_StorageRead(uint32_t a,uint8_t *p,uint16_t n){if(!c.media)return 0;if(!bp_volume_read(&v,a,p,n)){BP_StorageFault();return 0;}return 1;}
int BP_StorageWrite(uint32_t a,const uint8_t *p,uint16_t n){if(!c.media)return 0;if(!bp_volume_write(&v,a,p,n)){BP_StorageFault();return 0;}return 1;}
int sim_read(uint32_t a,uint8_t *p,uint16_t n){return USBD_Storage_Interface_fops_FS.Read(0,p,a,n);}
int sim_write(uint32_t a,uint8_t *p,uint16_t n){return USBD_Storage_Interface_fops_FS.Write(0,p,a,n);}
uint32_t sim_capacity(void){uint32_t n=0;uint16_t s=0;return USBD_Storage_Interface_fops_FS.GetCapacity(0,&n,&s)==0&&s==512?n:0;}
