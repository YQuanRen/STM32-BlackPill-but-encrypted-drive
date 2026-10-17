#include "control_app.h"
#include "control.h"
#include "transport.h"
#include "main.h"
#include <string.h>
static bp_journal journal;
static bp_control control;
static bp_transport transport;
static volatile uint32_t generation;
static volatile int media_ready;
static volatile int media_attention;
static uint32_t handled_generation;
static uint8_t request[256],response[256];

static int flash_read(void *u,unsigned bank,size_t off,void *dst,size_t n) {
    (void)u;if(bank>1||off>BP_BANK_SIZE||n>BP_BANK_SIZE-off)return 0;
    memcpy(dst,(const void *)(uintptr_t)(0x08040000u+bank*BP_BANK_SIZE+off),n);return 1;
}
static int flash_program(void *u,unsigned bank,size_t off,const void *src,size_t n) {
    (void)u;const uint8_t *p=src;int ok=1;
    if(bank>1||off>BP_BANK_SIZE||n>BP_BANK_SIZE-off||off%4||n%4)return 0;
    if(HAL_FLASH_Unlock()!=HAL_OK)return 0;
    for(size_t i=0;i<n;i+=4) {
        uint32_t addr=0x08040000u+bank*BP_BANK_SIZE+(uint32_t)off+(uint32_t)i;
        if(*(volatile uint32_t *)(uintptr_t)addr!=UINT32_MAX||
           HAL_FLASH_Program(FLASH_TYPEPROGRAM_WORD,addr,bp_u32(p+i))!=HAL_OK){ok=0;break;}
    }
    HAL_FLASH_Lock();return ok;
}
static int flash_erase(void *u,unsigned bank) {
    (void)u;if(bank>1)return 0;
    FLASH_EraseInitTypeDef e={0};uint32_t error;
    e.TypeErase=FLASH_TYPEERASE_SECTORS;e.Sector=bank?FLASH_SECTOR_7:FLASH_SECTOR_6;
    e.NbSectors=1;e.VoltageRange=FLASH_VOLTAGE_RANGE_3;
    if(HAL_FLASH_Unlock()!=HAL_OK)return 0;
    int ok=HAL_FLASHEx_Erase(&e,&error)==HAL_OK;HAL_FLASH_Lock();return ok;
}
static int authorize(void *u,unsigned mode,const uint8_t *key) {
    (void)u;(void)mode;(void)key;
    /* Milestone 4 must validate authenticated ready headers/card/key here.
       Never expose an old plaintext card through a milestone-3 unlock. */
    return BP_UNSUPPORTED;
}
void BP_Init(void) {
    uint8_t id[16]={0};bp_put(id,HAL_GetUIDw0(),4);bp_put(id+4,HAL_GetUIDw1(),4);bp_put(id+8,HAL_GetUIDw2(),4);
    bp_flash io={NULL,flash_read,flash_program,flash_erase};
    bp_journal_boot(&journal,&io,id);bp_control_init(&control,&journal,authorize,NULL);
    bp_transport_reset(&transport);media_ready=0;generation=handled_generation=0;
}
void BP_USB_Reset(void) {
    media_ready=0;media_attention=0;generation++;bp_transport_reset(&transport);
}
void BP_StorageFault(void) {BP_USB_Reset();}
int BP_MediaReady(void) {return media_ready;}
int BP_MediaAttention(void) {int changed=media_attention;media_attention=0;return changed;}
void BP_Receive(const uint8_t *r,size_t n) {bp_transport_receive(&transport,r,n,HAL_GetTick());}
void BP_GetReport(uint8_t r[64]) {bp_transport_get(&transport,r);}
void BP_Task(void) {
    uint32_t irq=__get_PRIMASK();__disable_irq();uint32_t current=generation;unsigned id;
    if(current!=handled_generation){bp_control_reset(&control);handled_generation=current;}
    size_t n=bp_transport_take(&transport,request,&id,HAL_GetTick());__set_PRIMASK(irq);
    if(!n)return;
    size_t rn=bp_control_request(&control,request,n,response,HAL_GetTick());
    irq=__get_PRIMASK();__disable_irq();
    if(generation==current){
        if(!media_ready&&control.media)media_attention=1;
        media_ready=control.media;bp_transport_publish(&transport,response,rn,id);
    }
    else {bp_control_reset(&control);handled_generation=generation;}
    bp_wipe(request,sizeof(request));bp_wipe(response,sizeof(response));__set_PRIMASK(irq);
}
