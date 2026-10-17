/* One ST class dispatcher owns MSC interface 0 and vendor HID interface 1.
 * MSC retains the sole pClassData/static allocator; HID state is separate. */
#include "usbd_composite.h"
#include "usbd_msc.h"
#include "usbd_ctlreq.h"
#include "control_app.h"
#include <string.h>

static uint8_t feature_rx[64],feature_tx[64],idle,alt,pending;
static uint16_t status_word;
static uint8_t report_desc[]={
    0x06,0x00,0xff,0x09,0x01,0xa1,0x01,0x85,0x01,
    0x15,0x00,0x26,0xff,0x00,0x75,0x08,0x95,0x3f,0x09,0x01,0xb1,0x02,0xc0
};
static uint8_t config_desc[]={
    9,2,57,0,2,1,0,0x80,50,
    9,4,0,0,2,8,6,0x50,0,
    7,5,0x81,2,64,0,0,
    7,5,0x01,2,64,0,0,
    9,4,1,0,1,3,0,0,0,
    9,0x21,0x11,0x01,0,1,0x22,sizeof(report_desc),0,
    7,5,0x82,3,64,0,10
};
/* Config length is 9+23+25 = 57. No IAD needed for independent MSC/HID. */
static uint8_t qualifier[]={10,6,0,2,0,0,0,64,1,0};
void USBD_BP_ResetBuffers(void) {
    pending=0;memset(feature_rx,0,64);memset(feature_tx,0,64);
}
static uint8_t init(USBD_HandleTypeDef *p,uint8_t cfg) {
    USBD_BP_ResetBuffers();idle=alt=0;
    uint8_t r=USBD_MSC.Init(p,cfg);if(r!=USBD_OK)return r;
    if(USBD_LL_OpenEP(p,0x82,USBD_EP_TYPE_INTR,64)!=USBD_OK){USBD_MSC.DeInit(p,cfg);return USBD_FAIL;}
    p->ep_in[2].is_used=1;return USBD_OK;
}
static uint8_t deinit(USBD_HandleTypeDef *p,uint8_t cfg) {
    BP_USB_Reset();USBD_BP_ResetBuffers();USBD_LL_CloseEP(p,0x82);p->ep_in[2].is_used=0;
    return USBD_MSC.DeInit(p,cfg);
}
static uint8_t setup(USBD_HandleTypeDef *p,USBD_SetupReqTypedef *r) {
    pending=0;memset(feature_rx,0,64);
    unsigned recipient=r->bmRequest&0x1f;
    if((recipient==1&&r->wIndex==0)||(recipient==2&&(r->wIndex==1||r->wIndex==0x81)))
        return USBD_MSC.Setup(p,r);
    if(recipient!=1||r->wIndex!=1)goto bad;
    if(r->bmRequest==0x81&&r->bRequest==USB_REQ_GET_DESCRIPTOR) {
        if(r->wValue==0x2200)return (uint8_t)USBD_CtlSendData(p,report_desc,MIN(r->wLength,sizeof(report_desc)));
        if(r->wValue==0x2100)return (uint8_t)USBD_CtlSendData(p,config_desc+41,MIN(r->wLength,9));
    }
    if(r->bmRequest==0xa1&&r->bRequest==1&&r->wValue==0x0301&&r->wLength==64) {
        BP_GetReport(feature_tx);return (uint8_t)USBD_CtlSendData(p,feature_tx,64);
    }
    if(r->bmRequest==0x21&&r->bRequest==9&&r->wValue==0x0301&&r->wLength==64) {
        pending=1;return (uint8_t)USBD_CtlPrepareRx(p,feature_rx,64);
    }
    if(r->bmRequest==0x21&&r->bRequest==10&&(r->wValue&255)==1&&r->wLength==0) {idle=(uint8_t)(r->wValue>>8);return USBD_OK;}
    if(r->bmRequest==0xa1&&r->bRequest==2&&r->wValue==1&&r->wLength==1) return (uint8_t)USBD_CtlSendData(p,&idle,1);
    if(r->bmRequest==0x81&&r->bRequest==USB_REQ_GET_INTERFACE&&r->wValue==0&&r->wLength==1) return (uint8_t)USBD_CtlSendData(p,&alt,1);
    if(r->bmRequest==0x01&&r->bRequest==USB_REQ_SET_INTERFACE&&r->wValue==0&&r->wLength==0) return USBD_OK;
    if(r->bmRequest==0x81&&r->bRequest==USB_REQ_GET_STATUS&&r->wValue==0&&r->wLength==2) return (uint8_t)USBD_CtlSendData(p,(uint8_t *)&status_word,2);
bad: USBD_CtlError(p,r);return USBD_FAIL;
}
static uint8_t received(USBD_HandleTypeDef *p) {
    if(pending){pending=0;BP_Receive(feature_rx,USBD_LL_GetRxDataSize(p,0));memset(feature_rx,0,64);}
    return USBD_OK;
}
static uint8_t sent(USBD_HandleTypeDef *p) {(void)p;memset(feature_tx,0,64);return USBD_OK;}
static uint8_t in(USBD_HandleTypeDef *p,uint8_t ep) {return ep==1?USBD_MSC.DataIn(p,ep):USBD_OK;}
static uint8_t out(USBD_HandleTypeDef *p,uint8_t ep) {return ep==1?USBD_MSC.DataOut(p,ep):USBD_FAIL;}
static uint8_t *config(uint16_t *n) {*n=sizeof(config_desc);return config_desc;}
static uint8_t *qual(uint16_t *n) {*n=sizeof(qualifier);return qualifier;}
USBD_ClassTypeDef USBD_BP={init,deinit,setup,sent,received,in,out,NULL,NULL,NULL,config,config,config,qual};
