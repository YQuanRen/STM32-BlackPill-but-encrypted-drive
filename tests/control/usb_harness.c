#include "usbd_composite.h"
#include "usbd_ctlreq.h"
#include <string.h>
static USBD_HandleTypeDef device;
static uint8_t sent[64],*receive;
static unsigned sent_n,rx_n,msc_calls;
static uint8_t msc_init(USBD_HandleTypeDef *p,uint8_t cfg) {(void)p;(void)cfg;msc_calls++;return USBD_OK;}
static uint8_t msc_setup(USBD_HandleTypeDef *p,USBD_SetupReqTypedef *r) {(void)p;(void)r;msc_calls++;return USBD_OK;}
static uint8_t msc_data(USBD_HandleTypeDef *p,uint8_t ep) {(void)p;(void)ep;msc_calls++;return USBD_OK;}
USBD_ClassTypeDef USBD_MSC={msc_init,msc_init,msc_setup,NULL,NULL,msc_data,msc_data};
int USBD_LL_OpenEP(USBD_HandleTypeDef *p,uint8_t ep,uint8_t type,uint16_t n) {(void)p;return ep==0x82&&type==3&&n==64?0:3;}
int USBD_LL_CloseEP(USBD_HandleTypeDef *p,uint8_t ep) {(void)p;(void)ep;return 0;}
uint32_t USBD_LL_GetRxDataSize(USBD_HandleTypeDef *p,uint8_t ep) {(void)p;(void)ep;return rx_n;}
int USBD_CtlSendData(USBD_HandleTypeDef *p,uint8_t *b,uint16_t n) {
    (void)p;if(n>64)return 3;memcpy(sent,b,n);sent_n=n;return 0;
}
int USBD_CtlPrepareRx(USBD_HandleTypeDef *p,uint8_t *b,uint16_t n) {(void)p;receive=b;return n==64?0:3;}
void USBD_CtlError(USBD_HandleTypeDef *p,USBD_SetupReqTypedef *r) {(void)p;(void)r;}
unsigned usb_config(uint8_t *out) {uint16_t n;uint8_t *p=USBD_BP.GetFSConfigDescriptor(&n);memcpy(out,p,n);return n;}
int usb_init(void) {return USBD_BP.Init(&device,0);}
int usb_deinit(void) {return USBD_BP.DeInit(&device,0);}
int usb_setup(unsigned bm,unsigned req,unsigned val,unsigned index,unsigned n,uint8_t *out) {
    USBD_SetupReqTypedef r={(uint8_t)bm,(uint8_t)req,(uint16_t)val,(uint16_t)index,(uint16_t)n};
    sent_n=0;receive=NULL;int status=USBD_BP.Setup(&device,&r);
    if(status)return -1;memcpy(out,sent,sent_n);return (int)sent_n;
}
int usb_receive(const uint8_t *r,unsigned n) {
    if(!receive||n>64)return -1;memcpy(receive,r,n);rx_n=n;return USBD_BP.EP0_RxReady(&device);
}
unsigned usb_msc_calls(void) {return msc_calls;}
