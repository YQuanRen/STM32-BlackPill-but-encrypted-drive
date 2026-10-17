#ifndef TEST_USBD_DEF_H
#define TEST_USBD_DEF_H
#include <stdint.h>
#define USBD_OK 0
#define USBD_FAIL 3
#define UNUSED(x) (void)(x)
#define MIN(a,b) ((a)<(b)?(a):(b))
#define USBD_EP_TYPE_INTR 3
#define USB_REQ_GET_DESCRIPTOR 6
#define USB_REQ_GET_INTERFACE 10
#define USB_REQ_SET_INTERFACE 11
#define USB_REQ_GET_STATUS 0
typedef struct {uint8_t is_used;} USBD_EndpointTypeDef;
typedef struct {USBD_EndpointTypeDef ep_in[16];} USBD_HandleTypeDef;
typedef struct {uint8_t bmRequest,bRequest;uint16_t wValue,wIndex,wLength;} USBD_SetupReqTypedef;
typedef struct {
    uint8_t (*Init)(USBD_HandleTypeDef *,uint8_t);
    uint8_t (*DeInit)(USBD_HandleTypeDef *,uint8_t);
    uint8_t (*Setup)(USBD_HandleTypeDef *,USBD_SetupReqTypedef *);
    uint8_t (*EP0_TxSent)(USBD_HandleTypeDef *);
    uint8_t (*EP0_RxReady)(USBD_HandleTypeDef *);
    uint8_t (*DataIn)(USBD_HandleTypeDef *,uint8_t);
    uint8_t (*DataOut)(USBD_HandleTypeDef *,uint8_t);
    uint8_t (*SOF)(USBD_HandleTypeDef *);
    uint8_t (*IsoINIncomplete)(USBD_HandleTypeDef *,uint8_t);
    uint8_t (*IsoOUTIncomplete)(USBD_HandleTypeDef *,uint8_t);
    uint8_t *(*GetHSConfigDescriptor)(uint16_t *);
    uint8_t *(*GetFSConfigDescriptor)(uint16_t *);
    uint8_t *(*GetOtherSpeedConfigDescriptor)(uint16_t *);
    uint8_t *(*GetDeviceQualifierDescriptor)(uint16_t *);
} USBD_ClassTypeDef;
int USBD_LL_OpenEP(USBD_HandleTypeDef *,uint8_t,uint8_t,uint16_t);
int USBD_LL_CloseEP(USBD_HandleTypeDef *,uint8_t);
uint32_t USBD_LL_GetRxDataSize(USBD_HandleTypeDef *,uint8_t);
#endif
