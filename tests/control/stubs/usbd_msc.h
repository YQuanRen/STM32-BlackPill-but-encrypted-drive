#ifndef TEST_USBD_MSC_H
#define TEST_USBD_MSC_H
#include "usbd_def.h"
#define STANDARD_INQUIRY_DATA_LEN 36
typedef struct {
    int8_t (*Init)(uint8_t);
    int8_t (*GetCapacity)(uint8_t,uint32_t *,uint16_t *);
    int8_t (*IsReady)(uint8_t);
    int8_t (*IsWriteProtected)(uint8_t);
    int8_t (*Read)(uint8_t,uint8_t *,uint32_t,uint16_t);
    int8_t (*Write)(uint8_t,uint8_t *,uint32_t,uint16_t);
    int8_t (*GetMaxLun)(void);
    int8_t *pInquiry;
} USBD_StorageTypeDef;
extern USBD_ClassTypeDef USBD_MSC;
#endif
