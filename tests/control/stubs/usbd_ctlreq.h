#ifndef TEST_CTLREQ_H
#define TEST_CTLREQ_H
#include "usbd_def.h"
int USBD_CtlSendData(USBD_HandleTypeDef *,uint8_t *,uint16_t);
int USBD_CtlPrepareRx(USBD_HandleTypeDef *,uint8_t *,uint16_t);
void USBD_CtlError(USBD_HandleTypeDef *,USBD_SetupReqTypedef *);
#endif
