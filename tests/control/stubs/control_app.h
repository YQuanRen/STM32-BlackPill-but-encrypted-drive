#ifndef TEST_CONTROL_APP_H
#define TEST_CONTROL_APP_H
#include <stdint.h>
#include <stddef.h>
int BP_MediaReady(void);
void BP_StorageFault(void);
void BP_USB_Reset(void);
void BP_Receive(const uint8_t *,size_t);
void BP_GetReport(uint8_t[64]);
uint32_t BP_StorageCapacity(void);
int BP_StorageRead(uint32_t,uint8_t *,uint16_t);
int BP_StorageWrite(uint32_t,const uint8_t *,uint16_t);
#endif
