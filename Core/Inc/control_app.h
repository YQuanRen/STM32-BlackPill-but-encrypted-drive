#ifndef BP_CONTROL_APP_H
#define BP_CONTROL_APP_H
#include <stdint.h>
#include <stddef.h>
void BP_Init(void);
void BP_Task(void);
void BP_USB_Reset(void);
void BP_Receive(const uint8_t *,size_t);
void BP_GetReport(uint8_t[64]);
int BP_MediaReady(void);
int BP_MediaAttention(void);
void BP_StorageFault(void);
uint32_t BP_StorageCapacity(void);
int BP_StorageRead(uint32_t,uint8_t *,uint16_t);
int BP_StorageWrite(uint32_t,const uint8_t *,uint16_t);
#endif
