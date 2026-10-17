#ifndef TEST_CONTROL_APP_H
#define TEST_CONTROL_APP_H
#include <stdint.h>
#include <stddef.h>
int BP_MediaReady(void);
void BP_StorageFault(void);
void BP_USB_Reset(void);
void BP_Receive(const uint8_t *,size_t);
void BP_GetReport(uint8_t[64]);
#endif
