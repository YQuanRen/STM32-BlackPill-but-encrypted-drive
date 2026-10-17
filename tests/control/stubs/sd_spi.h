#ifndef TEST_SD_SPI_H
#define TEST_SD_SPI_H
#include <stdint.h>
#define SD_SPI_BLOCK_SIZE 512
int SD_SPI_IsReady(void);
uint32_t SD_SPI_GetBlockCount(void);
int SD_SPI_ReadBlocks(uint32_t,uint8_t *,uint16_t);
int SD_SPI_WriteBlocks(uint32_t,const uint8_t *,uint16_t);
#endif
