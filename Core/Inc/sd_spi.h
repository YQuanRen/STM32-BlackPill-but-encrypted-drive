#ifndef SD_SPI_H
#define SD_SPI_H

#include <stdbool.h>
#include <stdint.h>

#define SD_SPI_BLOCK_SIZE 512U

bool SD_SPI_Init(void);
bool SD_SPI_IsReady(void);
uint32_t SD_SPI_GetBlockCount(void);
bool SD_SPI_ReadBlocks(uint32_t first_block, uint8_t *data, uint16_t block_count);
bool SD_SPI_WriteBlocks(uint32_t first_block, const uint8_t *data, uint16_t block_count);
void SD_SPI_ActivityTask(void);

#endif /* SD_SPI_H */
