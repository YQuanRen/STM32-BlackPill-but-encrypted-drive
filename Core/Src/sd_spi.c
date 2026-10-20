#include "sd_spi.h"

#include "main.h"
#include "spi.h"

#define SD_CMD0    0U
#define SD_CMD1    1U
#define SD_CMD8    8U
#define SD_CMD9    9U
#define SD_CMD10   10U
#define SD_CMD16   16U
#define SD_CMD17   17U
#define SD_CMD24   24U
#define SD_CMD55   55U
#define SD_CMD58   58U
#define SD_ACMD41  41U

#define SD_R1_IDLE_STATE       0x01U
#define SD_R1_ILLEGAL_COMMAND  0x04U
#define SD_DATA_TOKEN          0xFEU
#define SD_WRITE_ACCEPTED      0x05U

#define SD_RESPONSE_ATTEMPTS   16U
#define SD_READY_ATTEMPTS      500000U
#define SD_TOKEN_ATTEMPTS      500000U
#define SD_ACTIVITY_MIN_MS     60U

static bool sd_ready;
static bool sd_high_capacity;
static uint32_t sd_block_count;
static uint8_t sd_dummy_tx[SD_SPI_BLOCK_SIZE];
static volatile bool sd_activity_pending;
static volatile uint32_t sd_activity_off_tick;

static void SD_SPI_ActivityLedInit(void)
{
  GPIO_InitTypeDef led_init = {0};

  __HAL_RCC_GPIOC_CLK_ENABLE();
  HAL_GPIO_WritePin(GPIOC, GPIO_PIN_13, GPIO_PIN_SET);
  led_init.Pin = GPIO_PIN_13;
  led_init.Mode = GPIO_MODE_OUTPUT_PP;
  led_init.Pull = GPIO_NOPULL;
  led_init.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOC, &led_init);
}

static void SD_SPI_ActivityBegin(void)
{
  /* The Black Pill's PC13 LED is active-low. */
  HAL_GPIO_WritePin(GPIOC, GPIO_PIN_13, GPIO_PIN_RESET);
}

static void SD_SPI_ActivityEnd(void)
{
  sd_activity_off_tick = HAL_GetTick() + SD_ACTIVITY_MIN_MS;
  sd_activity_pending = true;
}

static uint8_t SD_SPI_TransferByte(uint8_t value)
{
  uint8_t received = 0xFFU;
  (void)HAL_SPI_TransmitReceive(&hspi1, &value, &received, 1U, 100U);
  return received;
}

static void SD_SPI_Deselect(void)
{
  HAL_GPIO_WritePin(SD_CS_GPIO_Port, SD_CS_Pin, GPIO_PIN_SET);
  (void)SD_SPI_TransferByte(0xFFU);
}

static void SD_SPI_Select(void)
{
  HAL_GPIO_WritePin(SD_CS_GPIO_Port, SD_CS_Pin, GPIO_PIN_RESET);
  (void)SD_SPI_TransferByte(0xFFU);
}

static bool SD_SPI_WaitReady(void)
{
  for (uint32_t attempt = 0U; attempt < SD_READY_ATTEMPTS; ++attempt)
  {
    if (SD_SPI_TransferByte(0xFFU) == 0xFFU)
    {
      return true;
    }
  }

  return false;
}

static uint8_t SD_SPI_SendCommand(uint8_t command, uint32_t argument, uint8_t crc)
{
  uint8_t response = 0xFFU;

  SD_SPI_Deselect();
  SD_SPI_Select();

  if (!SD_SPI_WaitReady())
  {
    SD_SPI_Deselect();
    return 0xFFU;
  }

  (void)SD_SPI_TransferByte((uint8_t)(0x40U | command));
  (void)SD_SPI_TransferByte((uint8_t)(argument >> 24));
  (void)SD_SPI_TransferByte((uint8_t)(argument >> 16));
  (void)SD_SPI_TransferByte((uint8_t)(argument >> 8));
  (void)SD_SPI_TransferByte((uint8_t)argument);
  (void)SD_SPI_TransferByte(crc);

  for (uint32_t attempt = 0U; attempt < SD_RESPONSE_ATTEMPTS; ++attempt)
  {
    response = SD_SPI_TransferByte(0xFFU);
    if ((response & 0x80U) == 0U)
    {
      break;
    }
  }

  return response;
}

static bool SD_SPI_WaitForToken(uint8_t token)
{
  for (uint32_t attempt = 0U; attempt < SD_TOKEN_ATTEMPTS; ++attempt)
  {
    if (SD_SPI_TransferByte(0xFFU) == token)
    {
      return true;
    }
  }

  return false;
}

static bool SD_SPI_ReadRegister(uint8_t command, uint8_t *data, uint16_t length)
{
  if (SD_SPI_SendCommand(command, 0U, 0x01U) != 0x00U)
  {
    SD_SPI_Deselect();
    return false;
  }

  if (!SD_SPI_WaitForToken(SD_DATA_TOKEN))
  {
    SD_SPI_Deselect();
    return false;
  }

  if (HAL_SPI_TransmitReceive(&hspi1, sd_dummy_tx, data, length, 100U) != HAL_OK)
  {
    SD_SPI_Deselect();
    return false;
  }

  (void)SD_SPI_TransferByte(0xFFU);
  (void)SD_SPI_TransferByte(0xFFU);
  SD_SPI_Deselect();
  return true;
}

static uint32_t SD_SPI_ParseBlockCount(const uint8_t csd[16])
{
  if ((csd[0] & 0xC0U) == 0x40U)
  {
    uint32_t c_size = ((uint32_t)(csd[7] & 0x3FU) << 16)
                    | ((uint32_t)csd[8] << 8)
                    | (uint32_t)csd[9];
    return (c_size + 1U) * 1024U;
  }

  uint32_t read_block_length = csd[5] & 0x0FU;
  uint32_t c_size = ((uint32_t)(csd[6] & 0x03U) << 10)
                  | ((uint32_t)csd[7] << 2)
                  | ((uint32_t)(csd[8] & 0xC0U) >> 6);
  uint32_t c_size_multiplier = ((uint32_t)(csd[9] & 0x03U) << 1)
                             | ((uint32_t)(csd[10] & 0x80U) >> 7);
  uint64_t capacity_bytes = ((uint64_t)c_size + 1ULL)
                          << (c_size_multiplier + read_block_length + 2U);
  return (uint32_t)(capacity_bytes / SD_SPI_BLOCK_SIZE);
}

static uint32_t SD_SPI_BlockAddress(uint32_t block)
{
  return sd_high_capacity ? block : (block * SD_SPI_BLOCK_SIZE);
}

bool SD_SPI_Init(void)
{
  uint8_t response;
  uint8_t register_data[16];

  sd_ready = false;
  sd_high_capacity = false;
  sd_block_count = 0U;
  sd_activity_pending = false;
  SD_SPI_ActivityLedInit();

  for (uint32_t index = 0U; index < SD_SPI_BLOCK_SIZE; ++index)
  {
    sd_dummy_tx[index] = 0xFFU;
  }

  SD_SPI_Deselect();
  for (uint32_t index = 0U; index < 10U; ++index)
  {
    (void)SD_SPI_TransferByte(0xFFU);
  }

  response = 0xFFU;
  for (uint32_t attempt = 0U; attempt < 100U; ++attempt)
  {
    response = SD_SPI_SendCommand(SD_CMD0, 0U, 0x95U);
    SD_SPI_Deselect();
    if (response == SD_R1_IDLE_STATE)
    {
      break;
    }
    HAL_Delay(2U);
  }

  if (response != SD_R1_IDLE_STATE)
  {
    return false;
  }

  response = SD_SPI_SendCommand(SD_CMD8, 0x000001AAU, 0x87U);
  if (response == SD_R1_IDLE_STATE)
  {
    uint8_t r7[4];
    for (uint32_t index = 0U; index < 4U; ++index)
    {
      r7[index] = SD_SPI_TransferByte(0xFFU);
    }
    SD_SPI_Deselect();

    if ((r7[2] != 0x01U) || (r7[3] != 0xAAU))
    {
      return false;
    }

    response = 0xFFU;
    for (uint32_t attempt = 0U; attempt < 1000U; ++attempt)
    {
      uint8_t app_response = SD_SPI_SendCommand(SD_CMD55, 0U, 0x01U);
      SD_SPI_Deselect();
      if (app_response > SD_R1_IDLE_STATE)
      {
        break;
      }

      response = SD_SPI_SendCommand(SD_ACMD41, 0x40000000U, 0x01U);
      SD_SPI_Deselect();
      if (response == 0x00U)
      {
        break;
      }
      HAL_Delay(1U);
    }

    if (response != 0x00U)
    {
      return false;
    }

    response = SD_SPI_SendCommand(SD_CMD58, 0U, 0x01U);
    if (response != 0x00U)
    {
      SD_SPI_Deselect();
      return false;
    }

    uint8_t ocr[4];
    for (uint32_t index = 0U; index < 4U; ++index)
    {
      ocr[index] = SD_SPI_TransferByte(0xFFU);
    }
    sd_high_capacity = (ocr[0] & 0x40U) != 0U;
    SD_SPI_Deselect();
  }
  else if ((response & SD_R1_ILLEGAL_COMMAND) != 0U)
  {
    SD_SPI_Deselect();
    response = 0xFFU;
    for (uint32_t attempt = 0U; attempt < 1000U; ++attempt)
    {
      uint8_t app_response = SD_SPI_SendCommand(SD_CMD55, 0U, 0x01U);
      SD_SPI_Deselect();

      if (app_response <= SD_R1_IDLE_STATE)
      {
        response = SD_SPI_SendCommand(SD_ACMD41, 0U, 0x01U);
      }
      else
      {
        response = SD_SPI_SendCommand(SD_CMD1, 0U, 0x01U);
      }
      SD_SPI_Deselect();

      if (response == 0x00U)
      {
        break;
      }
      HAL_Delay(1U);
    }

    if (response != 0x00U)
    {
      return false;
    }

    response = SD_SPI_SendCommand(SD_CMD16, SD_SPI_BLOCK_SIZE, 0x01U);
    SD_SPI_Deselect();
    if (response != 0x00U)
    {
      return false;
    }
  }
  else
  {
    SD_SPI_Deselect();
    return false;
  }

  /* 96 MHz APB2 / 16 = 6 MHz: conservative for jumper wires and
     resistor-level-shifted SD modules. */
  hspi1.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_16;
  if (HAL_SPI_Init(&hspi1) != HAL_OK)
  {
    return false;
  }

  if (!SD_SPI_ReadRegister(SD_CMD9, register_data, sizeof(register_data)))
  {
    return false;
  }

  sd_block_count = SD_SPI_ParseBlockCount(register_data);
  sd_ready = sd_block_count != 0U;
  return sd_ready;
}

bool SD_SPI_IsReady(void)
{
  return sd_ready;
}

uint32_t SD_SPI_GetBlockCount(void)
{
  return sd_block_count;
}

bool SD_SPI_GetCardID(uint8_t cid[16])
{
  if (!sd_ready || cid == NULL) return false;
  if (!SD_SPI_ReadRegister(SD_CMD10, cid, 16)) { sd_ready = false; return false; }
  return true;
}

bool SD_SPI_ReadBlocks(uint32_t first_block, uint8_t *data, uint16_t block_count)
{
  if (!sd_ready || (data == NULL) || (block_count == 0U)
      || (first_block >= sd_block_count)
      || ((uint32_t)block_count > (sd_block_count - first_block)))
  {
    return false;
  }

  SD_SPI_ActivityBegin();

  for (uint16_t block_index = 0U; block_index < block_count; ++block_index)
  {
    uint32_t address = SD_SPI_BlockAddress(first_block + block_index);
    if (SD_SPI_SendCommand(SD_CMD17, address, 0x01U) != 0x00U)
    {
      SD_SPI_Deselect();
      SD_SPI_ActivityEnd();
      return false;
    }

    if (!SD_SPI_WaitForToken(SD_DATA_TOKEN))
    {
      SD_SPI_Deselect();
      SD_SPI_ActivityEnd();
      return false;
    }

    if (HAL_SPI_TransmitReceive(&hspi1, sd_dummy_tx,
                                data + ((uint32_t)block_index * SD_SPI_BLOCK_SIZE),
                                SD_SPI_BLOCK_SIZE, 100U) != HAL_OK)
    {
      SD_SPI_Deselect();
      SD_SPI_ActivityEnd();
      return false;
    }

    (void)SD_SPI_TransferByte(0xFFU);
    (void)SD_SPI_TransferByte(0xFFU);
    SD_SPI_Deselect();
  }

  SD_SPI_ActivityEnd();
  return true;
}

bool SD_SPI_WriteBlocks(uint32_t first_block, const uint8_t *data, uint16_t block_count)
{
  if (!sd_ready || (data == NULL) || (block_count == 0U)
      || (first_block >= sd_block_count)
      || ((uint32_t)block_count > (sd_block_count - first_block)))
  {
    return false;
  }

  SD_SPI_ActivityBegin();

  for (uint16_t block_index = 0U; block_index < block_count; ++block_index)
  {
    uint32_t address = SD_SPI_BlockAddress(first_block + block_index);
    if (SD_SPI_SendCommand(SD_CMD24, address, 0x01U) != 0x00U)
    {
      SD_SPI_Deselect();
      SD_SPI_ActivityEnd();
      return false;
    }

    (void)SD_SPI_TransferByte(0xFFU);
    (void)SD_SPI_TransferByte(SD_DATA_TOKEN);
    if (HAL_SPI_Transmit(&hspi1,
                         (uint8_t *)(data + ((uint32_t)block_index * SD_SPI_BLOCK_SIZE)),
                         SD_SPI_BLOCK_SIZE, 100U) != HAL_OK)
    {
      SD_SPI_Deselect();
      SD_SPI_ActivityEnd();
      return false;
    }
    (void)SD_SPI_TransferByte(0xFFU);
    (void)SD_SPI_TransferByte(0xFFU);

    uint8_t data_response = SD_SPI_TransferByte(0xFFU);
    if ((data_response & 0x1FU) != SD_WRITE_ACCEPTED)
    {
      SD_SPI_Deselect();
      SD_SPI_ActivityEnd();
      return false;
    }

    if (!SD_SPI_WaitReady())
    {
      SD_SPI_Deselect();
      SD_SPI_ActivityEnd();
      return false;
    }
    SD_SPI_Deselect();
  }

  SD_SPI_ActivityEnd();
  return true;
}

void SD_SPI_ActivityTask(void)
{
  if (sd_activity_pending
      && ((int32_t)(HAL_GetTick() - sd_activity_off_tick) >= 0))
  {
    uint32_t interrupt_state = __get_PRIMASK();
    __disable_irq();

    if (sd_activity_pending
        && ((int32_t)(HAL_GetTick() - sd_activity_off_tick) >= 0))
    {
      HAL_GPIO_WritePin(GPIOC, GPIO_PIN_13, GPIO_PIN_SET);
      sd_activity_pending = false;
    }

    if (interrupt_state == 0U)
    {
      __enable_irq();
    }
  }
}
