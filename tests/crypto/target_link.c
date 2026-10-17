/* Link-only Cortex-M4 smoke test. Never flashed or run on hardware. */
#include "adiantum.h"
static adiantum_ctx ctx;
static uint8_t key[32], input[512], output[512];
int main(void)
{
    int result = adiantum_init(&ctx, key, sizeof(key));
    result |= adiantum_sector(&ctx, output, sizeof(output), input, 0, 0);
    result |= adiantum_sector(&ctx, input, sizeof(input), output, 0, 1);
    adiantum_clear(&ctx);
    return result;
}
