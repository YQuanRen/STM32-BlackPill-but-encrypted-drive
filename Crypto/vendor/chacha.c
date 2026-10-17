/*
 * ChaCha and XChaCha stream ciphers
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "primitives.h"

void chacha_setkey(struct chacha_ctx *ctx, const u8 *key, int nrounds)
{
	int i;

	for (i = 0; i < CHACHA_KEY_SIZE / sizeof(__le32); i++)
		ctx->key[i] = get_unaligned_le32(key + i * sizeof(__le32));
	ctx->nrounds = nrounds;
}

void chacha_init_state(u32 state[16], const struct chacha_ctx *ctx,
		       const u8 *iv)
{
	state[0]  = 0x61707865; /* "expa" */
	state[1]  = 0x3320646e; /* "nd 3" */
	state[2]  = 0x79622d32; /* "2-by" */
	state[3]  = 0x6b206574; /* "te k" */
	state[4]  = ctx->key[0];
	state[5]  = ctx->key[1];
	state[6]  = ctx->key[2];
	state[7]  = ctx->key[3];
	state[8]  = ctx->key[4];
	state[9]  = ctx->key[5];
	state[10] = ctx->key[6];
	state[11] = ctx->key[7];
	state[12] = get_unaligned_le32(iv +  0);
	state[13] = get_unaligned_le32(iv +  4);
	state[14] = get_unaligned_le32(iv +  8);
	state[15] = get_unaligned_le32(iv + 12);
}

#define COLUMN_HALFROUND(n1, n2) do {	\
	x[0]  += x[4];			\
	x[1]  += x[5];			\
	x[2]  += x[6];			\
	x[3]  += x[7];			\
	x[12] ^= x[0];			\
	x[13] ^= x[1];			\
	x[14] ^= x[2];			\
	x[15] ^= x[3];			\
	x[12] = rol32(x[12], n1);	\
	x[13] = rol32(x[13], n1);	\
	x[14] = rol32(x[14], n1);	\
	x[15] = rol32(x[15], n1);	\
					\
	x[8]  += x[12];			\
	x[9]  += x[13];			\
	x[10] += x[14];			\
	x[11] += x[15];			\
	x[4]  ^= x[8];			\
	x[5]  ^= x[9];			\
	x[6]  ^= x[10];			\
	x[7]  ^= x[11];			\
	x[4]  = rol32(x[4], n2);	\
	x[5]  = rol32(x[5], n2);	\
	x[6]  = rol32(x[6], n2);	\
	x[7]  = rol32(x[7], n2); } while (0)

#define DIAGONAL_HALFROUND(n1, n2) do {	\
	x[0]  += x[5];			\
	x[1]  += x[6];			\
	x[2]  += x[7];			\
	x[3]  += x[4];			\
	x[15] ^= x[0];			\
	x[12] ^= x[1];			\
	x[13] ^= x[2];			\
	x[14] ^= x[3];			\
	x[15] = rol32(x[15], n1);	\
	x[12] = rol32(x[12], n1);	\
	x[13] = rol32(x[13], n1);	\
	x[14] = rol32(x[14], n1);	\
					\
	x[8]  += x[13];			\
	x[9]  += x[14];			\
	x[10] += x[15];			\
	x[11] += x[12];			\
	x[7] ^= x[8];			\
	x[4] ^= x[9];			\
	x[5] ^= x[10];			\
	x[6] ^= x[11];			\
	x[7] = rol32(x[7], n2);		\
	x[4] = rol32(x[4], n2);		\
	x[5] = rol32(x[5], n2);		\
	x[6] = rol32(x[6], n2); } while (0)

void chacha_perm_generic(u32 x[16], int nrounds)
{
	do {
		COLUMN_HALFROUND(16, 12);
		COLUMN_HALFROUND(8, 7);
		DIAGONAL_HALFROUND(16, 12);
		DIAGONAL_HALFROUND(8, 7);
	} while ((nrounds -= 2) != 0);
}

static void chacha_block_generic(u32 state[16], __le32 stream[16], int nrounds)
{
	u32 x[16];
	int i;

	memcpy(x, state, sizeof(x));

	chacha_perm_generic(x, nrounds);

	for (i = 0; i < 16; i++)
		put_unaligned_le32(x[i] + state[i], (u8 *)stream + 4 * i);

	state[12]++;
    crypto_wipe(x, sizeof(x));
}

static void chacha_generic(const struct chacha_ctx *ctx, u8 *dst, const u8 *src,
			   unsigned int bytes, const u8 *iv)
{
	u32 state[16];
	__le32 stream[16];

	chacha_init_state(state, ctx, iv);

	while (bytes) {
		chacha_block_generic(state, stream, ctx->nrounds);
		if (bytes < CHACHA_BLOCK_SIZE) {
			xor(dst, src, stream, bytes);
			break;
		}
		xor(dst, src, stream, CHACHA_BLOCK_SIZE);
		bytes -= CHACHA_BLOCK_SIZE;
		dst += CHACHA_BLOCK_SIZE;
		src += CHACHA_BLOCK_SIZE;
	}
    crypto_wipe(state, sizeof(state));
    crypto_wipe(stream, sizeof(stream));
}

/* ChaCha stream cipher */
void chacha(const struct chacha_ctx *ctx, u8 *dst, const u8 *src,
	    unsigned int bytes, const u8 *iv, bool simd)
{
    (void)simd;
	chacha_generic(ctx, dst, src, bytes, iv);
}

/* HChaCha, an intermediate step towards XChaCha */
static void hchacha(const u32 state[16], u32 out[8], int nrounds, bool simd)
{
	u32 x[16];
    (void)simd;

	memcpy(x, state, sizeof(x));
	chacha_perm_generic(x, nrounds);
	memcpy(&out[0], &x[0], 16);
	memcpy(&out[4], &x[12], 16);
    crypto_wipe(x, sizeof(x));
}

/* XChaCha stream cipher */
void xchacha(const struct chacha_ctx *ctx, u8 *dst, const u8 *src,
	     unsigned int nbytes, const u8 *iv, bool simd)
{
	u32 state[16];
	struct chacha_ctx subctx;
	u8 real_iv[16];

	/* Compute the subkey given the original key and first 128 nonce bits */
	chacha_init_state(state, ctx, iv);
	hchacha(state, subctx.key, ctx->nrounds, simd);
	subctx.nrounds = ctx->nrounds;

	/* Build the real IV */
	memcpy(&real_iv[0], iv + 24, 8); /* stream position */
	memcpy(&real_iv[8], iv + 16, 8); /* remaining 64 nonce bits */

	/* Generate the stream and XOR it with the data */
	chacha(&subctx, dst, src, nbytes, real_iv, simd);
    crypto_wipe(&subctx, sizeof(subctx));
    crypto_wipe(state, sizeof(state));
}

