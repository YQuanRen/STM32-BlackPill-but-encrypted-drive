/*
 * NH hash algorithm, specifically the variant used by Adiantum hashing
 *
 * Copyright (C) 2018 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include "primitives.h"



void nh_generic(const u32 *key, const u8 *message, size_t message_len, u8 *hash)
{
	u64 sums[4] = { 0, 0, 0, 0 };

	BUILD_BUG_ON(NH_PAIR_STRIDE != 2);
	BUILD_BUG_ON(NH_NUM_PASSES != 4);

	while (message_len) {
		u32 m0 = get_unaligned_le32(message + 0);
		u32 m1 = get_unaligned_le32(message + 4);
		u32 m2 = get_unaligned_le32(message + 8);
		u32 m3 = get_unaligned_le32(message + 12);

		sums[0] += (u64)(u32)(m0 + key[ 0]) * (u32)(m2 + key[ 2]);
		sums[1] += (u64)(u32)(m0 + key[ 4]) * (u32)(m2 + key[ 6]);
		sums[2] += (u64)(u32)(m0 + key[ 8]) * (u32)(m2 + key[10]);
		sums[3] += (u64)(u32)(m0 + key[12]) * (u32)(m2 + key[14]);
		sums[0] += (u64)(u32)(m1 + key[ 1]) * (u32)(m3 + key[ 3]);
		sums[1] += (u64)(u32)(m1 + key[ 5]) * (u32)(m3 + key[ 7]);
		sums[2] += (u64)(u32)(m1 + key[ 9]) * (u32)(m3 + key[11]);
		sums[3] += (u64)(u32)(m1 + key[13]) * (u32)(m3 + key[15]);
		key += NH_MESSAGE_UNIT / sizeof(key[0]);
		message += NH_MESSAGE_UNIT;
		message_len -= NH_MESSAGE_UNIT;
	}

	put_unaligned_le64(sums[0], hash + 0);
	put_unaligned_le64(sums[1], hash + 8);
	put_unaligned_le64(sums[2], hash + 16);
	put_unaligned_le64(sums[3], hash + 24);
}
