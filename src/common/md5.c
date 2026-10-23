/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Straightforward RFC 1321 MD5 implementation. Not used for security,
 * only for deterministic interface naming. See md5.h.
 */
#include "md5.h"

#include <stdio.h>
#include <string.h>

static const uint32_t K[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
	0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
	0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
	0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
	0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
	0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static const uint8_t R[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

#define ROTL(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

static void md5_block(uint32_t st[4], const uint8_t blk[64])
{
	uint32_t m[16];
	for (int i = 0; i < 16; i++)
		m[i] = (uint32_t)blk[i * 4] | ((uint32_t)blk[i * 4 + 1] << 8) |
		       ((uint32_t)blk[i * 4 + 2] << 16) | ((uint32_t)blk[i * 4 + 3] << 24);

	uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
	for (int i = 0; i < 64; i++) {
		uint32_t f;
		int g;
		if (i < 16) {
			f = (b & c) | (~b & d);
			g = i;
		} else if (i < 32) {
			f = (d & b) | (~d & c);
			g = (5 * i + 1) % 16;
		} else if (i < 48) {
			f = b ^ c ^ d;
			g = (3 * i + 5) % 16;
		} else {
			f = c ^ (b | ~d);
			g = (7 * i) % 16;
		}
		uint32_t tmp = d;
		d = c;
		c = b;
		b = b + ROTL(a + f + K[i] + m[g], R[i]);
		a = tmp;
	}
	st[0] += a;
	st[1] += b;
	st[2] += c;
	st[3] += d;
}

void trestle_md5_init(trestle_md5_ctx *ctx)
{
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
	ctx->count = 0;
}

void trestle_md5_update(trestle_md5_ctx *ctx, const void *data, size_t len)
{
	const uint8_t *p = data;
	size_t have = (size_t)(ctx->count % 64);
	ctx->count += len;

	if (have) {
		size_t need = 64 - have;
		if (len < need) {
			memcpy(ctx->buffer + have, p, len);
			return;
		}
		memcpy(ctx->buffer + have, p, need);
		md5_block(ctx->state, ctx->buffer);
		p += need;
		len -= need;
	}
	while (len >= 64) {
		md5_block(ctx->state, p);
		p += 64;
		len -= 64;
	}
	if (len)
		memcpy(ctx->buffer, p, len);
}

void trestle_md5_final(trestle_md5_ctx *ctx, uint8_t digest[16])
{
	uint64_t bits = ctx->count * 8;
	static const uint8_t pad[64] = { 0x80 };
	size_t have = (size_t)(ctx->count % 64);
	size_t padlen = (have < 56) ? (56 - have) : (120 - have);
	uint8_t lenb[8];

	for (int i = 0; i < 8; i++)
		lenb[i] = (uint8_t)(bits >> (8 * i));
	trestle_md5_update(ctx, pad, padlen);
	trestle_md5_update(ctx, lenb, 8);

	for (int i = 0; i < 4; i++) {
		digest[i * 4]     = (uint8_t)(ctx->state[i]);
		digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 8);
		digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 16);
		digest[i * 4 + 3] = (uint8_t)(ctx->state[i] >> 24);
	}
	memset(ctx, 0, sizeof(*ctx));
}

void trestle_md5_hex(const void *data, size_t len, char out[33])
{
	static const char hx[] = "0123456789abcdef";
	trestle_md5_ctx ctx;
	uint8_t d[16];

	trestle_md5_init(&ctx);
	trestle_md5_update(&ctx, data, len);
	trestle_md5_final(&ctx, d);
	for (int i = 0; i < 16; i++) {
		out[i * 2]     = hx[d[i] >> 4];
		out[i * 2 + 1] = hx[d[i] & 0xf];
	}
	out[32] = '\0';
}
