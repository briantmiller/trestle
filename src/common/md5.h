/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * trestle - self-contained MD5 (RFC 1321).
 *
 * MD5 is used ONLY to derive deterministic, short interface names. It is not
 * used for any security purpose.  Because this is a private implementation
 * and does not go through OpenSSL/libgcrypt, it keeps working on hosts that
 * run with FIPS mode enabled (where MD5 is blocked in the crypto providers).
 */
#ifndef TRESTLE_MD5_H
#define TRESTLE_MD5_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
	uint32_t state[4];
	uint64_t count;          /* bytes processed */
	uint8_t  buffer[64];
} trestle_md5_ctx;

void trestle_md5_init(trestle_md5_ctx *ctx);
void trestle_md5_update(trestle_md5_ctx *ctx, const void *data, size_t len);
void trestle_md5_final(trestle_md5_ctx *ctx, uint8_t digest[16]);

/* Convenience: hex digest (33 bytes incl. NUL) of a buffer. */
void trestle_md5_hex(const void *data, size_t len, char out[33]);

#endif
