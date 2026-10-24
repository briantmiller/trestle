/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Fuzz the daemon's decoding of the wire request (JSON from the socket). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/log.h"

int handler_fuzz_decode(const char *wire, int nsfd);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int init;
	if (!init) {
		tlog_init("fuzz", TLOG_STDERR, LOG_EMERG);
		init = 1;
	}
	if (size > 256 * 1024)
		return 0;
	char *s = malloc(size + 1);
	memcpy(s, data, size);
	s[size] = '\0';
	handler_fuzz_decode(s, -1);
	free(s);
	return 0;
}
