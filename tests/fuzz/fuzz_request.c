/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Fuzz the CNI and Netavark invocation parsers with arbitrary environment,
 * arguments and stdin. Input layout: byte 0 selects the mode; the rest is
 * split on 0x00 into fields. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/request.h"

struct env { char *k[16], *v[16]; int n; };

static const char *lookup(void *ctx, const char *name)
{
	struct env *e = ctx;
	for (int i = 0; i < e->n; i++)
		if (!strcmp(e->k[i], name))
			return e->v[i];
	return NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1 || size > 65536)
		return 0;
	char *buf = malloc(size + 1);
	memcpy(buf, data + 1, size - 1);
	buf[size - 1] = '\0';
	char *fields[24];
	int nf = 0;
	char *p = buf, *end = buf + size - 1;
	while (p <= end && nf < 24) {
		fields[nf++] = p;
		p += strlen(p) + 1;
	}
	struct tr_request r;
	char err[512];
	if (data[0] & 1) {
		/* CNI: fields = KEY=VALUE..., last field = stdin */
		static const char *keys[] = { "CNI_COMMAND", "CNI_CONTAINERID", "CNI_NETNS", "CNI_IFNAME",
					      "CNI_ARGS", "CNI_PATH" };
		struct env e = { .n = 0 };
		for (int i = 0; i < nf - 1 && i < 6; i++) {
			e.k[e.n] = (char *)keys[i];
			e.v[e.n++] = fields[i];
		}
		int code;
		tr_parse_cni(lookup, &e, nf ? fields[nf - 1] : NULL, &r, err, sizeof(err), &code);
	} else {
		/* Netavark: fields = args..., last field = stdin */
		int nargs = nf > 1 ? nf - 1 : 0;
		if (nargs > 4)
			nargs = 4;
		tr_parse_netavark(nargs, fields, nf ? fields[nf - 1] : "", &r, err, sizeof(err));
	}
	tr_request_free(&r);
	free(buf);
	return 0;
}
