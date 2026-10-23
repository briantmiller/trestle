/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "naming.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "md5.h"

static void prefixed_hash(const char *prefix, const char *input, char out[TR_IFNAMSIZ])
{
	char hex[33];
	trestle_md5_hex(input, strlen(input), hex);
	snprintf(out, TR_IFNAMSIZ, "%s%.*s", prefix, TR_HASH_CHARS, hex);
}

void tr_bridge_name(const char *network, char out[TR_IFNAMSIZ])
{
	prefixed_hash(TR_BRIDGE_PREFIX, network, out);
}

void tr_veth_name(const char *network, const char *user, const char *container,
		  char out[TR_IFNAMSIZ])
{
	char key[3 * (TR_MAX_NAME + 1) + 8];
	snprintf(key, sizeof(key), "%s:%s:%s", network, user, container);
	prefixed_hash(TR_VETH_PREFIX, key, out);
}

void tr_veth_alias(const char *network, const char *user, const char *container,
		   char *out, size_t outlen)
{
	snprintf(out, outlen, "trestle:%s.%s.%s", user, container, network);
}

static void host_label(const char *in, char *out, size_t outlen)
{
	size_t i = 0;
	for (; in[i] && i + 1 < outlen && i < 63; i++) {
		unsigned char c = (unsigned char)in[i];
		out[i] = (isalnum(c) || c == '-') ? (char)tolower(c) : '-';
	}
	out[i] = '\0';
}

void tr_fqdn(const char *network, const char *user, const char *container,
	     char *out, size_t outlen)
{
	char u[64], c[64], n[64];
	host_label(user, u, sizeof(u));
	host_label(container, c, sizeof(c));
	host_label(network, n, sizeof(n));
	snprintf(out, outlen, "%s.%s.%s.trestle", u, c, n);
}
