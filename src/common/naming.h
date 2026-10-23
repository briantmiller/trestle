/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TRESTLE_NAMING_H
#define TRESTLE_NAMING_H

#include "util.h"

#define TR_BRIDGE_PREFIX "tbr"
#define TR_VETH_PREFIX   "trv"
#define TR_HASH_CHARS    12

/* "tbr" + first 12 hex chars of MD5(network_name). */
void tr_bridge_name(const char *network, char out[TR_IFNAMSIZ]);

/* "trv" + first 12 hex chars of MD5("<network>:<user>:<container>"). */
void tr_veth_name(const char *network, const char *user, const char *container,
		  char out[TR_IFNAMSIZ]);

/* Interface alias shown by `ip link`: "trestle:<user>.<container>.<network>" */
void tr_veth_alias(const char *network, const char *user, const char *container,
		   char *out, size_t outlen);

/* Fully qualified host name: "<user>.<container>.<network>.trestle". Characters
 * that are not valid in a host name are replaced by '-'. */
void tr_fqdn(const char *network, const char *user, const char *container,
	     char *out, size_t outlen);

#endif
