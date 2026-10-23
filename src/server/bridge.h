/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TRESTLE_BRIDGE_H
#define TRESTLE_BRIDGE_H

#include <stdbool.h>
#include <stddef.h>

#include "../common/config.h"
#include "netlink.h"

/* Create (if needed) and configure the bridge of a network; returns its
 * ifindex or -1 with err set. */
int bridge_ensure(int nlfd, const struct tr_config *cfg, const struct tr_network *net,
		  bool *created, char *err, size_t errlen);

/* Delete the bridge if trestle created it, no other network manager claims
 * it and no ports (other than the configured uplink) remain. */
void bridge_maybe_remove(int nlfd, const struct tr_config *cfg, const struct tr_network *net);

/* Which other manager (if any) claims an interface: "NetworkManager",
 * "systemd-networkd", "libvirt" or NULL. Root of the probed paths can be
 * redirected for tests with prefix (normally ""). */
const char *bridge_foreign_manager(const char *prefix, const char *name, int ifindex);

#endif
