/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * DHCP lease keepers. Every attachment on an ipam = dhcp network has one
 * small process ("trestled --dhcp-keeper NETWORK CONTAINER-ID", the
 * container's network namespace on fd 3) that renews the lease, follows
 * address changes and releases the lease on teardown. Keepers are started in
 * their own systemd scope (when systemd is available) so restarting
 * trestled does not interrupt them. Their pid is kept in
 * <state_dir>/dhcp/<host veth>.pid.
 */
#ifndef TRESTLE_KEEPER_H
#define TRESTLE_KEEPER_H

#include <stdbool.h>

#include "../common/config.h"
#include "state.h"

int keeper_start(const struct tr_config *cfg, const struct tr_attachment *a, int nsfd);
/* Stop the keeper of an attachment; it releases the lease first (it waits
 * up to 3 s for that). */
void keeper_stop(const struct tr_config *cfg, const char *veth);
bool keeper_running(const struct tr_config *cfg, const char *veth);

/* Entry point of the keeper process. */
int keeper_main(const char *cfgpath, const char *network, const char *cid, bool debug);

/* Configure a lease in the container (address + default route). */
int keeper_configure(int nlc, const char *ifname, uint32_t old_ip, uint8_t old_prefix,
		     uint32_t ip, uint8_t prefix, uint32_t router, char *err, size_t errlen);

#endif
