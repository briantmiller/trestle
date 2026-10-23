/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Networks known to trestled: every explicit [network:NAME] section plus the
 * networks that were created from the [network:*] catch-all section.
 *
 * A network created from [network:*] is recorded in <state_dir>/wildcard/<name>
 * together with the subnet assigned to it from subnet_pool ("-" when the
 * catch-all section has no pool). The assignment is kept, so a network name
 * keeps its subnet across container restarts, bridge removal and daemon
 * restarts. Delete the file (with no containers on that network) to free it.
 */
#ifndef TRESTLE_NETSET_H
#define TRESTLE_NETSET_H

#include <stdbool.h>
#include <stddef.h>

#include "../common/config.h"

struct netset {
	const struct tr_network **all;  /* explicit networks first, then instances */
	size_t n;
	struct tr_network *inst;        /* storage for [network:*] instances */
	size_t ninst;
};

/* Load all known networks (fresh from disk every time). */
int netset_load(const struct tr_config *cfg, struct netset *ns);
void netset_free(struct netset *ns);

/*
 * Find the configuration for a network name.
 *  - an explicit section always wins;
 *  - otherwise the [network:*] section applies, stored in *storage;
 *    with materialize, the network is recorded and gets a subnet from
 *    subnet_pool if it has none yet.
 * Returns 0 and sets *out, 1 if the network is not permitted at all,
 * -1 on error (err set).
 */
int net_resolve(const struct tr_config *cfg, const char *name, bool materialize,
		struct tr_network *storage, const struct tr_network **out,
		bool *created, char *err, size_t errlen);

#endif
