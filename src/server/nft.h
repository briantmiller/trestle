/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TRESTLE_NFT_H
#define TRESTLE_NFT_H

#include "../common/config.h"
#include "../common/util.h"

/* Build the complete nftables ruleset for the configuration (pure; used by
 * the unit tests). Returns false when no network needs firewall rules. */
bool nft_build_ruleset(const struct tr_config *cfg, struct buf *out);

/* Apply (atomically replace) the trestle table, or remove it when no network
 * needs rules. Returns 0 or -1. */
int nft_apply(const struct tr_config *cfg);

/* Remove the trestle table. */
int nft_cleanup(const struct tr_config *cfg);

#endif
