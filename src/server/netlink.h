/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Minimal rtnetlink helpers (no libnl dependency). */
#ifndef TRESTLE_NETLINK_H
#define TRESTLE_NETLINK_H

#include <stdbool.h>
#include <stdint.h>

#include "../common/util.h"

struct nl_link {
	int ifindex;
	unsigned int flags;
	int master;                 /* 0 = none */
	int mtu;
	char name[TR_IFNAMSIZ];
	char kind[32];              /* "bridge", "veth", ... ("" if none) */
	char alias[256];
	uint8_t mac[6];
	bool has_mac;
};

/* Open a NETLINK_ROUTE socket in the current network namespace. */
int nl_open(void);

/* All functions return 0 on success or -errno. */
int nl_get_link(int fd, const char *name, struct nl_link *out);   /* -ENODEV if absent */
int nl_get_link_by_index(int fd, int ifindex, struct nl_link *out);

typedef int (*nl_link_cb)(const struct nl_link *l, void *ctx);
int nl_dump_links(int fd, nl_link_cb cb, void *ctx);

int nl_create_bridge(int fd, const char *name, int mtu, bool stp, bool vlan_filtering);
/* Create veth <host> in the current netns with peer <peer> directly placed in
 * the netns referenced by peer_nsfd. peer_mac may be NULL. */
int nl_create_veth(int fd, const char *host, const char *peer, int peer_nsfd,
		   int mtu, const uint8_t *peer_mac);
int nl_del_link(int fd, int ifindex);
int nl_set_up(int fd, int ifindex, bool up);
int nl_set_master(int fd, int ifindex, int master_ifindex); /* 0 = nomaster */
int nl_set_alias(int fd, int ifindex, const char *alias);
int nl_set_mtu(int fd, int ifindex, int mtu);

/* IPv4 addresses (host byte order) */
int nl_addr_add(int fd, int ifindex, uint32_t addr, uint8_t prefix);
int nl_addr_has(int fd, int ifindex, uint32_t addr, uint8_t *prefix_out); /* 1 yes, 0 no, <0 err */
int nl_addr_first(int fd, int ifindex, uint32_t *addr, uint8_t *prefix); /* -ENOENT if none */
int nl_route_add_default(int fd, int ifindex, uint32_t gw);

#endif
