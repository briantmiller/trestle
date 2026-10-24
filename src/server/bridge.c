/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "bridge.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../common/log.h"
#include "../common/md5.h"
#include "firewalld.h"
#include "nm.h"
#include "state.h"

/* Does any regular file in dir (optionally filtered by suffix) contain needle? */
static bool dir_files_contain(const char *dir, const char *suffix, const char *needle)
{
	DIR *d = opendir(dir);
	if (!d)
		return false;
	struct dirent *de;
	bool hit = false;
	while (!hit && (de = readdir(d))) {
		if (de->d_name[0] == '.')
			continue;
		size_t l = strlen(de->d_name), sl = suffix ? strlen(suffix) : 0;
		if (suffix && (l < sl || strcmp(de->d_name + l - sl, suffix)))
			continue;
		char p[PATH_MAX];
		snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
		char *t = tr_read_file(p, 1024 * 1024, NULL);
		if (t) {
			hit = strstr(t, needle) != NULL;
			free(t);
		}
	}
	closedir(d);
	return hit;
}

static bool file_contains(const char *path, const char *needle)
{
	char *t = tr_read_file(path, 1024 * 1024, NULL);
	if (!t)
		return false;
	bool hit = strstr(t, needle) != NULL;
	free(t);
	return hit;
}

const char *bridge_foreign_manager(const char *prefix, const char *name, int ifindex)
{
	char p[PATH_MAX], needle[128];

	/* NetworkManager: runtime device state and connection profiles */
	snprintf(p, sizeof(p), "%s/run/NetworkManager/devices/%d", prefix, ifindex);
	if (ifindex > 0 && file_contains(p, "managed=true"))
		return "NetworkManager";
	if (nm_profile_claims(prefix, name))
		return "NetworkManager";

	/* systemd-networkd: link state and .netdev definitions */
	snprintf(p, sizeof(p), "%s/run/systemd/netif/links/%d", prefix, ifindex);
	if (ifindex > 0 && (file_contains(p, "NETWORK_FILE=/") || file_contains(p, "ADMIN_STATE=configured")))
		return "systemd-networkd";
	snprintf(needle, sizeof(needle), "Name=%s\n", name);
	const char *nd[] = { "/etc/systemd/network", "/run/systemd/network", "/usr/lib/systemd/network" };
	for (size_t i = 0; i < ARRAY_SIZE(nd); i++) {
		snprintf(p, sizeof(p), "%s%s", prefix, nd[i]);
		if (dir_files_contain(p, ".netdev", needle))
			return "systemd-networkd";
	}

	/* libvirt networks */
	char n1[128], n2[128];
	snprintf(n1, sizeof(n1), "<bridge name='%s'", name);
	snprintf(n2, sizeof(n2), "<bridge name=\"%s\"", name);
	const char *ld[] = { "/etc/libvirt/qemu/networks", "/run/libvirt/network" };
	for (size_t i = 0; i < ARRAY_SIZE(ld); i++) {
		snprintf(p, sizeof(p), "%s%s", prefix, ld[i]);
		if (dir_files_contain(p, ".xml", n1) || dir_files_contain(p, ".xml", n2))
			return "libvirt";
	}
	return NULL;
}

int bridge_ensure(int nlfd, const struct tr_config *cfg, const struct tr_network *net,
		  bool *created, char *err, size_t errlen)
{
	struct nl_link l;
	if (created)
		*created = false;
	int r = nl_get_link(nlfd, net->bridge, &l);
	if (r == -ENODEV) {
		/* decide before creating it: is NetworkManager meant to own it? */
		bool unmanage = nm_should_unmanage(cfg, net->bridge);
		/* stable, locally administered unicast MAC from the bridge name */
		uint8_t mac[6], dig[16];
		trestle_md5_ctx m;
		trestle_md5_init(&m);
		trestle_md5_update(&m, "trestle-bridge:", 15);
		trestle_md5_update(&m, net->bridge, strlen(net->bridge));
		trestle_md5_final(&m, dig);
		memcpy(mac, dig, 6);
		mac[0] = (uint8_t)((mac[0] & 0xfe) | 0x02);
		r = nl_create_bridge(nlfd, net->bridge, net->mtu, net->stp, net->vlan_filtering, mac);
		if (r && r != -EEXIST) {
			snprintf(err, errlen, "cannot create bridge %s: %s", net->bridge, strerror(-r));
			return -1;
		}
		if (!r) {
			if (created)
				*created = true;
			state_mark_bridge(cfg->state_dir, net->bridge, net->name);
			log_info("created bridge %s for network %s", net->bridge, net->name);
			if (unmanage)
				nm_set_unmanaged(cfg, net->bridge);
		}
		r = nl_get_link(nlfd, net->bridge, &l);
		if (!r) {
			char alias[128];
			snprintf(alias, sizeof(alias), "trestle:%s", net->name);
			if (state_bridge_marked(cfg->state_dir, net->bridge))
				nl_set_alias(nlfd, l.ifindex, alias);
		}
	}
	if (r) {
		snprintf(err, errlen, "cannot look up bridge %s: %s", net->bridge, strerror(-r));
		return -1;
	}
	if (strcmp(l.kind, "bridge") != 0) {
		snprintf(err, errlen, "interface %s exists but is not a bridge (kind '%s')", net->bridge, l.kind);
		return -1;
	}
	if (net->mtu > 0 && l.mtu != net->mtu) {
		r = nl_set_mtu(nlfd, l.ifindex, net->mtu);
		if (r)
			log_warn("cannot set MTU %d on %s: %s", net->mtu, net->bridge, strerror(-r));
	}
	if (net->uplink[0]) {
		struct nl_link up;
		r = nl_get_link(nlfd, net->uplink, &up);
		if (r) {
			snprintf(err, errlen, "uplink %s for bridge %s: %s", net->uplink, net->bridge, strerror(-r));
			return -1;
		}
		if (up.master != l.ifindex) {
			if (up.master) {
				snprintf(err, errlen, "uplink %s is already enslaved to another device", net->uplink);
				return -1;
			}
			r = nl_set_master(nlfd, up.ifindex, l.ifindex);
			if (r) {
				snprintf(err, errlen, "cannot add uplink %s to %s: %s", net->uplink, net->bridge, strerror(-r));
				return -1;
			}
			log_info("added uplink %s to bridge %s", net->uplink, net->bridge);
		}
		nl_set_up(nlfd, up.ifindex, true);
	}
	if (!(l.flags & 1 /* IFF_UP */)) {
		r = nl_set_up(nlfd, l.ifindex, true);
		if (r) {
			snprintf(err, errlen, "cannot bring up %s: %s", net->bridge, strerror(-r));
			return -1;
		}
	}
	/* firewalld zone: checked every time, a firewalld reload drops it */
	fwd_bind(cfg, net);

	if (net->has_subnet) {
		r = nl_addr_has(nlfd, l.ifindex, net->gateway, NULL);
		if (r == 0) {
			r = nl_addr_add(nlfd, l.ifindex, net->gateway, net->prefix);
			if (r && r != -EEXIST) {
				char gw[16];
				tr_fmt_ipv4(net->gateway, gw);
				snprintf(err, errlen, "cannot assign %s/%u to %s: %s", gw, net->prefix, net->bridge,
					 strerror(-r));
				return -1;
			}
		} else if (r < 0) {
			snprintf(err, errlen, "cannot read addresses of %s: %s", net->bridge, strerror(-r));
			return -1;
		}
	}
	return l.ifindex;
}

struct port_count {
	int master;
	int uplink;
	int n;
};

static int count_ports(const struct nl_link *l, void *ctx)
{
	struct port_count *c = ctx;
	if (l->master == c->master && l->ifindex != c->uplink)
		c->n++;
	return 0;
}

void bridge_maybe_remove(int nlfd, const struct tr_config *cfg, const struct tr_network *net)
{
	struct nl_link l;
	if (!state_bridge_marked(cfg->state_dir, net->bridge))
		return;
	if (nl_get_link(nlfd, net->bridge, &l) != 0) {
		state_unmark_bridge(cfg->state_dir, net->bridge);
		return;
	}
	const char *mgr = bridge_foreign_manager("", net->bridge, l.ifindex);
	if (mgr) {
		log_info("not removing bridge %s: it is managed by %s", net->bridge, mgr);
		return;
	}
	struct port_count c = { .master = l.ifindex };
	struct nl_link up;
	if (net->uplink[0] && nl_get_link(nlfd, net->uplink, &up) == 0)
		c.uplink = up.ifindex;
	if (nl_dump_links(nlfd, count_ports, &c) != 0 || c.n > 0)
		return;
	if (c.uplink)
		nl_set_master(nlfd, c.uplink, 0);
	fwd_unbind(cfg, net);
	int r = nl_del_link(nlfd, l.ifindex);
	if (r) {
		log_warn("cannot delete bridge %s: %s", net->bridge, strerror(-r));
		return;
	}
	state_unmark_bridge(cfg->state_dir, net->bridge);
	log_info("removed bridge %s (no containers left on network %s)", net->bridge, net->name);
}
