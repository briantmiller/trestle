/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "gc.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../common/log.h"
#include "bridge.h"
#include "dnsout.h"
#include "keeper.h"
#include "netlink.h"
#include "netset.h"
#include "nft.h"
#include "state.h"

void gc_report_free(struct gc_report *r)
{
	strv_clear(&r->removed);
	strv_clear(&r->leases);
	strv_clear(&r->keepers);
}

static int scan_ns_dir(const char *dir, const char *suffix, bool numeric, unsigned long long dev,
		       unsigned long long ino)
{
	DIR *d = opendir(dir);
	if (!d)
		return -1;
	struct dirent *de;
	int fd = -1;
	while (fd < 0 && (de = readdir(d))) {
		if (de->d_name[0] == '.' || (numeric && !isdigit((unsigned char)de->d_name[0])))
			continue;
		char p[PATH_MAX];
		struct stat st;
		snprintf(p, sizeof(p), "%s/%s%s", dir, de->d_name, suffix);
		if (stat(p, &st) == 0 && (unsigned long long)st.st_dev == dev && (unsigned long long)st.st_ino == ino)
			fd = open(p, O_RDONLY | O_CLOEXEC);
	}
	closedir(d);
	return fd;
}

int gc_find_netns(unsigned long long dev, unsigned long long ino)
{
	/* named namespaces (ip netns, CNI runtimes) may have no process in
	 * them; then any process inside (container, pause process) */
	int fd = scan_ns_dir("/run/netns", "", false, dev, ino);
	if (fd < 0)
		fd = scan_ns_dir("/var/run/netns", "", false, dev, ino);
	if (fd < 0)
		fd = scan_ns_dir("/proc", "/ns/net", true, dev, ino);
	return fd;
}

struct net_ctx {
	const struct tr_config *cfg;
	const struct gc_filter *f;
	const struct tr_network *net;    /* NULL if no longer configured */
	int nlfd;
	bool dry;
	struct gc_report *rep;
	struct strv live;                /* container ids with a kept record */
	bool changed;
};

static bool is_trestle_veth(const struct nl_link *l)
{
	return strncmp(l->alias, "trestle:", 8) == 0 && !strcmp(l->kind, "veth");
}

static int record_cb(const struct tr_attachment *a, void *ctx)
{
	struct net_ctx *c = ctx;
	struct nl_link l;
	bool link = nl_get_link(c->nlfd, a->veth, &l) == 0;
	bool stale;

	if (c->f->cni) {
		char key[160];
		snprintf(key, sizeof(key), "%s/%s", a->container_id, a->ifname);
		stale = !strcmp(a->mode, "cni") && a->uid == c->f->uid && !strv_contains(c->f->valid, key);
	} else {
		stale = !link;
	}
	if (!stale) {
		strv_push(&c->live, a->container_id);
		/* a DHCP attachment needs its keeper */
		if (!c->f->cni && a->dhcp && c->net && c->net->dhcp && !keeper_running(c->cfg, a->veth)) {
			char what[256];
			snprintf(what, sizeof(what), "%s %s", a->network, a->container_id);
			int nsfd = a->ns_ino ? gc_find_netns(a->ns_dev, a->ns_ino) : -1;
			if (nsfd < 0) {
				log_warn("gc: DHCP attachment %s (%s) has no keeper and its network namespace "
					 "cannot be found; its lease will not be renewed", a->veth, a->container_name);
				c->rep->errors++;
			} else {
				if (!c->dry && keeper_start(c->cfg, a, nsfd) == 0)
					log_info("gc: restarted DHCP keeper for %s", a->veth);
				strv_push(&c->rep->keepers, what);
				close(nsfd);
			}
		}
		return 0;
	}

	char what[320];
	snprintf(what, sizeof(what), "%s %s (%s, user %s)", a->network, a->container_id, a->container_name, a->user);
	strv_push(&c->rep->removed, what);
	if (c->dry)
		return 0;
	if (a->dhcp)
		keeper_stop(c->cfg, a->veth);
	if (link && is_trestle_veth(&l)) {
		int r = nl_del_link(c->nlfd, l.ifindex);
		if (r && r != -ENODEV) {
			log_warn("gc: cannot delete %s: %s", a->veth, strerror(-r));
			c->rep->errors++;
		}
	}
	ipam_release(c->cfg->state_dir, a->network, a->container_id);
	state_delete(c->cfg->state_dir, a->network, a->container_id);
	log_info("gc: removed stale attachment %s", what);
	c->changed = true;
	return 0;
}

static int orphan_lease_cb(uint32_t ip, const char *owner, void *ctx)
{
	struct net_ctx *c = ctx;
	if (strv_contains(&c->live, owner))
		return 0;
	struct tr_attachment a;
	if (state_load(c->cfg->state_dir, c->net ? c->net->name : "", owner, &a) == 0) {
		attachment_free(&a);
		return 0;
	}
	char s[16], what[320];
	tr_fmt_ipv4(ip, s);
	snprintf(what, sizeof(what), "%s %s %s", c->net ? c->net->name : "?", s, owner);
	strv_push(&c->rep->leases, what);
	if (!c->dry) {
		ipam_release_ip(c->cfg->state_dir, c->net ? c->net->name : "", ip);
		log_info("gc: released orphaned lease %s", what);
		c->changed = true;
	}
	return 0;
}

int gc_run(const struct tr_config *cfg, int nlfd, const struct gc_filter *f, bool dry_run, struct gc_report *rep)
{
	struct strv names = { 0 };
	if (f->network) {
		strv_push(&names, f->network);
	} else {
		struct netset ns;
		netset_load(cfg, &ns);
		for (size_t i = 0; i < ns.n; i++)
			strv_push(&names, ns.all[i]->name);
		netset_free(&ns);
		state_networks(cfg->state_dir, &names);
	}
	bool any = false;
	for (size_t i = 0; i < names.n; i++) {
		struct tr_network storage;
		const struct tr_network *net = NULL;
		char err[256];
		if (net_resolve(cfg, names.v[i], false, &storage, &net, NULL, err, sizeof(err)) != 0)
			net = NULL;
		struct net_ctx c = { .cfg = cfg, .f = f, .net = net, .nlfd = nlfd, .dry = dry_run, .rep = rep };
		state_foreach(cfg->state_dir, names.v[i], record_cb, &c);
		if (!f->cni && net)
			ipam_foreach(cfg->state_dir, names.v[i], orphan_lease_cb, &c);
		else if (!f->cni) {
			/* network no longer configured: its leases have no meaning */
			struct tr_network tmp = { 0 };
			tr_strlcpy(tmp.name, names.v[i], sizeof(tmp.name));
			c.net = &tmp;
			ipam_foreach(cfg->state_dir, names.v[i], orphan_lease_cb, &c);
			c.net = NULL;
		}
		if (c.changed && net) {
			dns_refresh(cfg, net);
			bridge_maybe_remove(nlfd, cfg, net);
		}
		any |= c.changed;
		strv_clear(&c.live);
	}
	strv_clear(&names);
	if (any)
		nft_apply(cfg);
	return 0;
}
