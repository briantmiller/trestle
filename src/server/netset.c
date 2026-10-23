/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "netset.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../common/log.h"

static void wild_dir(const struct tr_config *cfg, char *out, size_t len)
{
	snprintf(out, len, "%s/wildcard", cfg->state_dir);
}

/* Apply a recorded assignment ("a.b.c.d/p" = bridge address, or "-"). */
static void apply_marker(struct tr_network *n, const char *text)
{
	struct tr_ipv4net net;
	if (!tr_parse_ipv4_cidr(text, &net) || net.prefix < 8 || net.prefix > 30)
		return;
	uint32_t mask = tr_prefix_mask(net.prefix);
	n->has_subnet = true;
	n->gateway = net.addr;
	n->prefix = net.prefix;
	n->netaddr = net.addr & mask;
	n->broadcast = n->netaddr | ~mask;
}

static int read_marker(const struct tr_config *cfg, const char *name, struct tr_network *n)
{
	char dir[PATH_MAX], path[PATH_MAX];
	wild_dir(cfg, dir, sizeof(dir));
	if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int)sizeof(path))
		return -ENAMETOOLONG;
	char *t = tr_read_file(path, 256, NULL);
	if (!t)
		return -errno;
	apply_marker(n, tr_trim(t));
	free(t);
	return 0;
}

int netset_load(const struct tr_config *cfg, struct netset *ns)
{
	memset(ns, 0, sizeof(*ns));
	size_t cap = cfg->nnets + 8;
	ns->all = calloc(cap, sizeof(*ns->all));
	if (!ns->all)
		abort();
	for (size_t i = 0; i < cfg->nnets; i++)
		ns->all[ns->n++] = &cfg->nets[i];
	if (!cfg->has_wildcard)
		return 0;

	char dir[PATH_MAX];
	wild_dir(cfg, dir, sizeof(dir));
	DIR *d = opendir(dir);
	if (!d)
		return 0;
	struct strv names = { 0 };
	struct dirent *de;
	while ((de = readdir(d)))
		if (tr_valid_network_name(de->d_name) && !strstr(de->d_name, ".trestle-tmp.") &&
		    !config_find_network(cfg, de->d_name))
			strv_push(&names, de->d_name);
	closedir(d);

	ns->inst = calloc(names.n ? names.n : 1, sizeof(*ns->inst));
	if (!ns->inst)
		abort();
	if (ns->n + names.n > cap) {
		cap = ns->n + names.n;
		ns->all = realloc(ns->all, cap * sizeof(*ns->all));
		if (!ns->all)
			abort();
	}
	for (size_t i = 0; i < names.n; i++) {
		struct tr_network *n = &ns->inst[ns->ninst];
		config_wildcard_instance(cfg, names.v[i], n);
		if (read_marker(cfg, names.v[i], n) < 0)
			continue;
		ns->ninst++;
		ns->all[ns->n++] = n;
	}
	strv_clear(&names);
	return 0;
}

void netset_free(struct netset *ns)
{
	free(ns->all);
	free(ns->inst);   /* instance lists are borrowed from the template */
	memset(ns, 0, sizeof(*ns));
}

static bool overlaps(uint32_t a, uint8_t pa, uint32_t b, uint8_t pb)
{
	uint8_t p = pa < pb ? pa : pb;
	uint32_t m = tr_prefix_mask(p);
	return (a & m) == (b & m);
}

/* Pick the first /subnet_prefix of the pool that no known network uses. */
static int allocate_subnet(const struct tr_config *cfg, struct tr_network *n, char *err, size_t errlen)
{
	const struct tr_network *w = &cfg->wildcard;
	struct netset ns;
	netset_load(cfg, &ns);
	uint64_t step = 1ull << (32 - w->subnet_prefix);
	uint64_t end = (uint64_t)w->pool_addr + (1ull << (32 - w->pool_prefix));
	int rc = -1;
	for (uint64_t cand = w->pool_addr; cand + step <= end; cand += step) {
		bool used = false;
		for (size_t i = 0; i < ns.n && !used; i++) {
			const struct tr_network *o = ns.all[i];
			if (o->has_subnet && overlaps((uint32_t)cand, w->subnet_prefix, o->netaddr, o->prefix))
				used = true;
		}
		if (used)
			continue;
		char buf[16];
		tr_fmt_ipv4((uint32_t)cand + 1, buf);
		struct buf text = { 0 };
		buf_printf(&text, "%s/%u", buf, w->subnet_prefix);
		apply_marker(n, text.p);
		buf_free(&text);
		rc = 0;
		break;
	}
	netset_free(&ns);
	if (rc < 0)
		snprintf(err, errlen, "subnet_pool of [network:*] has no free /%u left for network '%s'",
			 w->subnet_prefix, n->name);
	return rc;
}

int net_resolve(const struct tr_config *cfg, const char *name, bool materialize,
		struct tr_network *storage, const struct tr_network **out,
		bool *created, char *err, size_t errlen)
{
	if (created)
		*created = false;
	const struct tr_network *n = config_find_network(cfg, name);
	if (n) {
		*out = n;
		return 0;
	}
	if (!config_wildcard_instance(cfg, name, storage))
		return 1;
	*out = storage;
	if (read_marker(cfg, name, storage) == 0 || !materialize)
		return 0;

	/* first use of this network name: record it (and give it a subnet) */
	if (cfg->wildcard.has_pool && allocate_subnet(cfg, storage, err, errlen) < 0)
		return -1;
	char dir[PATH_MAX], path[PATH_MAX], gw[16];
	wild_dir(cfg, dir, sizeof(dir));
	int r = tr_mkdir_p(dir, 0700);
	if (r) {
		snprintf(err, errlen, "cannot create %s: %s", dir, strerror(-r));
		return -1;
	}
	snprintf(path, sizeof(path), "%s/%s", dir, name);
	struct buf text = { 0 };
	if (storage->has_subnet) {
		tr_fmt_ipv4(storage->gateway, gw);
		buf_printf(&text, "%s/%u\n", gw, storage->prefix);
	} else {
		buf_printf(&text, "-\n");
	}
	r = tr_write_file_atomic(path, text.p, text.len, 0600);
	buf_free(&text);
	if (r) {
		snprintf(err, errlen, "cannot record network %s: %s", name, strerror(-r));
		return -1;
	}
	if (created)
		*created = true;
	if (storage->has_subnet) {
		tr_fmt_ipv4(storage->gateway, gw);
		log_info("network %s configured from [network:*] (bridge %s, subnet %s/%u)",
			 name, storage->bridge, gw, storage->prefix);
	} else {
		log_info("network %s configured from [network:*] (bridge %s, no subnet)", name, storage->bridge);
	}
	return 0;
}
