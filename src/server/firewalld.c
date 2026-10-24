/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "firewalld.h"

#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../common/log.h"
#include "exec.h"
#include "netset.h"

#define FWD_TIMEOUT_MS 15000
#define FWD_NOT_RUNNING 252          /* firewall-cmd exit code */

/* Current zone of an interface: 1 = found (zone filled), 0 = in no zone,
 * -1 = firewalld not running / firewall-cmd unusable. */
static int current_zone(const struct tr_config *cfg, const char *ifname, char *zone, size_t zlen)
{
	char arg[64];
	snprintf(arg, sizeof(arg), "--get-zone-of-interface=%s", ifname);
	char *argv[] = { (char *)cfg->firewall_cmd, arg, NULL };
	struct buf out = { 0 };
	int r = tr_run_cmd(argv, FWD_TIMEOUT_MS, &out);
	char *text = out.p ? tr_trim(out.p) : "";
	int ret;
	if (r == 0) {
		tr_strlcpy(zone, text, zlen);
		ret = 1;
	} else if (r == 2) {             /* "no zone" */
		zone[0] = '\0';
		ret = 0;
	} else {
		if (r == FWD_NOT_RUNNING)
			log_debug("firewalld is not running; skipping zone of %s", ifname);
		else
			log_warn("%s --get-zone-of-interface=%s failed (status %d)%s%s", cfg->firewall_cmd,
				 ifname, r, *text ? ": " : "", text);
		ret = -1;
	}
	buf_free(&out);
	return ret;
}

static int zone_cmd(const struct tr_config *cfg, const char *action, const char *zone, const char *ifname)
{
	char z[160], a[64];
	snprintf(z, sizeof(z), "--zone=%s", zone);
	snprintf(a, sizeof(a), "--%s-interface=%s", action, ifname);
	char *argv[] = { (char *)cfg->firewall_cmd, z, a, NULL };
	struct buf out = { 0 };
	int r = tr_run_cmd(argv, FWD_TIMEOUT_MS, &out);
	if (r != 0) {
		char *text = out.p ? tr_trim(out.p) : "";
		log_warn("firewall-cmd --zone=%s --%s-interface=%s failed (status %d)%s%s", zone, action,
			 ifname, r, *text ? ": " : "", text);
	}
	buf_free(&out);
	return r == 0 ? 0 : -1;
}

int fwd_bind(const struct tr_config *cfg, const struct tr_network *net)
{
	char zone[128];
	if (!net->firewalld_zone[0])
		return 0;
	if (access(cfg->firewall_cmd, X_OK) != 0) {
		log_warn("firewalld_zone is set for network %s but %s is not executable", net->name,
			 cfg->firewall_cmd);
		return -1;
	}
	int r = current_zone(cfg, net->bridge, zone, sizeof(zone));
	if (r < 0)
		return 0;   /* firewalld not running: nothing to bind */
	if (r == 1 && !strcmp(zone, net->firewalld_zone))
		return 0;
	if (zone_cmd(cfg, "change", net->firewalld_zone, net->bridge) < 0)
		return -1;
	if (r == 1)
		log_info("moved bridge %s from firewalld zone %s to %s", net->bridge, zone, net->firewalld_zone);
	else
		log_info("added bridge %s to firewalld zone %s", net->bridge, net->firewalld_zone);
	return 0;
}

void fwd_unbind(const struct tr_config *cfg, const struct tr_network *net)
{
	char zone[128];
	if (!net->firewalld_zone[0] || access(cfg->firewall_cmd, X_OK) != 0)
		return;
	/* only undo our own binding */
	if (current_zone(cfg, net->bridge, zone, sizeof(zone)) == 1 && !strcmp(zone, net->firewalld_zone) &&
	    zone_cmd(cfg, "remove", zone, net->bridge) == 0)
		log_info("removed bridge %s from firewalld zone %s", net->bridge, zone);
}

void fwd_bind_all(const struct tr_config *cfg)
{
	struct netset ns;
	netset_load(cfg, &ns);
	for (size_t i = 0; i < ns.n; i++) {
		const struct tr_network *n = ns.all[i];
		if (n->firewalld_zone[0] && if_nametoindex(n->bridge) != 0)
			fwd_bind(cfg, n);
	}
	netset_free(&ns);
}
