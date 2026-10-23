/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "handler.h"

#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <limits.h>
#include <unistd.h>

#include "../common/log.h"
#include "../common/naming.h"
#include "../common/proto.h"
#include "../common/request.h"
#include "bridge.h"
#include "checks.h"
#include "dnsout.h"
#include "hooks.h"
#include "netset.h"
#include "nft.h"
#include "netlink.h"
#include "state.h"

#ifndef TRESTLE_VERSION
#define TRESTLE_VERSION "0.1"
#endif

struct hctx {
	const struct tr_config *cfg;
	int sock;
	struct tr_peer peer;
	struct tr_request req;
	bool req_valid;
	enum tr_mode mode;
	int nsfd;                 /* fd passed by the client, -1 if none */
	bool rootless;
	const struct tr_network *net;
	struct tr_network net_storage;   /* network made from [network:*] */
	int nlfd;                 /* host netlink socket */
	char err[1024];
	int cni_code;
};

static int failf(struct hctx *h, int cni_code, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static int failf(struct hctx *h, int cni_code, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(h->err, sizeof(h->err), fmt, ap);
	va_end(ap);
	h->cni_code = cni_code;
	return -1;
}

static void respond(struct hctx *h, int code, const char *out)
{
	int r = tr_send_response(h->sock, code, out ? out : "", out ? strlen(out) : 0);
	if (r)
		log_warn("failed to send response: %s", strerror(-r));
}

static void respond_error(struct hctx *h)
{
	char *s = h->mode == TR_MODE_CNI
		  ? tr_format_cni_error(h->req.cni_version, h->cni_code ? h->cni_code : CNI_ERR_PLUGIN, h->err, NULL)
		  : tr_format_netavark_error(h->err);
	log_warn("request from pid %d uid %u (%s) failed: %s", (int)h->peer.pid, (unsigned)h->peer.uid,
		 h->peer.user[0] ? h->peer.user : "?", h->err);
	respond(h, 1, s);
	free(s);
}

static const char *json_env_lookup(void *ctx, const char *name)
{
	json_object *env = ctx, *v;
	if (!env || !json_object_object_get_ex(env, name, &v) || !json_object_is_type(v, json_type_string))
		return NULL;
	return json_object_get_string(v);
}

static char *to_json(json_object *o)
{
	char *s = strdup(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE));
	json_object_put(o);
	return s;
}

static void mac_fmt(const uint8_t m[6], char out[18])
{
	snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* ---- request decoding & validation ---------------------------------- */

static int decode_request(struct hctx *h, const char *wire)
{
	json_object *w = json_tokener_parse(wire);
	if (!w || !json_object_is_type(w, json_type_object)) {
		if (w)
			json_object_put(w);
		return failf(h, CNI_ERR_DECODE, "malformed request");
	}
	json_object *v, *mode, *cmd, *argv, *env, *nspath, *nsfd, *rootless, *in;
	int ok = json_object_object_get_ex(w, "version", &v) && json_object_get_int(v) == TR_PROTO_VERSION &&
		 json_object_object_get_ex(w, "mode", &mode) && json_object_is_type(mode, json_type_string) &&
		 json_object_object_get_ex(w, "command", &cmd) && json_object_is_type(cmd, json_type_string) &&
		 json_object_object_get_ex(w, "argv", &argv) && json_object_is_type(argv, json_type_array) &&
		 json_object_object_get_ex(w, "env", &env) && json_object_is_type(env, json_type_object) &&
		 json_object_object_get_ex(w, "netns_path", &nspath) && json_object_is_type(nspath, json_type_string) &&
		 json_object_object_get_ex(w, "netns_fd", &nsfd) && json_object_is_type(nsfd, json_type_boolean) &&
		 json_object_object_get_ex(w, "rootless", &rootless) && json_object_is_type(rootless, json_type_boolean) &&
		 json_object_object_get_ex(w, "stdin", &in) && json_object_is_type(in, json_type_string);
	if (!ok) {
		json_object_put(w);
		return failf(h, CNI_ERR_DECODE, "malformed request");
	}
	h->mode = strcmp(json_object_get_string(mode), "cni") == 0 ? TR_MODE_CNI : TR_MODE_NETAVARK;
	if (strcmp(json_object_get_string(mode), "cni") && strcmp(json_object_get_string(mode), "netavark")) {
		json_object_put(w);
		return failf(h, CNI_ERR_DECODE, "unknown mode");
	}
	h->rootless = json_object_get_boolean(rootless);
	if (json_object_get_boolean(nsfd) != (h->nsfd >= 0)) {
		json_object_put(w);
		return failf(h, CNI_ERR_DECODE, "netns fd flag does not match the received descriptor");
	}

	int rc;
	const char *stdin_text = json_object_get_string(in);
	if (h->mode == TR_MODE_CNI) {
		rc = tr_parse_cni(json_env_lookup, env, stdin_text, &h->req, h->err, sizeof(h->err), &h->cni_code);
	} else {
		size_t n = json_object_array_length(argv);
		if (n < 2 || n > 8) {
			json_object_put(w);
			return failf(h, CNI_ERR_DECODE, "invalid argument vector");
		}
		char *args[8];
		for (size_t i = 1; i < n; i++) {
			json_object *a = json_object_array_get_idx(argv, i);
			if (!json_object_is_type(a, json_type_string)) {
				json_object_put(w);
				return failf(h, CNI_ERR_DECODE, "invalid argument vector");
			}
			args[i - 1] = (char *)json_object_get_string(a);
		}
		rc = tr_parse_netavark((int)n - 1, args, stdin_text, &h->req, h->err, sizeof(h->err));
		h->cni_code = CNI_ERR_INVALID_CONFIG;
	}
	if (rc == 0 && strcmp(h->req.command, json_object_get_string(cmd)) != 0)
		rc = failf(h, CNI_ERR_DECODE, "command mismatch");
	if (rc == 0 && strcmp(h->req.netns_path, json_object_get_string(nspath)) != 0)
		rc = failf(h, CNI_ERR_DECODE, "netns path mismatch");
	if (rc == 0 && (h->req.cmd == TR_CMD_CNI_VERSION || h->req.cmd == TR_CMD_NV_INFO))
		rc = failf(h, CNI_ERR_DECODE, "%s is answered by the client", h->req.command);
	json_object_put(w);
	if (rc == 0)
		h->req_valid = true;
	return rc;
}

/* Obtain a validated netns fd for the container. */
static int get_netns(struct hctx *h)
{
	int fd = h->nsfd;
	if (fd < 0) {
		if (h->peer.uid != 0)
			return failf(h, CNI_ERR_INVALID_ENV,
				     "the client must pass the container network namespace as a file descriptor");
		if (!h->req.netns_path[0])
			return failf(h, CNI_ERR_INVALID_ENV, "no network namespace given");
		fd = open(h->req.netns_path, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			return failf(h, CNI_ERR_INVALID_ENV, "cannot open network namespace %s: %s",
				     h->req.netns_path, strerror(errno));
		h->nsfd = fd;
	}
	if (netns_validate(fd, h->peer.uid, h->err, sizeof(h->err)) < 0) {
		h->cni_code = CNI_ERR_INVALID_ENV;
		return -1;
	}
	return 0;
}

/* ---- hook scripts ---------------------------------------------------- */

static void hook_base(struct hctx *h, struct hook_info *hi, const char *event)
{
	memset(hi, 0, sizeof(*hi));
	hi->event = event;
	hi->mode = h->mode == TR_MODE_CNI ? "cni" : "netavark";
	hi->command = h->req.command;
	hi->net = h->net;
	hi->user = h->peer.user;
	hi->uid = h->peer.uid;
	hi->gid = h->peer.gid;
	hi->rootless = h->rootless;
	hi->netns_fd = -1;
	if (h->req.container_id[0])
		hi->container_id = h->req.container_id;
	if (h->req.container_name[0])
		hi->container_name = h->req.container_name;
	hi->aliases = &h->req.aliases;
	hi->k8s_pod_name = h->req.k8s_pod_name;
	hi->k8s_pod_namespace = h->req.k8s_pod_namespace;
	hi->netns_path = h->req.netns_path;
	if (h->req.ifname[0])
		hi->container_ifname = h->req.ifname;
}

/* Run a hook if configured. Returns -1 only when it failed and the network
 * has script_on_error = fail (and fail_allowed is true). */
static int run_hook(struct hctx *h, const char *script, const struct hook_info *hi, bool fail_allowed)
{
	char err[512];
	if (!script || !script[0])
		return 0;
	log_debug("running %s script %s for network %s", hi->event, script, h->net->name);
	if (hook_run(script, hi, h->net->script_timeout, err, sizeof(err)) == 0)
		return 0;
	if (fail_allowed && h->net->script_fail) {
		failf(h, CNI_ERR_PLUGIN, "%s", err);
		return -1;
	}
	log_warn("%s (ignored)", err);
	return 0;
}

static int run_create_hook(struct hctx *h, bool bridge_created, const char *podman_id)
{
	struct hook_info hi;
	hook_base(h, &hi, "create");
	hi.bridge_created = bridge_created;
	hi.podman_network_id = podman_id;
	/* the network event carries no container details */
	hi.container_id = hi.container_name = hi.container_ifname = NULL;
	hi.aliases = NULL;
	hi.k8s_pod_name = hi.k8s_pod_namespace = NULL;
	hi.netns_path = NULL;
	return run_hook(h, h->net->create_script, &hi, true);
}

/* ---- attach (CNI ADD / Netavark setup) ------------------------------ */

static char *build_add_output(struct hctx *h, const struct tr_attachment *a, const char *host_mac)
{
	const struct tr_network *n = h->net;
	char ip[16], gw[16], ipnet[24];
	if (a->has_ip) {
		tr_fmt_ipv4(a->ip, ip);
		tr_fmt_ipv4(n->gateway, gw);
		snprintf(ipnet, sizeof(ipnet), "%s/%u", ip, a->prefix);
	}

	if (h->mode == TR_MODE_CNI) {
		bool legacy = strcmp(h->req.cni_version, "1.0.0") < 0;
		json_object *o = json_object_new_object();
		json_object_object_add(o, "cniVersion", json_object_new_string(h->req.cni_version));
		json_object *ifs = json_object_new_array();
		json_object *hi = json_object_new_object();
		json_object_object_add(hi, "name", json_object_new_string(a->veth));
		json_object_object_add(hi, "mac", json_object_new_string(host_mac));
		json_object_array_add(ifs, hi);
		json_object *ci = json_object_new_object();
		json_object_object_add(ci, "name", json_object_new_string(a->ifname));
		json_object_object_add(ci, "mac", json_object_new_string(a->mac));
		json_object_object_add(ci, "sandbox", json_object_new_string(h->req.netns_path));
		json_object_array_add(ifs, ci);
		json_object_object_add(o, "interfaces", ifs);
		if (a->has_ip) {
			json_object *ips = json_object_new_array();
			json_object *e = json_object_new_object();
			if (legacy)
				json_object_object_add(e, "version", json_object_new_string("4"));
			json_object_object_add(e, "address", json_object_new_string(ipnet));
			json_object_object_add(e, "gateway", json_object_new_string(gw));
			json_object_object_add(e, "interface", json_object_new_int(1));
			json_object_array_add(ips, e);
			json_object_object_add(o, "ips", ips);
			json_object *routes = json_object_new_array();
			json_object *rt = json_object_new_object();
			json_object_object_add(rt, "dst", json_object_new_string("0.0.0.0/0"));
			json_object_object_add(rt, "gw", json_object_new_string(gw));
			json_object_array_add(routes, rt);
			json_object_object_add(o, "routes", routes);
		}
		json_object_object_add(o, "dns", json_object_new_object());
		return to_json(o);
	}

	/* Netavark StatusBlock */
	json_object *o = json_object_new_object();
	json_object *search = json_object_new_array(), *servers = json_object_new_array();
	if (n->aardvark_dns && a->has_ip) {
		json_object_array_add(search, json_object_new_string("dns.podman"));
		json_object_array_add(servers, json_object_new_string(gw));
	}
	json_object_object_add(o, "dns_search_domains", search);
	json_object_object_add(o, "dns_server_ips", servers);
	json_object *ifs = json_object_new_object();
	json_object *ifo = json_object_new_object();
	json_object_object_add(ifo, "mac_address", json_object_new_string(a->mac));
	json_object *subs = json_object_new_array();
	if (a->has_ip) {
		json_object *s = json_object_new_object();
		json_object_object_add(s, "ipnet", json_object_new_string(ipnet));
		json_object_object_add(s, "gateway", json_object_new_string(gw));
		json_object_array_add(subs, s);
	}
	json_object_object_add(ifo, "subnets", subs);
	json_object_object_add(ifs, a->ifname, ifo);
	json_object_object_add(o, "interfaces", ifs);
	return to_json(o);
}

static int do_attach(struct hctx *h, char **out)
{
	const struct tr_config *cfg = h->cfg;
	const struct tr_network *n = h->net;
	struct tr_attachment a;
	struct tr_attachment existing;
	int nlc = -1, r;
	bool veth_created = false, ip_taken = false;

	memset(&a, 0, sizeof(a));
	if (get_netns(h) < 0)
		return -1;

	bool br_created = false;
	int br = bridge_ensure(h->nlfd, cfg, n, &br_created, h->err, sizeof(h->err));
	if (br < 0) {
		h->cni_code = CNI_ERR_PLUGIN;
		return -1;
	}
	/* a network comes into existence on the host when its bridge is made */
	if (br_created && run_create_hook(h, true, NULL) < 0)
		return -1;

	if (state_load(cfg->state_dir, n->name, h->req.container_id, &existing) == 0) {
		attachment_free(&existing);
		return failf(h, CNI_ERR_PLUGIN, "container %s is already attached to network %s",
			     h->req.container_id, n->name);
	}

	tr_strlcpy(a.network, n->name, sizeof(a.network));
	tr_strlcpy(a.container_id, h->req.container_id, sizeof(a.container_id));
	tr_strlcpy(a.container_name, h->req.container_name, sizeof(a.container_name));
	tr_strlcpy(a.user, h->peer.user, sizeof(a.user));
	a.uid = h->peer.uid;
	tr_strlcpy(a.mode, h->mode == TR_MODE_CNI ? "cni" : "netavark", sizeof(a.mode));
	tr_strlcpy(a.ifname, h->req.ifname, sizeof(a.ifname));
	tr_veth_name(n->name, h->peer.user, h->req.container_name, a.veth);
	for (size_t i = 0; i < h->req.aliases.n; i++)
		strv_push(&a.aliases, h->req.aliases.v[i]);

	struct nl_link l;
	r = nl_get_link(h->nlfd, a.veth, &l);
	if (r == 0) {
		failf(h, CNI_ERR_PLUGIN,
		      "host interface %s already exists (user %s already has a container named '%s' on network %s)",
		      a.veth, h->peer.user, a.container_name, n->name);
		goto fail;
	}

	if (n->has_subnet) {
		if (ipam_allocate(cfg->state_dir, n, a.container_id, &h->req.static_ips, &a.ip,
				  h->err, sizeof(h->err)) < 0) {
			h->cni_code = CNI_ERR_PLUGIN;
			goto fail;
		}
		ip_taken = true;
		a.has_ip = true;
		a.prefix = n->prefix;
	} else if (h->req.static_ips.n) {
		failf(h, CNI_ERR_INVALID_CONFIG, "static IPs requested but network %s has no subnet configured", n->name);
		goto fail;
	}

	uint8_t mac[6], *macp = NULL;
	if (h->req.static_mac[0] && tr_valid_mac(h->req.static_mac, mac))
		macp = mac;

	r = nl_create_veth(h->nlfd, a.veth, a.ifname, h->nsfd, n->mtu, macp);
	if (r) {
		failf(h, CNI_ERR_PLUGIN, "cannot create veth pair %s/%s: %s%s", a.veth, a.ifname, strerror(-r),
		      r == -EEXIST ? " (interface name already used inside the container?)" : "");
		goto fail;
	}
	veth_created = true;

	r = nl_get_link(h->nlfd, a.veth, &l);
	if (r) {
		failf(h, CNI_ERR_PLUGIN, "veth %s vanished: %s", a.veth, strerror(-r));
		goto fail;
	}
	char alias[256];
	tr_veth_alias(n->name, h->peer.user, a.container_name, alias, sizeof(alias));
	if ((r = nl_set_alias(h->nlfd, l.ifindex, alias)) ||
	    (r = nl_set_master(h->nlfd, l.ifindex, br)) ||
	    (r = nl_set_up(h->nlfd, l.ifindex, true))) {
		failf(h, CNI_ERR_PLUGIN, "cannot configure %s: %s", a.veth, strerror(-r));
		goto fail;
	}
	char host_mac[18] = "";
	if (l.has_mac)
		mac_fmt(l.mac, host_mac);

	/* configure the container side */
	nlc = netns_nl_open(h->nsfd, h->err, sizeof(h->err));
	if (nlc < 0) {
		h->cni_code = CNI_ERR_PLUGIN;
		goto fail;
	}
	struct nl_link c;
	r = nl_get_link(nlc, a.ifname, &c);
	if (r) {
		failf(h, CNI_ERR_PLUGIN, "container interface %s not found: %s", a.ifname, strerror(-r));
		goto fail;
	}
	if (c.has_mac)
		mac_fmt(c.mac, a.mac);
	if ((r = nl_set_up(nlc, c.ifindex, true))) {
		failf(h, CNI_ERR_PLUGIN, "cannot bring up %s in container: %s", a.ifname, strerror(-r));
		goto fail;
	}
	if (a.has_ip) {
		if ((r = nl_addr_add(nlc, c.ifindex, a.ip, a.prefix)) && r != -EEXIST) {
			failf(h, CNI_ERR_PLUGIN, "cannot assign address in container: %s", strerror(-r));
			goto fail;
		}
		if ((r = nl_route_add_default(nlc, c.ifindex, n->gateway)) && r != -EEXIST) {
			failf(h, CNI_ERR_PLUGIN, "cannot add default route in container: %s", strerror(-r));
			goto fail;
		}
	}
	close(nlc);
	nlc = -1;

	if ((r = state_save(cfg->state_dir, &a))) {
		failf(h, CNI_ERR_IO, "cannot save state: %s", strerror(-r));
		goto fail;
	}
	dns_refresh(cfg, n);

	if (n->setup_script[0]) {
		struct hook_info hi;
		hook_base(h, &hi, "setup");
		hi.bridge_created = br_created;
		hi.host_ifname = a.veth;
		hi.container_ifname = a.ifname;
		hi.host_mac = host_mac;
		hi.container_mac = a.mac;
		hi.has_ip = a.has_ip;
		hi.ip = a.ip;
		hi.prefix = a.prefix;
		hi.netns_fd = h->nsfd;
		if (run_hook(h, n->setup_script, &hi, true) < 0) {
			/* undo the attachment: the container must not run half set up */
			state_delete(cfg->state_dir, n->name, a.container_id);
			if (nl_get_link(h->nlfd, a.veth, &l) == 0)
				nl_del_link(h->nlfd, l.ifindex);
			veth_created = false;
			ipam_release(cfg->state_dir, n->name, a.container_id);
			ip_taken = false;
			dns_refresh(cfg, n);
			bridge_maybe_remove(h->nlfd, cfg, n);
			goto fail;
		}
	}

	char ipbuf[16] = "-";
	if (a.has_ip)
		tr_fmt_ipv4(a.ip, ipbuf);
	log_info("%s %s: user %s container %s (%.12s) attached to %s via %s/%s ip %s",
		 a.mode, h->req.command, a.user, a.container_name, a.container_id, n->bridge,
		 a.veth, a.ifname, ipbuf);

	*out = build_add_output(h, &a, host_mac);
	attachment_free(&a);
	return 0;

fail:
	if (nlc >= 0)
		close(nlc);
	if (veth_created && nl_get_link(h->nlfd, a.veth, &l) == 0)
		nl_del_link(h->nlfd, l.ifindex);
	if (ip_taken)
		ipam_release(cfg->state_dir, n->name, a.container_id);
	attachment_free(&a);
	return -1;
}

/* ---- detach (CNI DEL / Netavark teardown) ---------------------------- */

static int do_detach(struct hctx *h)
{
	const struct tr_config *cfg = h->cfg;
	const struct tr_network *n = h->net;
	struct tr_attachment a;
	char veth[TR_IFNAMSIZ];
	bool have_rec = state_load(cfg->state_dir, n->name, h->req.container_id, &a) == 0;

	if (have_rec) {
		if (h->peer.uid != 0 && a.uid != h->peer.uid) {
			attachment_free(&a);
			return failf(h, CNI_ERR_PLUGIN, "container %s on network %s belongs to another user",
				     h->req.container_id, n->name);
		}
		tr_strlcpy(veth, a.veth, sizeof(veth));
	} else {
		tr_veth_name(n->name, h->peer.user, h->req.container_name, veth);
	}

	struct nl_link l;
	bool have_link = nl_get_link(h->nlfd, veth, &l) == 0;

	/* teardown hook runs while the interfaces still exist; its failure
	 * never stops the teardown */
	if (n->teardown_script[0]) {
		struct hook_info hi;
		char host_mac[18] = "";
		hook_base(h, &hi, "teardown");
		hi.host_ifname = veth;
		if (have_link && l.has_mac) {
			mac_fmt(l.mac, host_mac);
			hi.host_mac = host_mac;
		}
		if (have_rec) {
			hi.container_name = a.container_name;
			hi.container_ifname = a.ifname;
			hi.container_mac = a.mac[0] ? a.mac : NULL;
			hi.has_ip = a.has_ip;
			hi.ip = a.ip;
			hi.prefix = a.prefix;
			if (a.aliases.n)
				hi.aliases = &a.aliases;
		}
		run_hook(h, n->teardown_script, &hi, false);
	}

	if (have_link) {
		struct nl_link br;
		bool ours = strncmp(l.alias, "trestle:", 8) == 0 && !strcmp(l.kind, "veth");
		bool on_bridge = nl_get_link(h->nlfd, n->bridge, &br) == 0 && l.master == br.ifindex;
		if (ours && (on_bridge || !l.master)) {
			int r = nl_del_link(h->nlfd, l.ifindex);
			if (r && r != -ENODEV)
				log_warn("cannot delete %s: %s", veth, strerror(-r));
		} else {
			log_warn("not deleting %s: it is not a trestle veth on bridge %s", veth, n->bridge);
		}
	}

	/* only release state that belongs to this caller */
	if (have_rec || h->peer.uid == 0) {
		ipam_release(cfg->state_dir, n->name, h->req.container_id);
		state_delete(cfg->state_dir, n->name, h->req.container_id);
	}
	if (have_rec)
		attachment_free(&a);
	dns_refresh(cfg, n);
	bridge_maybe_remove(h->nlfd, cfg, n);
	log_info("%s %s: user %s container %s (%.12s) detached from %s",
		 h->mode == TR_MODE_CNI ? "cni" : "netavark", h->req.command, h->peer.user,
		 h->req.container_name, h->req.container_id, n->name);
	return 0;
}

/* ---- CNI CHECK ------------------------------------------------------- */

static int do_check(struct hctx *h)
{
	const struct tr_config *cfg = h->cfg;
	const struct tr_network *n = h->net;
	struct tr_attachment a;
	struct nl_link l, br, c;
	int rc = -1;

	if (get_netns(h) < 0)
		return -1;
	if (state_load(cfg->state_dir, n->name, h->req.container_id, &a) != 0)
		return failf(h, CNI_ERR_UNKNOWN_CONTAINER, "container %s is not attached to network %s",
			     h->req.container_id, n->name);
	if (h->peer.uid != 0 && a.uid != h->peer.uid) {
		failf(h, CNI_ERR_PLUGIN, "container belongs to another user");
		goto out;
	}
	if (nl_get_link(h->nlfd, n->bridge, &br) != 0) {
		failf(h, CNI_ERR_PLUGIN, "bridge %s is missing", n->bridge);
		goto out;
	}
	if (nl_get_link(h->nlfd, a.veth, &l) != 0 || l.master != br.ifindex) {
		failf(h, CNI_ERR_PLUGIN, "host interface %s is missing or not on %s", a.veth, n->bridge);
		goto out;
	}
	int nlc = netns_nl_open(h->nsfd, h->err, sizeof(h->err));
	if (nlc < 0) {
		h->cni_code = CNI_ERR_PLUGIN;
		goto out;
	}
	if (nl_get_link(nlc, a.ifname, &c) != 0) {
		failf(h, CNI_ERR_PLUGIN, "interface %s is missing in the container", a.ifname);
	} else if (a.has_ip && nl_addr_has(nlc, c.ifindex, a.ip, NULL) != 1) {
		failf(h, CNI_ERR_PLUGIN, "interface %s lost its address", a.ifname);
	} else {
		rc = 0;
	}
	close(nlc);
out:
	attachment_free(&a);
	return rc;
}

/* ---- Netavark create ------------------------------------------------- */

static int do_create(struct hctx *h, char **out)
{
	const struct tr_network *n = h->net;
	json_object *in = h->req.input, *v;
	char gw[16], netaddr[16], want[24];

	if (json_object_object_get_ex(in, "ipv6_enabled", &v) && json_object_get_boolean(v))
		return failf(h, 0, "trestle does not support IPv6 yet");

	if (json_object_object_get_ex(in, "network_interface", &v) && json_object_is_type(v, json_type_string) &&
	    *json_object_get_string(v) && strcmp(json_object_get_string(v), n->bridge) != 0)
		return failf(h, 0, "network %s uses bridge %s (from trestle configuration), not %s",
			     n->name, n->bridge, json_object_get_string(v));

	bool br_created = false;
	int br = bridge_ensure(h->nlfd, h->cfg, n, &br_created, h->err, sizeof(h->err));
	if (br < 0)
		return -1;
	json_object *idv;
	const char *podman_id = json_object_object_get_ex(in, "id", &idv) ? json_object_get_string(idv) : NULL;
	if (run_create_hook(h, br_created, podman_id) < 0)
		return -1;

	json_object_object_add(in, "network_interface", json_object_new_string(n->bridge));

	json_object *subnets = NULL;
	json_object_object_get_ex(in, "subnets", &subnets);
	size_t nsub = subnets && json_object_is_type(subnets, json_type_array) ? json_object_array_length(subnets) : 0;
	if (n->has_subnet) {
		tr_fmt_ipv4(n->gateway, gw);
		tr_fmt_ipv4(n->netaddr, netaddr);
		snprintf(want, sizeof(want), "%s/%u", netaddr, n->prefix);
	}
	for (size_t i = 0; i < nsub; i++) {
		json_object *s = json_object_array_get_idx(subnets, i), *sv, *gv;
		if (!n->has_subnet)
			return failf(h, 0, "network %s has no subnet in the trestle configuration", n->name);
		struct tr_ipv4net req;
		if (!json_object_object_get_ex(s, "subnet", &sv) || !tr_parse_ipv4_cidr(json_object_get_string(sv), &req))
			return failf(h, 0, "invalid subnet in network config");
		if ((req.addr & tr_prefix_mask(req.prefix)) != n->netaddr || req.prefix != n->prefix)
			return failf(h, 0, "subnet %s conflicts with the trestle subnet %s of network %s",
				     json_object_get_string(sv), want, n->name);
		if (json_object_object_get_ex(s, "gateway", &gv) && json_object_is_type(gv, json_type_string) &&
		    strcmp(json_object_get_string(gv), gw) != 0)
			return failf(h, 0, "gateway %s conflicts with the trestle bridge address %s",
				     json_object_get_string(gv), gw);
		json_object_object_add(s, "gateway", json_object_new_string(gw));
	}
	if (nsub == 0 && n->has_subnet && n->podman_ipam == TR_PODMAN_IPAM_HOST_LOCAL) {
		json_object *arr = json_object_new_array();
		json_object *s = json_object_new_object();
		json_object_object_add(s, "subnet", json_object_new_string(want));
		json_object_object_add(s, "gateway", json_object_new_string(gw));
		json_object_array_add(arr, s);
		json_object_object_add(in, "subnets", arr);
	}
	json_object *ipam = json_object_new_object();
	json_object_object_add(ipam, "driver",
			       json_object_new_string(n->podman_ipam == TR_PODMAN_IPAM_HOST_LOCAL ? "host-local" : "none"));
	json_object_object_add(in, "ipam_options", ipam);

	*out = strdup(json_object_to_json_string_ext(in, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE));
	log_info("netavark create: user %s created podman network %s (bridge %s)", h->peer.user, n->name, n->bridge);
	return 0;
}

/* ---- entry point ----------------------------------------------------- */

void handle_connection(const struct tr_config *cfg, int sock)
{
	struct hctx h = { .cfg = cfg, .sock = sock, .nsfd = -1, .nlfd = -1, .mode = TR_MODE_NETAVARK };
	char *wire = NULL, *out = NULL;
	size_t wlen;
	int r, lockfd = -1;

	if (peer_identify(sock, &h.peer, h.err, sizeof(h.err)) < 0) {
		log_warn("rejecting connection: %s", h.err);
		respond_error(&h);
		return;
	}
	r = tr_recv_request(sock, &wire, &wlen, &h.nsfd);
	if (r) {
		log_warn("bad request from pid %d: %s", (int)h.peer.pid, strerror(-r));
		return;
	}
	if (decode_request(&h, wire) < 0)
		goto error;
	log_debug("request: pid=%d uid=%u user=%s mode=%s cmd=%s rootless=%d fd=%d",
		  (int)h.peer.pid, (unsigned)h.peer.uid, h.peer.user,
		  h.mode == TR_MODE_CNI ? "cni" : "netavark", h.req.command, h.rootless, h.nsfd >= 0);

	/* 2. the connection must come from the trestle client binary */
	if (peer_verify_client_binary(&h.peer, cfg->client_binary, h.err, sizeof(h.err)) < 0) {
		h.cni_code = CNI_ERR_PLUGIN;
		goto error;
	}

	/* 1. the network must be configured and the user permitted */
	/* explicit [network:NAME] section, else the [network:*] catch-all */
	r = net_resolve(cfg, h.req.network, false, &h.net_storage, &h.net, NULL, h.err, sizeof(h.err));
	if (r == 1) {
		failf(&h, CNI_ERR_INVALID_CONFIG, "network '%s' is not permitted by trestle", h.req.network);
		goto error;
	}
	if (r < 0) {
		h.cni_code = CNI_ERR_IO;
		goto error;
	}
	char why[128];
	if (!acl_allowed(&h.net->users, &h.peer, why, sizeof(why))) {
		failf(&h, CNI_ERR_PLUGIN, "user '%s' is not permitted to use network '%s' (%s)",
		      h.peer.user, h.net->name, why);
		goto error;
	}
	log_debug("user %s on network %s: %s", h.peer.user, h.net->name, why);

	/* serialize all state changing work between concurrent requests */
	char lockpath[PATH_MAX];
	snprintf(lockpath, sizeof(lockpath), "%s/state.lock", cfg->state_dir);
	lockfd = open(lockpath, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (lockfd < 0 || flock(lockfd, LOCK_EX) < 0) {
		failf(&h, CNI_ERR_IO, "cannot lock %s: %s", lockpath, strerror(errno));
		goto error;
	}

	/* a network from [network:*] is recorded (and gets its subnet from
	 * subnet_pool) the first time something is attached or created */
	if (h.net->from_wildcard && (h.req.cmd == TR_CMD_CNI_ADD || h.req.cmd == TR_CMD_NV_SETUP ||
				     h.req.cmd == TR_CMD_NV_CREATE)) {
		bool created = false;
		if (net_resolve(cfg, h.req.network, true, &h.net_storage, &h.net, &created,
				h.err, sizeof(h.err)) != 0) {
			h.cni_code = CNI_ERR_PLUGIN;
			goto error;
		}
		if (created && (h.net->firewall || h.net->masquerade))
			nft_apply(cfg);   /* add the new bridge/subnet to the ruleset */
	}

	h.nlfd = nl_open();
	if (h.nlfd < 0) {
		failf(&h, CNI_ERR_IO, "netlink: %s", strerror(-h.nlfd));
		goto error;
	}

	switch (h.req.cmd) {
	case TR_CMD_CNI_ADD:
	case TR_CMD_NV_SETUP:
		r = do_attach(&h, &out);
		break;
	case TR_CMD_CNI_DEL:
	case TR_CMD_NV_TEARDOWN:
		r = do_detach(&h);
		break;
	case TR_CMD_CNI_CHECK:
		r = do_check(&h);
		break;
	case TR_CMD_NV_CREATE:
		r = do_create(&h, &out);
		break;
	default:
		r = failf(&h, CNI_ERR_INVALID_ENV, "unsupported command");
	}
	if (r < 0)
		goto error;
	respond(&h, 0, out);
	goto done;

error:
	respond_error(&h);
done:
	free(out);
	free(wire);
	if (h.nlfd >= 0)
		close(h.nlfd);
	if (h.nsfd >= 0)
		close(h.nsfd);
	if (lockfd >= 0)
		close(lockfd);   /* releases the lock */
	tr_request_free(&h.req);
}
