/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "nft.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../common/log.h"
#include "netset.h"
#include "state.h"

/* ---- attachments as seen by the ruleset ------------------------------ */

struct port {
	const struct tr_network *net;
	char veth[TR_IFNAMSIZ];
	char mac[18];
	bool has_ip;
	uint32_t ip;
	uid_t uid;
	bool dhcp;
};

struct ports {
	struct port *v;
	size_t n, cap;
	const struct netset *ns;
};

static const struct tr_network *ns_find(const struct netset *ns, const char *name)
{
	for (size_t i = 0; i < ns->n; i++)
		if (!strcmp(ns->all[i]->name, name))
			return ns->all[i];
	return NULL;
}

static int collect_port(const struct tr_attachment *a, void *ctx)
{
	struct ports *ps = ctx;
	const struct tr_network *n = ns_find(ps->ns, a->network);
	uint8_t m[6];
	if (!n || !tr_valid_ifname(a->veth))
		return 0;
	if (ps->n == ps->cap) {
		ps->cap = ps->cap ? ps->cap * 2 : 32;
		ps->v = realloc(ps->v, ps->cap * sizeof(*ps->v));
		if (!ps->v)
			abort();
	}
	struct port *p = &ps->v[ps->n++];
	memset(p, 0, sizeof(*p));
	p->net = n;
	tr_strlcpy(p->veth, a->veth, sizeof(p->veth));
	if (tr_valid_mac(a->mac, m))
		tr_strlcpy(p->mac, a->mac, sizeof(p->mac));
	p->has_ip = a->has_ip;
	p->ip = a->ip;
	p->uid = a->uid;
	p->dhcp = a->dhcp;
	return 0;
}

static void load_ports(const struct tr_config *cfg, const struct netset *ns, struct ports *ps)
{
	memset(ps, 0, sizeof(*ps));
	ps->ns = ns;
	for (size_t i = 0; i < ns->n; i++)
		state_foreach(cfg->state_dir, ns->all[i]->name, collect_port, ps);
}

/* Emit "elements = { a, b }" items through a callback-free loop. */
typedef bool (*port_pred)(const struct port *p);
static bool p_protected(const struct port *p) { return p->net->anti_spoofing; }
static bool p_open(const struct port *p) { return !p->net->anti_spoofing; }
static bool p_mac(const struct port *p) { return p->net->anti_spoofing && p->mac[0]; }
static bool p_ip(const struct port *p) { return p->net->anti_spoofing && p->has_ip; }
/* addresses unknown to trestle (no IPAM): only the MAC is enforced */
static bool p_mac_only(const struct port *p) { return p->net->anti_spoofing && !p->net->has_subnet && !p->net->dhcp; }
static bool p_dhcp(const struct port *p) { return p->net->anti_spoofing && p->net->dhcp; }
static bool p_v6(const struct port *p) { return p->net->anti_spoofing && p->net->allow_ipv6; }
static bool p_iso(const struct port *p) { return p->net->isolation != TR_ISO_NONE; }

static void emit_set(struct buf *b, const char *name, const char *type, const struct ports *ps, port_pred pred,
		     int what)
{
	buf_printf(b, "\tset %s {\n\t\ttype %s;\n", name, type);
	bool first = true;
	for (size_t i = 0; i < ps->n; i++) {
		const struct port *p = &ps->v[i];
		if (!pred(p))
			continue;
		buf_printf(b, first ? "\t\telements = { " : ",\n\t\t\t     ");
		first = false;
		char ip[16];
		switch (what) {
		case 0: buf_printf(b, "\"%s\"", p->veth); break;
		case 1: buf_printf(b, "\"%s\" . %s", p->veth, p->mac); break;
		case 2: tr_fmt_ipv4(p->ip, ip); buf_printf(b, "\"%s\" . %s", p->veth, ip); break;
		}
	}
	if (!first)
		buf_printf(b, " }\n");
	buf_printf(b, "\t}\n");
}

/* ports allowed to talk to each other: same user (isolation = user) */
static void emit_peer_set(struct buf *b, const struct ports *ps)
{
	buf_printf(b, "\tset iso_peers {\n\t\ttype ifname . ifname;\n");
	bool first = true;
	for (size_t i = 0; i < ps->n; i++)
		for (size_t j = 0; j < ps->n; j++) {
			const struct port *a = &ps->v[i], *c = &ps->v[j];
			if (i == j || a->net != c->net || a->net->isolation != TR_ISO_USER || a->uid != c->uid)
				continue;
			buf_printf(b, first ? "\t\telements = { " : ",\n\t\t\t     ");
			first = false;
			buf_printf(b, "\"%s\" . \"%s\"", a->veth, c->veth);
		}
	if (!first)
		buf_printf(b, " }\n");
	buf_printf(b, "\t}\n");
}

/* Port security in the bridge family: frames entering the bridge from a
 * container's host-side veth. trv* ports that are not (yet) known are
 * dropped, so a port is never unprotected. */
static void emit_bridge_table(struct buf *b, const char *t, const struct ports *ps)
{
	buf_printf(b, "table bridge %s {\n", t);
	emit_set(b, "ports", "ifname", ps, p_protected, 0);
	emit_set(b, "open_ports", "ifname", ps, p_open, 0);
	emit_set(b, "port_mac", "ifname . ether_addr", ps, p_mac, 1);
	emit_set(b, "port_ip", "ifname . ipv4_addr", ps, p_ip, 2);
	emit_set(b, "mac_only_ports", "ifname", ps, p_mac_only, 0);
	emit_set(b, "dhcp_ports", "ifname", ps, p_dhcp, 0);
	emit_set(b, "v6_ports", "ifname", ps, p_v6, 0);
	emit_set(b, "iso_ports", "ifname", ps, p_iso, 0);
	emit_peer_set(b, ps);

	buf_printf(b,
		"\tchain prerouting {\n"
		"\t\ttype filter hook prerouting priority -200; policy accept;\n"
		"\t\tiifname @open_ports accept\n"
		"\t\tiifname @ports jump port_in\n"
		"\t\tiifname \"trv*\" counter drop comment \"unknown trestle port\"\n"
		"\t}\n"
		"\tchain port_in {\n"
		"\t\tiifname . ether saddr != @port_mac counter drop comment \"MAC spoofing\"\n"
		"\t\tether type vlan counter drop comment \"VLAN tagged frame from a container\"\n"
		"\t\tether type ip udp sport 67 counter drop comment \"DHCP server in a container\"\n"
		"\t\tether type ip6 icmpv6 type { nd-router-advert, nd-redirect } counter drop comment \"IPv6 RA/redirect from a container\"\n"
		"\t\tether type ip6 udp sport 547 counter drop comment \"DHCPv6 server in a container\"\n"
		"\t\tiifname @mac_only_ports accept\n"
		"\t\tether type arp jump arp_in\n"
		"\t\tether type ip jump ip_in\n"
		"\t\tether type ip6 iifname @v6_ports accept\n"
		"\t\tcounter drop comment \"other protocol\"\n"
		"\t}\n"
		"\tchain arp_in {\n"
		"\t\tiifname . arp saddr ether != @port_mac counter drop comment \"ARP sender MAC spoofing\"\n"
		"\t\tiifname . arp saddr ip @port_ip accept\n"
		"\t\tiifname @dhcp_ports arp saddr ip 0.0.0.0 accept comment \"address conflict probe\"\n"
		"\t\tcounter drop comment \"ARP sender IP spoofing\"\n"
		"\t}\n"
		"\tchain ip_in {\n"
		"\t\tiifname . ip saddr @port_ip accept\n"
		"\t\tiifname @dhcp_ports ip saddr 0.0.0.0 udp sport 68 udp dport 67 accept comment \"DHCP client\"\n"
		"\t\tcounter drop comment \"IP spoofing\"\n"
		"\t}\n"
		"\tchain forward {\n"
		"\t\ttype filter hook forward priority 0; policy accept;\n"
		"\t\tiifname @iso_ports oifname @iso_ports iifname . oifname != @iso_peers counter drop comment \"isolation\"\n"
		"\t}\n"
		"}\n");
}

/* L3 hairpin: a container sending to the gateway MAC with another
 * container's IP as destination is routed back onto the same bridge by the
 * host. For isolated networks only same-user pairs may do that. */
static void emit_hairpin_set(struct buf *b, const char *id, const struct tr_network *n, const struct ports *ps)
{
	buf_printf(b, "\tset iso_%s {\n\t\ttype ipv4_addr . ipv4_addr;\n", id);
	bool first = true;
	for (size_t i = 0; i < ps->n; i++)
		for (size_t j = 0; j < ps->n; j++) {
			const struct port *a = &ps->v[i], *c = &ps->v[j];
			if (i == j || a->net != n || c->net != n || n->isolation != TR_ISO_USER || a->uid != c->uid ||
			    !a->has_ip || !c->has_ip)
				continue;
			char x[16], y[16];
			tr_fmt_ipv4(a->ip, x);
			tr_fmt_ipv4(c->ip, y);
			buf_printf(b, first ? "\t\telements = { " : ",\n\t\t\t     ");
			first = false;
			buf_printf(b, "%s . %s", x, y);
		}
	if (!first)
		buf_printf(b, " }\n");
	buf_printf(b, "\t}\n");
}

static void chain_id(const char *bridge, char *out, size_t len)
{
	size_t i = 0;
	for (; bridge[i] && i + 1 < len; i++)
		out[i] = isalnum((unsigned char)bridge[i]) ? bridge[i] : '_';
	out[i] = '\0';
}

static void emit_port_rules(struct buf *b, const struct strv *rules)
{
	for (size_t i = 0; i < rules->n; i++) {
		const char *r = rules->v[i];
		if (!strcasecmp(r, "icmp")) {
			buf_printf(b, "\t\tmeta l4proto icmp accept\n");
			continue;
		}
		char proto[4] = { (char)tolower((unsigned char)r[0]), (char)tolower((unsigned char)r[1]),
				  (char)tolower((unsigned char)r[2]), 0 };
		buf_printf(b, "\t\t%s dport %s accept\n", proto, r + 4);
	}
}

static bool net_needs_rules(const struct tr_network *n)
{
	return n->firewall || n->masquerade || n->isolation != TR_ISO_NONE;
}

static bool net_needs_bridge_rules(const struct tr_network *n)
{
	return n->anti_spoofing || n->isolation != TR_ISO_NONE;
}

bool nft_build_ruleset(const struct tr_config *cfg, struct buf *b)
{
	struct netset ns;
	netset_load(cfg, &ns);   /* explicit networks and [network:*] instances */
	bool any = false, any_masq = false, any_br = false;
	for (size_t i = 0; i < ns.n; i++) {
		any |= net_needs_rules(ns.all[i]);
		any_masq |= ns.all[i]->masquerade;
		any_br |= net_needs_bridge_rules(ns.all[i]);
	}
	if (!any && !any_br) {
		netset_free(&ns);
		return false;
	}
	struct ports ps;
	load_ports(cfg, &ns, &ps);

	const char *t = cfg->nft_table;
	/* "add then delete" makes the replace idempotent and atomic in one
	 * transaction; both tables are replaced together */
	buf_printf(b, "table inet %s\ndelete table inet %s\n", t, t);
	buf_printf(b, "table bridge %s\ndelete table bridge %s\n", t, t);
	if (any_br)
		emit_bridge_table(b, t, &ps);
	if (!any) {
		free(ps.v);
		netset_free(&ns);
		return true;
	}
	buf_printf(b, "table inet %s {\n", t);
	for (size_t i = 0; i < ns.n; i++) {
		const struct tr_network *n = ns.all[i];
		char id[TR_IFNAMSIZ + 4];
		if (n->isolation == TR_ISO_NONE)
			continue;
		chain_id(n->bridge, id, sizeof(id));
		emit_hairpin_set(b, id, n, &ps);
	}

	for (size_t i = 0; i < ns.n; i++) {
		const struct tr_network *n = ns.all[i];
		char id[TR_IFNAMSIZ + 4];
		if (!n->firewall)
			continue;
		chain_id(n->bridge, id, sizeof(id));

		/* traffic leaving containers of this network */
		buf_printf(b, "\tchain out_%s {\n", id);
		buf_printf(b, "\t\t# network %s, bridge %s\n", n->name, n->bridge);
		for (size_t k = 0; k < n->nft_rules.n; k++)
			buf_printf(b, "\t\t%s\n", n->nft_rules.v[k]);
		for (size_t k = 0; k < n->allow_outbound_to.n; k++)
			buf_printf(b, "\t\tip daddr %s accept\n", n->allow_outbound_to.v[k]);
		buf_printf(b, "\t\t%s\n\t}\n", n->outbound_accept ? "accept" : "drop");

		/* traffic going to containers of this network */
		buf_printf(b, "\tchain in_%s {\n", id);
		for (size_t k = 0; k < n->nft_rules.n; k++)
			buf_printf(b, "\t\t%s\n", n->nft_rules.v[k]);
		for (size_t k = 0; k < n->allow_inbound_from.n; k++)
			buf_printf(b, "\t\tip saddr %s accept\n", n->allow_inbound_from.v[k]);
		emit_port_rules(b, &n->allow_inbound);
		buf_printf(b, "\t\t%s\n\t}\n", n->inbound_accept ? "accept" : "drop");
	}

	buf_printf(b, "\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n");
	bool any_fw = false;
	for (size_t i = 0; i < ns.n; i++)
		any_fw |= ns.all[i]->firewall;
	/* isolation first: an established flow must not survive switching it on */
	for (size_t i = 0; i < ns.n; i++) {
		const struct tr_network *n = ns.all[i];
		char id[TR_IFNAMSIZ + 4];
		if (n->isolation == TR_ISO_NONE)
			continue;
		chain_id(n->bridge, id, sizeof(id));
		buf_printf(b, "\t\tiifname \"%s\" oifname \"%s\" ip saddr . ip daddr != @iso_%s counter drop comment \"isolation\"\n",
			   n->bridge, n->bridge, id);
	}
	if (any_fw)
		buf_printf(b, "\t\tct state established,related accept\n\t\tct state invalid drop\n");
	for (size_t i = 0; i < ns.n; i++) {
		const struct tr_network *n = ns.all[i];
		char id[TR_IFNAMSIZ + 4];
		if (!n->firewall)
			continue;
		chain_id(n->bridge, id, sizeof(id));
		buf_printf(b, "\t\tiifname \"%s\" jump out_%s\n", n->bridge, id);
		buf_printf(b, "\t\toifname \"%s\" jump in_%s\n", n->bridge, id);
	}
	buf_printf(b, "\t}\n");

	if (any_masq) {
		buf_printf(b, "\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n");
		for (size_t i = 0; i < ns.n; i++) {
			const struct tr_network *n = ns.all[i];
			char net[16];
			if (!n->masquerade)
				continue;
			tr_fmt_ipv4(n->netaddr, net);
			buf_printf(b, "\t\tip saddr %s/%u oifname != \"%s\" masquerade\n", net, n->prefix, n->bridge);
		}
		buf_printf(b, "\t}\n");
	}
	buf_printf(b, "}\n");
	free(ps.v);
	netset_free(&ns);
	return true;
}

static int run_nft(const struct tr_config *cfg, const char *script)
{
	int in[2], errp[2];
	if (pipe2(in, O_CLOEXEC) < 0)
		return -1;
	if (pipe2(errp, O_CLOEXEC) < 0) {
		close(in[0]);
		close(in[1]);
		return -1;
	}
	pid_t pid = fork();
	if (pid < 0) {
		close(in[0]); close(in[1]); close(errp[0]); close(errp[1]);
		return -1;
	}
	if (pid == 0) {
		signal(SIGPIPE, SIG_DFL);
		signal(SIGHUP, SIG_DFL);
		dup2(in[0], 0);
		dup2(errp[1], 1);
		dup2(errp[1], 2);
		execl(cfg->nft_binary, "nft", "-f", "-", (char *)NULL);
		_exit(127);
	}
	close(in[0]);
	close(errp[1]);
	size_t len = strlen(script), off = 0;
	while (off < len) {
		ssize_t w = write(in[1], script + off, len - off);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		off += (size_t)w;
	}
	close(in[1]);
	struct buf out = { 0 };
	char chunk[1024];
	ssize_t r;
	while ((r = read(errp[0], chunk, sizeof(chunk))) != 0) {
		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (out.len < 16384)
			buf_append(&out, chunk, (size_t)r);
	}
	close(errp[0]);
	int status;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	int ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
	if (!ok)
		log_err("nft failed (status %d): %s", WIFEXITED(status) ? WEXITSTATUS(status) : -1,
			out.p ? out.p : (WIFEXITED(status) && WEXITSTATUS(status) == 127 ? "cannot execute nft" : ""));
	buf_free(&out);
	return ok ? 0 : -1;
}

int nft_apply(const struct tr_config *cfg)
{
	struct buf b = { 0 };
	if (!nft_build_ruleset(cfg, &b)) {
		buf_free(&b);
		return nft_cleanup(cfg);
	}
	log_debug("applying nftables ruleset:");
	for (const char *l = b.p; l && *l;) {
		const char *e = strchr(l, '\n');
		int n = e ? (int)(e - l) : (int)strlen(l);
		log_debug("  %.*s", n, l);
		l = e ? e + 1 : NULL;
	}
	int r = run_nft(cfg, b.p);
	if (!r)
		log_info("nftables table inet %s applied", cfg->nft_table);
	buf_free(&b);
	return r;
}

int nft_cleanup(const struct tr_config *cfg)
{
	if (access(cfg->nft_binary, X_OK) != 0)
		return 0;
	char script[256];
	snprintf(script, sizeof(script), "table inet %s\ndelete table inet %s\ntable bridge %s\ndelete table bridge %s\n",
		 cfg->nft_table, cfg->nft_table, cfg->nft_table, cfg->nft_table);
	return run_nft(cfg, script);
}
