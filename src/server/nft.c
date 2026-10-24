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
	return n->firewall || n->masquerade;
}

bool nft_build_ruleset(const struct tr_config *cfg, struct buf *b)
{
	struct netset ns;
	netset_load(cfg, &ns);   /* explicit networks and [network:*] instances */
	bool any = false, any_masq = false;
	for (size_t i = 0; i < ns.n; i++) {
		any |= net_needs_rules(ns.all[i]);
		any_masq |= ns.all[i]->masquerade;
	}
	if (!any) {
		netset_free(&ns);
		return false;
	}

	const char *t = cfg->nft_table;
	/* "add then delete" makes the replace idempotent and atomic in one transaction */
	buf_printf(b, "table inet %s\ndelete table inet %s\n", t, t);
	buf_printf(b, "table inet %s {\n", t);

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
	snprintf(script, sizeof(script), "table inet %s\ndelete table inet %s\n", cfg->nft_table, cfg->nft_table);
	return run_nft(cfg, script);
}
