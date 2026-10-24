/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "config.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "log.h"
#include "naming.h"

#define MAX_CONFIG_SIZE (1024 * 1024)

static int seterr(char *errbuf, size_t errlen, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));
static int seterr(char *errbuf, size_t errlen, const char *fmt, ...)
{
	va_list ap;
	if (errbuf && errlen) {
		va_start(ap, fmt);
		vsnprintf(errbuf, errlen, fmt, ap);
		va_end(ap);
	}
	return -1;
}

void config_defaults(struct tr_config *c)
{
	memset(c, 0, sizeof(*c));
	tr_strlcpy(c->socket_path, TRESTLE_DEFAULT_SOCKET, sizeof(c->socket_path));
	tr_strlcpy(c->socket_owner, "root", sizeof(c->socket_owner));
	tr_strlcpy(c->socket_group, "root", sizeof(c->socket_group));
	c->socket_mode = 0777;
	tr_strlcpy(c->client_binary, TRESTLE_DEFAULT_CLIENT, sizeof(c->client_binary));
	tr_strlcpy(c->server_binary, TRESTLE_DEFAULT_SERVER, sizeof(c->server_binary));
	c->verify_server = TR_VERIFY_RELAXED;
	tr_strlcpy(c->state_dir, TRESTLE_DEFAULT_STATE, sizeof(c->state_dir));
	tr_strlcpy(c->hosts_path, "/etc/hosts", sizeof(c->hosts_path));
	c->log_level = LOG_INFO;
	c->request_timeout = 10;
	c->max_requests_per_user = 8;
	c->ip_forward = false;
	tr_strlcpy(c->nft_binary, TRESTLE_NFT_BINARY, sizeof(c->nft_binary));
	tr_strlcpy(c->nft_table, "trestle", sizeof(c->nft_table));
	c->firewall_cleanup = true;
	tr_strlcpy(c->aardvark_binary, TRESTLE_AARDVARK_BINARY, sizeof(c->aardvark_binary));
	tr_strlcpy(c->aardvark_dir, "/run/trestle/aardvark-dns", sizeof(c->aardvark_dir));
	c->aardvark_port = 53;
	c->networkmanager = TR_NM_AUTO;
	tr_strlcpy(c->firewall_cmd, "/usr/bin/firewall-cmd", sizeof(c->firewall_cmd));
	tr_strlcpy(c->nmcli_binary, "/usr/bin/nmcli", sizeof(c->nmcli_binary));
}

static void network_free(struct tr_network *n)
{
	strv_clear(&n->users);
	strv_clear(&n->allow_inbound);
	strv_clear(&n->allow_inbound_from);
	strv_clear(&n->allow_outbound_to);
	strv_clear(&n->nft_rules);
}

void config_free(struct tr_config *c)
{
	for (size_t i = 0; i < c->nnets; i++)
		network_free(&c->nets[i]);
	free(c->nets);
	c->nets = NULL;
	c->nnets = 0;
	if (c->has_wildcard)
		network_free(&c->wildcard);
	c->has_wildcard = false;
}

void config_expand_path(const char *tmpl, const char *network, char *out, size_t outlen)
{
	size_t o = 0;
	for (const char *p = tmpl; *p && o + 1 < outlen; p++) {
		if (p[0] == '%' && p[1] == 'n') {
			for (const char *q = network; *q && o + 1 < outlen; q++)
				out[o++] = *q;
			p++;
		} else {
			out[o++] = *p;
		}
	}
	out[o] = '\0';
}

bool config_wildcard_instance(const struct tr_config *c, const char *name, struct tr_network *out)
{
	if (!c->has_wildcard)
		return false;
	*out = c->wildcard;               /* shallow copy: lists are borrowed */
	out->is_wildcard = false;
	out->from_wildcard = true;
	tr_strlcpy(out->name, name, sizeof(out->name));
	tr_bridge_name(name, out->bridge);
	out->bridge_configured = false;
	out->has_subnet = false;
	return true;
}

int config_max_script_time(const struct tr_config *c)
{
	int max = 0;
	for (size_t i = 0; i <= c->nnets; i++) {
		const struct tr_network *n = i < c->nnets ? &c->nets[i] : (c->has_wildcard ? &c->wildcard : NULL);
		if (!n)
			break;
		/* one request can run create (new bridge) and setup, or teardown */
		int t = (n->create_script[0] ? n->script_timeout : 0) +
			(n->setup_script[0] || n->teardown_script[0] ? n->script_timeout : 0);
		if (t > max)
			max = t;
	}
	return max;
}

const struct tr_network *config_find_network(const struct tr_config *c, const char *name)
{
	for (size_t i = 0; i < c->nnets; i++)
		if (strcmp(c->nets[i].name, name) == 0)
			return &c->nets[i];
	return NULL;
}

static void network_defaults(struct tr_network *n, const char *name)
{
	memset(n, 0, sizeof(*n));
	tr_strlcpy(n->name, name, sizeof(n->name));
	n->outbound_accept = true;
	n->inbound_accept = false;
	n->podman_ipam = TR_PODMAN_IPAM_NONE;
	n->script_timeout = 30;
	n->subnet_prefix = 24;
}

static struct tr_network *get_or_add_network(struct tr_config *c, const char *name)
{
	if (!strcmp(name, "*")) {
		if (!c->has_wildcard) {
			network_defaults(&c->wildcard, "*");
			c->wildcard.is_wildcard = true;
			c->has_wildcard = true;
		}
		return &c->wildcard;
	}
	for (size_t i = 0; i < c->nnets; i++)
		if (strcmp(c->nets[i].name, name) == 0)
			return &c->nets[i];
	struct tr_network *nn = realloc(c->nets, (c->nnets + 1) * sizeof(*nn));
	if (!nn)
		abort();
	c->nets = nn;
	struct tr_network *n = &c->nets[c->nnets++];
	network_defaults(n, name);
	return n;
}

#define CPY(dst) do { \
	if (tr_strlcpy(dst, val, sizeof(dst)) >= sizeof(dst)) \
		return seterr(errbuf, errlen, "%s:%d: value for '%s' too long", fname, line, key); \
} while (0)

#define BOOL(dst) do { \
	bool _b; \
	if (!tr_parse_bool(val, &_b)) \
		return seterr(errbuf, errlen, "%s:%d: '%s' expects yes/no", fname, line, key); \
	dst = _b; \
} while (0)

static int set_global(struct tr_config *c, const char *key, const char *val,
		      const char *fname, int line, char *errbuf, size_t errlen)
{
	long v;
	if (!strcmp(key, "socket")) {
		if (val[0] != '/')
			return seterr(errbuf, errlen, "%s:%d: socket must be an absolute path", fname, line);
		CPY(c->socket_path);
	} else if (!strcmp(key, "socket_owner")) {
		CPY(c->socket_owner);
	} else if (!strcmp(key, "socket_group")) {
		CPY(c->socket_group);
	} else if (!strcmp(key, "socket_mode")) {
		char *end;
		errno = 0;
		unsigned long m = strtoul(val, &end, 8);
		if (errno || *end || m > 07777)
			return seterr(errbuf, errlen, "%s:%d: socket_mode must be octal (e.g. 0770)", fname, line);
		c->socket_mode = (mode_t)m;
	} else if (!strcmp(key, "client_binary")) {
		CPY(c->client_binary);
	} else if (!strcmp(key, "server_binary")) {
		CPY(c->server_binary);
	} else if (!strcmp(key, "verify_server")) {
		if (!strcasecmp(val, "strict"))
			c->verify_server = TR_VERIFY_STRICT;
		else if (!strcasecmp(val, "relaxed"))
			c->verify_server = TR_VERIFY_RELAXED;
		else if (!strcasecmp(val, "no") || !strcasecmp(val, "none"))
			c->verify_server = TR_VERIFY_NONE;
		else
			return seterr(errbuf, errlen, "%s:%d: verify_server must be strict, relaxed or no", fname, line);
	} else if (!strcmp(key, "server_selinux_type")) {
		CPY(c->server_selinux_type);
	} else if (!strcmp(key, "state_dir")) {
		CPY(c->state_dir);
	} else if (!strcmp(key, "hosts_path")) {
		CPY(c->hosts_path);
	} else if (!strcmp(key, "log_level")) {
		int l = tlog_level_from_string(val);
		if (l < 0)
			return seterr(errbuf, errlen, "%s:%d: unknown log_level '%s'", fname, line, val);
		c->log_level = l;
	} else if (!strcmp(key, "request_timeout")) {
		if (!tr_parse_int(val, 1, 600, &v))
			return seterr(errbuf, errlen, "%s:%d: request_timeout must be 1-600", fname, line);
		c->request_timeout = (int)v;
	} else if (!strcmp(key, "max_requests_per_user")) {
		if (!tr_parse_int(val, 1, 64, &v))
			return seterr(errbuf, errlen, "%s:%d: max_requests_per_user must be 1-64", fname, line);
		c->max_requests_per_user = (int)v;
	} else if (!strcmp(key, "ip_forward")) {
		BOOL(c->ip_forward);
	} else if (!strcmp(key, "nft_binary")) {
		CPY(c->nft_binary);
	} else if (!strcmp(key, "nft_table")) {
		if (!tr_valid_hostname_label(val))
			return seterr(errbuf, errlen, "%s:%d: invalid nft_table name", fname, line);
		CPY(c->nft_table);
	} else if (!strcmp(key, "firewall_cleanup")) {
		BOOL(c->firewall_cleanup);
	} else if (!strcmp(key, "networkmanager")) {
		bool b;
		if (!strcasecmp(val, "auto"))
			c->networkmanager = TR_NM_AUTO;
		else if (tr_parse_bool(val, &b))
			c->networkmanager = b ? TR_NM_YES : TR_NM_NO;
		else
			return seterr(errbuf, errlen, "%s:%d: networkmanager must be auto, yes or no", fname, line);
	} else if (!strcmp(key, "firewall_cmd")) {
		if (val[0] != '/')
			return seterr(errbuf, errlen, "%s:%d: firewall_cmd must be an absolute path", fname, line);
		CPY(c->firewall_cmd);
	} else if (!strcmp(key, "nmcli_binary")) {
		if (val[0] != '/')
			return seterr(errbuf, errlen, "%s:%d: nmcli_binary must be an absolute path", fname, line);
		CPY(c->nmcli_binary);
	} else if (!strcmp(key, "aardvark_binary")) {
		CPY(c->aardvark_binary);
	} else if (!strcmp(key, "aardvark_dir")) {
		CPY(c->aardvark_dir);
	} else if (!strcmp(key, "aardvark_port")) {
		if (!tr_parse_int(val, 1, 65535, &v))
			return seterr(errbuf, errlen, "%s:%d: aardvark_port must be 1-65535", fname, line);
		c->aardvark_port = (int)v;
	} else {
		return seterr(errbuf, errlen, "%s:%d: unknown key '%s' in [global]", fname, line, key);
	}
	return 0;
}

static int set_network(struct tr_network *n, const char *key, const char *val,
		       const char *fname, int line, char *errbuf, size_t errlen)
{
	long v;
	if (!strcmp(key, "bridge")) {
		if (!tr_valid_ifname(val))
			return seterr(errbuf, errlen, "%s:%d: invalid bridge name '%s'", fname, line, val);
		CPY(n->bridge);
		n->bridge_configured = true;
	} else if (!strcmp(key, "users")) {
		/* last definition wins so conf.d can override the main file */
		strv_clear(&n->users);
		strv_split_push(&n->users, val);
	} else if (!strcmp(key, "subnet")) {
		struct tr_ipv4net net;
		if (!strcasecmp(val, "none") || !*val) {
			n->has_subnet = false;
			n->seen_subnet = true;
			return 0;
		}
		if (!tr_parse_ipv4_cidr(val, &net) || net.prefix < 8 || net.prefix > 30)
			return seterr(errbuf, errlen,
				      "%s:%d: subnet must be <gateway-ip>/<8-30>, e.g. 10.0.0.1/24", fname, line);
		uint32_t mask = tr_prefix_mask(net.prefix);
		uint32_t na = net.addr & mask, bc = na | ~mask;
		if (net.addr == na || net.addr == bc)
			return seterr(errbuf, errlen,
				      "%s:%d: subnet address must be a host address (the bridge IP), not the network or broadcast address",
				      fname, line);
		n->has_subnet = true;
		n->seen_subnet = true;
		n->gateway = net.addr;
		n->prefix = net.prefix;
		n->netaddr = na;
		n->broadcast = bc;
	} else if (!strcmp(key, "mtu")) {
		if (!tr_parse_int(val, 68, 65535, &v))
			return seterr(errbuf, errlen, "%s:%d: mtu must be 68-65535", fname, line);
		n->mtu = (int)v;
	} else if (!strcmp(key, "stp")) {
		BOOL(n->stp);
	} else if (!strcmp(key, "vlan_filtering")) {
		BOOL(n->vlan_filtering);
	} else if (!strcmp(key, "uplink")) {
		if (*val && !tr_valid_ifname(val))
			return seterr(errbuf, errlen, "%s:%d: invalid uplink interface '%s'", fname, line, val);
		CPY(n->uplink);
	} else if (!strcmp(key, "hosts_file")) {
		BOOL(n->hosts_file);
	} else if (!strcmp(key, "dnsmasq_hosts")) {
		if (*val && val[0] != '/')
			return seterr(errbuf, errlen, "%s:%d: dnsmasq_hosts must be an absolute path", fname, line);
		CPY(n->dnsmasq_hosts);
	} else if (!strcmp(key, "dnsmasq_pid_file")) {
		if (*val && val[0] != '/')
			return seterr(errbuf, errlen, "%s:%d: dnsmasq_pid_file must be an absolute path", fname, line);
		CPY(n->dnsmasq_pid_file);
	} else if (!strcmp(key, "aardvark_dns")) {
		BOOL(n->aardvark_dns);
	} else if (!strcmp(key, "podman_ipam")) {
		if (!strcasecmp(val, "none"))
			n->podman_ipam = TR_PODMAN_IPAM_NONE;
		else if (!strcasecmp(val, "host-local"))
			n->podman_ipam = TR_PODMAN_IPAM_HOST_LOCAL;
		else
			return seterr(errbuf, errlen, "%s:%d: podman_ipam must be none or host-local", fname, line);
	} else if (!strcmp(key, "firewall")) {
		BOOL(n->firewall);
	} else if (!strcmp(key, "masquerade")) {
		BOOL(n->masquerade);
	} else if (!strcmp(key, "inbound_policy") || !strcmp(key, "outbound_policy")) {
		bool acc;
		if (!strcasecmp(val, "accept"))
			acc = true;
		else if (!strcasecmp(val, "drop"))
			acc = false;
		else
			return seterr(errbuf, errlen, "%s:%d: %s must be accept or drop", fname, line, key);
		if (key[0] == 'i')
			n->inbound_accept = acc;
		else
			n->outbound_accept = acc;
	} else if (!strcmp(key, "allow_inbound")) {
		strv_clear(&n->allow_inbound);
		strv_split_push(&n->allow_inbound, val);
	} else if (!strcmp(key, "allow_inbound_from")) {
		strv_clear(&n->allow_inbound_from);
		strv_split_push(&n->allow_inbound_from, val);
	} else if (!strcmp(key, "allow_outbound_to")) {
		strv_clear(&n->allow_outbound_to);
		strv_split_push(&n->allow_outbound_to, val);
	} else if (!strcmp(key, "subnet_pool")) {
		struct tr_ipv4net pool;
		if (!n->is_wildcard)
			return seterr(errbuf, errlen, "%s:%d: subnet_pool is only valid in [network:*]", fname, line);
		if (!tr_parse_ipv4_cidr(val, &pool) || pool.prefix < 8 || pool.prefix > 30 ||
		    (pool.addr & ~tr_prefix_mask(pool.prefix)) != 0)
			return seterr(errbuf, errlen,
				      "%s:%d: subnet_pool must be a network address/prefix (8-30), e.g. 10.100.0.0/16",
				      fname, line);
		n->has_pool = true;
		n->pool_addr = pool.addr;
		n->pool_prefix = pool.prefix;
	} else if (!strcmp(key, "subnet_prefix")) {
		if (!n->is_wildcard)
			return seterr(errbuf, errlen, "%s:%d: subnet_prefix is only valid in [network:*]", fname, line);
		if (!tr_parse_int(val, 8, 30, &v))
			return seterr(errbuf, errlen, "%s:%d: subnet_prefix must be 8-30", fname, line);
		n->subnet_prefix = (uint8_t)v;
	} else if (!strcmp(key, "create_script") || !strcmp(key, "setup_script") ||
		   !strcmp(key, "teardown_script")) {
		if (*val && val[0] != '/')
			return seterr(errbuf, errlen, "%s:%d: %s must be an absolute path", fname, line, key);
		if (key[0] == 'c')
			CPY(n->create_script);
		else if (key[0] == 's')
			CPY(n->setup_script);
		else
			CPY(n->teardown_script);
	} else if (!strcmp(key, "script_timeout")) {
		if (!tr_parse_int(val, 1, 600, &v))
			return seterr(errbuf, errlen, "%s:%d: script_timeout must be 1-600 seconds", fname, line);
		n->script_timeout = (int)v;
	} else if (!strcmp(key, "script_on_error")) {
		if (!strcasecmp(val, "ignore"))
			n->script_fail = false;
		else if (!strcasecmp(val, "fail"))
			n->script_fail = true;
		else
			return seterr(errbuf, errlen, "%s:%d: script_on_error must be ignore or fail", fname, line);
	} else if (!strcmp(key, "firewalld_zone")) {
		if (*val && !tr_valid_hostname_label(val))
			return seterr(errbuf, errlen, "%s:%d: invalid firewalld zone name '%s'", fname, line, val);
		CPY(n->firewalld_zone);
	} else if (!strcmp(key, "nft_rule")) {
		/* repeatable, accumulates across files */
		if (strchr(val, '\n') || strchr(val, ';') || strchr(val, '{') || strchr(val, '}'))
			return seterr(errbuf, errlen,
				      "%s:%d: nft_rule must be a single rule without ';', '{' or '}'", fname, line);
		strv_push(&n->nft_rules, val);
	} else {
		return seterr(errbuf, errlen, "%s:%d: unknown key '%s' in network section", fname, line, key);
	}
	return 0;
}

int config_parse_text(struct tr_config *c, const char *text, const char *fname,
		      char *errbuf, size_t errlen)
{
	char *dup = strdup(text), *save = NULL;
	enum { SEC_NONE, SEC_GLOBAL, SEC_NETWORK } sec = SEC_NONE;
	char netname[TR_MAX_NAME + 1] = "";
	int line = 0, rc = 0;

	if (!dup)
		abort();
	/* strtok_r would merge empty lines and break line numbers; walk manually */
	char *p = dup;
	(void)save;
	while (p && *p != '\0' && rc == 0) {
		char *nl = strchr(p, '\n');
		if (nl)
			*nl = '\0';
		line++;
		char *s = tr_trim(p);
		p = nl ? nl + 1 : NULL;

		if (!*s || *s == '#' || *s == ';')
			continue;
		if (*s == '[') {
			char *end = strchr(s, ']');
			if (!end || end[1] != '\0') {
				rc = seterr(errbuf, errlen, "%s:%d: malformed section header", fname, line);
				break;
			}
			*end = '\0';
			char *name = tr_trim(s + 1);
			if (!strcmp(name, "global")) {
				sec = SEC_GLOBAL;
			} else if (!strncmp(name, "network:", 8) || !strncmp(name, "network ", 8)) {
				char *nn = tr_trim(name + 8);
				size_t l = strlen(nn);
				if (l >= 2 && nn[0] == '"' && nn[l - 1] == '"') {
					nn[l - 1] = '\0';
					nn++;
				}
				if (strcmp(nn, "*") != 0 && !tr_valid_network_name(nn)) {
					rc = seterr(errbuf, errlen, "%s:%d: invalid network name '%s'", fname, line, nn);
					break;
				}
				tr_strlcpy(netname, nn, sizeof(netname));
				get_or_add_network(c, netname);
				sec = SEC_NETWORK;
			} else {
				rc = seterr(errbuf, errlen, "%s:%d: unknown section [%s]", fname, line, name);
				break;
			}
			continue;
		}
		char *eq = strchr(s, '=');
		if (!eq) {
			rc = seterr(errbuf, errlen, "%s:%d: expected key = value", fname, line);
			break;
		}
		*eq = '\0';
		char *key = tr_trim(s), *val = tr_trim(eq + 1);
		/* strip optional surrounding quotes */
		size_t vl = strlen(val);
		if (vl >= 2 && ((val[0] == '"' && val[vl - 1] == '"') || (val[0] == '\'' && val[vl - 1] == '\''))) {
			val[vl - 1] = '\0';
			val++;
		}
		switch (sec) {
		case SEC_GLOBAL:
			rc = set_global(c, key, val, fname, line, errbuf, errlen);
			break;
		case SEC_NETWORK:
			rc = set_network(get_or_add_network(c, netname), key, val, fname, line, errbuf, errlen);
			break;
		default:
			rc = seterr(errbuf, errlen, "%s:%d: key outside of a section", fname, line);
		}
	}
	free(dup);
	return rc;
}

static int load_file(struct tr_config *c, const char *path, bool must_exist,
		     char *errbuf, size_t errlen)
{
	char *text = tr_read_file(path, MAX_CONFIG_SIZE, NULL);
	if (!text) {
		if (!must_exist && errno == ENOENT)
			return 0;
		return seterr(errbuf, errlen, "cannot read %s: %s", path, strerror(errno));
	}
	int rc = config_parse_text(c, text, path, errbuf, errlen);
	free(text);
	return rc;
}

static int cmpstr(const void *a, const void *b)
{
	return strcmp(*(char *const *)a, *(char *const *)b);
}

int config_load(struct tr_config *c, const char *path, char *errbuf, size_t errlen)
{
	char dir[PATH_MAX];
	if (load_file(c, path, true, errbuf, errlen) < 0)
		return -1;

	/* conf.d next to the main file */
	tr_strlcpy(dir, path, sizeof(dir));
	char *slash = strrchr(dir, '/');
	if (slash)
		*slash = '\0';
	else
		tr_strlcpy(dir, ".", sizeof(dir));
	char ddir[PATH_MAX];
	if (snprintf(ddir, sizeof(ddir), "%s/conf.d", dir) >= (int)sizeof(ddir))
		return seterr(errbuf, errlen, "path too long");

	DIR *d = opendir(ddir);
	if (d) {
		struct strv files = { 0 };
		struct dirent *de;
		while ((de = readdir(d))) {
			size_t l = strlen(de->d_name);
			if (de->d_name[0] == '.' || l < 6 || strcmp(de->d_name + l - 5, ".conf"))
				continue;
			strv_push(&files, de->d_name);
		}
		closedir(d);
		if (files.n)
			qsort(files.v, files.n, sizeof(char *), cmpstr);
		int rc = 0;
		for (size_t i = 0; i < files.n && rc == 0; i++) {
			char fp[PATH_MAX];
			snprintf(fp, sizeof(fp), "%s/%s", ddir, files.v[i]);
			rc = load_file(c, fp, true, errbuf, errlen);
		}
		strv_clear(&files);
		if (rc < 0)
			return -1;
	}
	return config_finalize(c, errbuf, errlen);
}

static bool valid_port_rule(const char *r)
{
	if (!strcasecmp(r, "icmp"))
		return true;
	const char *colon = strchr(r, ':');
	if (!colon)
		return false;
	size_t pl = (size_t)(colon - r);
	if (!((pl == 3 && !strncasecmp(r, "tcp", 3)) || (pl == 3 && !strncasecmp(r, "udp", 3))))
		return false;
	const char *ports = colon + 1;
	char tmp[32];
	if (tr_strlcpy(tmp, ports, sizeof(tmp)) >= sizeof(tmp))
		return false;
	char *dash = strchr(tmp, '-');
	long a, b;
	if (dash) {
		*dash = '\0';
		return tr_parse_int(tmp, 1, 65535, &a) && tr_parse_int(dash + 1, 1, 65535, &b) && a <= b;
	}
	return tr_parse_int(tmp, 1, 65535, &a);
}

static int validate_network(struct tr_network *n, char *errbuf, size_t errlen)
{
	/* a network from [network:*] gets its subnet from the pool */
	bool addressed = n->has_subnet || n->has_pool;
	{
		if (n->users.n == 0)
			log_warn("network '%s' has no 'users' entry; nobody will be allowed to use it", n->name);
		for (size_t u = 0; u < n->users.n; u++) {
			const char *t = n->users.v[u];
			if (*t == '!')
				t++;
			if (*t == '@')
				t++;
			if (!*t)
				return seterr(errbuf, errlen, "network '%s': empty user/group entry", n->name);
		}
		if (n->aardvark_dns && !addressed)
			return seterr(errbuf, errlen, "network '%s': aardvark_dns requires subnet", n->name);
		if (n->masquerade && !addressed)
			return seterr(errbuf, errlen, "network '%s': masquerade requires subnet", n->name);
		if ((n->hosts_file || n->dnsmasq_hosts[0]) && !addressed)
			return seterr(errbuf, errlen, "network '%s': hosts_file/dnsmasq_hosts require subnet", n->name);
		for (size_t k = 0; k < n->allow_inbound.n; k++)
			if (!valid_port_rule(n->allow_inbound.v[k]))
				return seterr(errbuf, errlen,
					      "network '%s': allow_inbound entry '%s' must be tcp:PORT[-PORT], udp:PORT[-PORT] or icmp",
					      n->name, n->allow_inbound.v[k]);
		struct strv *cidrs[2] = { &n->allow_inbound_from, &n->allow_outbound_to };
		for (int l = 0; l < 2; l++)
			for (size_t k = 0; k < cidrs[l]->n; k++) {
				struct tr_ipv4net tmp;
				uint32_t a;
				if (!tr_parse_ipv4_cidr(cidrs[l]->v[k], &tmp) && !tr_parse_ipv4(cidrs[l]->v[k], &a))
					return seterr(errbuf, errlen, "network '%s': '%s' is not an IPv4 address/CIDR",
						      n->name, cidrs[l]->v[k]);
			}
	}
	return 0;
}

int config_finalize(struct tr_config *c, char *errbuf, size_t errlen)
{
	if (c->has_wildcard) {
		struct tr_network *w = &c->wildcard;
		if (w->bridge_configured)
			return seterr(errbuf, errlen,
				      "[network:*]: 'bridge' is not allowed (every network gets its own tbr bridge)");
		if (w->uplink[0])
			return seterr(errbuf, errlen,
				      "[network:*]: 'uplink' is not allowed (an interface can only join one bridge)");
		if (w->has_subnet)
			return seterr(errbuf, errlen,
				      "[network:*]: 'subnet' is not allowed (networks would overlap); use subnet_pool");
		if (w->has_pool && w->subnet_prefix < w->pool_prefix)
			return seterr(errbuf, errlen, "[network:*]: subnet_prefix /%u is larger than subnet_pool /%u",
				      w->subnet_prefix, w->pool_prefix);
		if (w->dnsmasq_hosts[0] && !strstr(w->dnsmasq_hosts, "%n"))
			return seterr(errbuf, errlen,
				      "[network:*]: dnsmasq_hosts must contain %%n (the network name), e.g. /etc/dnsmasq.d/trestle-%%n.hosts");
		if (validate_network(w, errbuf, errlen) < 0)
			return -1;
		for (size_t i = 0; i < c->nnets; i++) {
			struct tr_network *n = &c->nets[i];
			if (w->has_pool && n->has_subnet) {
				uint8_t p = n->prefix < w->pool_prefix ? n->prefix : w->pool_prefix;
				uint32_t m = tr_prefix_mask(p);
				if ((n->gateway & m) == (w->pool_addr & m))
					log_info("subnet of network '%s' lies in subnet_pool; it will be skipped", n->name);
			}
		}
	}
	for (size_t i = 0; i < c->nnets; i++) {
		struct tr_network *n = &c->nets[i];
		if (!n->bridge_configured)
			tr_bridge_name(n->name, n->bridge);
		if (validate_network(n, errbuf, errlen) < 0)
			return -1;
		/* two networks must not share a bridge, nor overlap subnets */
		for (size_t j = 0; j < i; j++) {
			struct tr_network *o = &c->nets[j];
			if (!strcmp(o->bridge, n->bridge))
				return seterr(errbuf, errlen, "networks '%s' and '%s' use the same bridge %s",
					      o->name, n->name, n->bridge);
			if (n->has_subnet && o->has_subnet) {
				uint8_t p = n->prefix < o->prefix ? n->prefix : o->prefix;
				uint32_t m = tr_prefix_mask(p);
				if ((n->gateway & m) == (o->gateway & m))
					return seterr(errbuf, errlen, "networks '%s' and '%s' have overlapping subnets",
						      o->name, n->name);
			}
		}
	}
	return 0;
}
