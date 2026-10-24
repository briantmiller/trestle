/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TRESTLE_CONFIG_H
#define TRESTLE_CONFIG_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "util.h"

#ifndef TRESTLE_SYSCONFDIR
#define TRESTLE_SYSCONFDIR "/etc"
#endif
#ifndef TRESTLE_LIBEXECDIR
#define TRESTLE_LIBEXECDIR "/usr/libexec"
#endif
#ifndef TRESTLE_SBINDIR
#define TRESTLE_SBINDIR "/usr/sbin"
#endif
#ifndef TRESTLE_LOCALSTATEDIR
#define TRESTLE_LOCALSTATEDIR "/var/lib"
#endif

#ifndef TRESTLE_AARDVARK_BINARY
#define TRESTLE_AARDVARK_BINARY TRESTLE_LIBEXECDIR "/podman/aardvark-dns"
#endif
#ifndef TRESTLE_NFT_BINARY
#define TRESTLE_NFT_BINARY "/usr/sbin/nft"
#endif

#define TRESTLE_DEFAULT_CONFIG  TRESTLE_SYSCONFDIR "/trestle/trestle.conf"
/* in the root-owned state directory: unlike /tmp nobody else can create or
 * replace a file there (Netavark's private /run hides /run and /var/run, but
 * not /var/lib) */
#define TRESTLE_DEFAULT_SOCKET  TRESTLE_LOCALSTATEDIR "/trestle/trestle.sock"
#define TRESTLE_DEFAULT_CLIENT  TRESTLE_LIBEXECDIR "/trestle/trestle"
#define TRESTLE_DEFAULT_SERVER  TRESTLE_SBINDIR "/trestled"
#define TRESTLE_DEFAULT_STATE   TRESTLE_LOCALSTATEDIR "/trestle"

enum tr_ipam_mode { TR_PODMAN_IPAM_NONE, TR_PODMAN_IPAM_HOST_LOCAL };
enum tr_verify_mode { TR_VERIFY_STRICT, TR_VERIFY_RELAXED, TR_VERIFY_NONE };
enum tr_nm_mode { TR_NM_AUTO, TR_NM_YES, TR_NM_NO };
enum tr_isolation { TR_ISO_NONE, TR_ISO_USER, TR_ISO_CONTAINER };

struct tr_network {
	char name[TR_MAX_NAME + 1];
	char bridge[TR_IFNAMSIZ];      /* resolved (configured or tbr<hash>) */
	bool bridge_configured;        /* name came from the config file */

	struct strv users;             /* ACL tokens: user, @group, !user, !@group, * */

	bool has_subnet;
	uint32_t gateway;              /* host order: bridge address */
	uint8_t prefix;
	uint32_t netaddr, broadcast;   /* derived */

	int mtu;                       /* 0 = kernel default */
	bool stp;
	bool vlan_filtering;
	char uplink[TR_IFNAMSIZ];      /* optional physical NIC enslaved to the bridge */

	bool hosts_file;               /* write /etc/hosts entries */
	char dnsmasq_hosts[PATH_MAX];  /* optional addn-hosts file */
	char dnsmasq_pid_file[PATH_MAX];
	bool aardvark_dns;             /* Netavark: run/update aardvark-dns */
	enum tr_ipam_mode podman_ipam;

	/* nftables */
	bool firewall;
	bool masquerade;
	bool inbound_accept;           /* default policy for new inbound traffic */
	bool outbound_accept;          /* default policy for new outbound traffic */
	struct strv allow_inbound;     /* proto:port[-port] | icmp */
	struct strv allow_inbound_from;/* CIDRs */
	struct strv allow_outbound_to; /* CIDRs */
	struct strv nft_rules;         /* raw rules appended to the network's forward chain */
	char firewalld_zone[64];       /* put the bridge into this firewalld zone ("" = no) */

	/* port security (nftables bridge table) */
	bool anti_spoofing;            /* containers may only use their own MAC / IP */
	bool allow_ipv6;               /* let IPv6 from containers through (MAC checked) */
	enum tr_isolation isolation;   /* traffic between containers on the bridge */

	/* ipam = dhcp: trestled obtains a lease from the LAN's DHCP server for
	 * each container and keeps it renewed */
	bool dhcp;
	int dhcp_timeout;              /* seconds for the initial lease */
	bool dhcp_hostname;            /* send the container name (option 12) */

	/* hook scripts */
	char create_script[PATH_MAX];
	char setup_script[PATH_MAX];
	char teardown_script[PATH_MAX];
	int script_timeout;            /* seconds */
	bool script_fail;              /* script_on_error = fail */

	/* [network:*] only: every network using the catch-all section gets its
	 * own /subnet_prefix out of subnet_pool */
	bool has_pool;
	uint32_t pool_addr;            /* host order, network address of the pool */
	uint8_t pool_prefix;
	uint8_t subnet_prefix;

	bool is_wildcard;              /* this is the [network:*] template */
	bool from_wildcard;            /* instance created from the template; its
	                                * lists are borrowed and must not be freed */

	bool seen_subnet;              /* parse bookkeeping */
};

struct tr_config {
	/* socket */
	char socket_path[PATH_MAX];
	char socket_owner[64];
	char socket_group[64];
	mode_t socket_mode;

	/* identity checks */
	char client_binary[PATH_MAX];
	char server_binary[PATH_MAX];
	enum tr_verify_mode verify_server;
	char server_selinux_type[128];

	/* runtime */
	char config_path[PATH_MAX];    /* file this configuration was loaded from */
	char state_dir[PATH_MAX];
	char hosts_path[PATH_MAX];
	int log_level;
	int request_timeout;           /* seconds */
	int max_requests_per_user;     /* concurrent connections per non-root uid */
	int gc_interval;               /* seconds between stale state sweeps, 0 = off */
	bool ip_forward;

	/* nftables */
	char nft_binary[PATH_MAX];
	char nft_table[64];
	bool firewall_cleanup;

	/* firewalld (per-network firewalld_zone) */
	char firewall_cmd[PATH_MAX];

	/* NetworkManager: mark bridges trestle creates as unmanaged */
	enum tr_nm_mode networkmanager;
	char nmcli_binary[PATH_MAX];

	/* aardvark-dns */
	char aardvark_binary[PATH_MAX];
	char aardvark_dir[PATH_MAX];
	int aardvark_port;

	struct tr_network *nets;
	size_t nnets;

	/* [network:*]: settings for any network without its own section */
	bool has_wildcard;
	struct tr_network wildcard;
};

void config_defaults(struct tr_config *c);
/* Load the main file and every *.conf in <dir of main>/conf.d (sorted).
 * errbuf receives a human readable message on failure. */
int config_load(struct tr_config *c, const char *path, char *errbuf, size_t errlen);
/* Parse one chunk of INI text (used by config_load and the unit tests). */
int config_parse_text(struct tr_config *c, const char *text, const char *fname,
		      char *errbuf, size_t errlen);
/* Resolve derived fields and validate. */
int config_finalize(struct tr_config *c, char *errbuf, size_t errlen);
void config_free(struct tr_config *c);

/* Explicitly configured network (its own [network:NAME] section) or NULL. */
const struct tr_network *config_find_network(const struct tr_config *c, const char *name);

/* Expand a dnsmasq_hosts path: "%n" becomes the network name. */
void config_expand_path(const char *tmpl, const char *network, char *out, size_t outlen);

/*
 * Make a network from the [network:*] template for `name` (no subnet yet;
 * the daemon assigns one from subnet_pool). Returns false when there is no
 * wildcard section. The result borrows the template's lists.
 */
bool config_wildcard_instance(const struct tr_config *c, const char *name, struct tr_network *out);

/* Longest time one request may spend in hook scripts (used by the client
 * to size its response timeout). */
int config_max_script_time(const struct tr_config *c);

/* Longest time one request may wait for a DHCP lease (0 if no network uses
 * ipam = dhcp). */
int config_max_dhcp_time(const struct tr_config *c);

#endif
