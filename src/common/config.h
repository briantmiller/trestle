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
#define TRESTLE_DEFAULT_SOCKET  "/tmp/trestle.sock"
#define TRESTLE_DEFAULT_CLIENT  TRESTLE_LIBEXECDIR "/trestle/trestle"
#define TRESTLE_DEFAULT_SERVER  TRESTLE_SBINDIR "/trestled"
#define TRESTLE_DEFAULT_STATE   TRESTLE_LOCALSTATEDIR "/trestle"

enum tr_ipam_mode { TR_PODMAN_IPAM_NONE, TR_PODMAN_IPAM_HOST_LOCAL };
enum tr_verify_mode { TR_VERIFY_STRICT, TR_VERIFY_RELAXED, TR_VERIFY_NONE };

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
	char state_dir[PATH_MAX];
	char hosts_path[PATH_MAX];
	int log_level;
	int request_timeout;           /* seconds */
	bool ip_forward;

	/* nftables */
	char nft_binary[PATH_MAX];
	char nft_table[64];
	bool firewall_cleanup;

	/* aardvark-dns */
	char aardvark_binary[PATH_MAX];
	char aardvark_dir[PATH_MAX];
	int aardvark_port;

	struct tr_network *nets;
	size_t nnets;
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

const struct tr_network *config_find_network(const struct tr_config *c, const char *name);

#endif
