/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Name publication: /etc/hosts block, dnsmasq hosts files, aardvark-dns. */
#ifndef TRESTLE_DNSOUT_H
#define TRESTLE_DNSOUT_H

#include "../common/config.h"

#define TR_HOSTS_BEGIN "# BEGIN trestle managed entries - do not edit"
#define TR_HOSTS_END   "# END trestle managed entries"

/* Regenerate every name output for one network from the attachment
 * records (and the shared /etc/hosts block for all networks). */
void dns_refresh(const struct tr_config *cfg, const struct tr_network *net);

/* Rebuild the managed /etc/hosts block for all networks (startup/reload). */
int hosts_refresh_all(const struct tr_config *cfg);

/* Pure function used by hosts_refresh_all and the unit tests: replace the
 * managed block in `orig` with `block` (may be empty). Caller frees. */
char *hosts_replace_block(const char *orig, const char *block);

/* Stop aardvark-dns when no network uses it anymore (shutdown). */
void aardvark_stop(const struct tr_config *cfg);
/* Rewrite every aardvark-dns config from the records and make sure
 * aardvark-dns runs when any network needs it (start, reload, sweeps). */
void aardvark_ensure(const struct tr_config *cfg);
/* Networks need aardvark-dns but it is not running. */
bool aardvark_down(const struct tr_config *cfg);

#define AARDVARK_SCOPE_NAME "trestle-aardvark-dns"
#define AARDVARK_SCOPE AARDVARK_SCOPE_NAME ".scope"

struct aardvark_state {
	bool needed;            /* some network has entries for aardvark-dns */
	pid_t pid;              /* 0 = not running */
	bool systemd;           /* trestled starts it through systemd-run --scope */
	char unit[256];         /* systemd unit the process is in ("" = unknown) */
	char expected_unit[64];
	bool in_scope;          /* unit == trestle-aardvark-dns.scope */
};
void aardvark_status(const struct tr_config *cfg, struct aardvark_state *st);
/* systemd unit (last cgroup path component) from /proc/<pid>/cgroup text */
void dns_cgroup_unit(const char *cgroup, char *out, size_t outlen);

/* dnsmasq output of a network: -2 = none, else the hosts file in file and
 * the pid of the dnsmasq from dnsmasq_pid_file (0 = not running, -1 = no
 * pid file configured). */
int dnsmasq_status(const struct tr_network *net, char *file, size_t filelen);

#endif
