/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Stale state cleanup.
 *
 * Sweep (daemon start, every gc_interval, "trestlectl gc"): an attachment
 * whose host veth no longer exists (host crash, runtime that never called
 * DEL/teardown) is removed together with its lease and DHCP keeper; leases
 * without an attachment are released; DHCP attachments whose keeper died
 * get a new one. Affected DNS outputs, the nftables sets and unused bridges
 * are updated.
 *
 * CNI GC (CNI 1.1.0): the runtime lists the attachments that are still
 * valid; trestle removes the caller's other CNI attachments on that network.
 *
 * The caller holds the state lock.
 */
#ifndef TRESTLE_GC_H
#define TRESTLE_GC_H

#include <stdbool.h>
#include <sys/types.h>

#include "../common/config.h"
#include "../common/util.h"

struct gc_filter {
	const char *network;              /* NULL = every network */
	bool cni;                         /* CNI GC instead of a sweep */
	uid_t uid;                        /* CNI GC: only this caller's attachments */
	const struct strv *valid;         /* CNI GC: "<container id>/<ifname>" */
};

struct gc_report {
	struct strv removed;              /* "network container-id (name, user)" */
	struct strv leases;               /* "network ip owner" */
	struct strv keepers;              /* "network container-id" restarted */
	int errors;
};

int gc_run(const struct tr_config *cfg, int nlfd, const struct gc_filter *f, bool dry_run, struct gc_report *rep);
void gc_report_free(struct gc_report *r);

/* Find a network namespace by the st_dev/st_ino recorded at attach time
 * (via /proc/<pid>/ns/net of a process inside it). Returns an fd or -1. */
int gc_find_netns(unsigned long long dev, unsigned long long ino);

#endif
