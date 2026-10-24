/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Persistent state under <state_dir>:
 *
 *   ipam/<network>/<ipv4>                 owner container id (one file per lease)
 *   ipam/<network>/.last                  last allocated address (round robin)
 *   attachments/<network>/<container_id>  attachment record (key=value)
 *   bridges/<bridge>                      present if trestle created the bridge
 *   dhcp/<veth>.pid                       DHCP lease keeper of an attachment
 */
#ifndef TRESTLE_STATE_H
#define TRESTLE_STATE_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "../common/config.h"
#include "../common/util.h"

struct tr_attachment {
	char network[TR_MAX_NAME + 1];
	char container_id[129];
	char container_name[TR_MAX_NAME + 1];
	char user[TR_MAX_NAME + 1];
	uid_t uid;
	char mode[16];                 /* "cni" or "netavark" */
	char ifname[TR_IFNAMSIZ];
	char veth[TR_IFNAMSIZ];
	char mac[18];
	bool has_ip;
	uint32_t ip;
	uint8_t prefix;
	struct strv aliases;

	/* ipam = dhcp */
	bool dhcp;
	uint32_t gateway;              /* 0 = none (static IPAM uses the network's) */
	uint32_t dns[3];               /* DNS servers from the lease, 0 terminated */
	uint32_t dhcp_server;
	long long lease_expiry;        /* unix time, 0 = unknown */

	/* identity of the container network namespace (st_dev/st_ino of the
	 * nsfs file), used to find it again after a daemon restart */
	unsigned long long ns_dev, ns_ino;
};

void attachment_free(struct tr_attachment *a);
int state_save(const char *state_dir, const struct tr_attachment *a);
int state_load(const char *state_dir, const char *network, const char *cid, struct tr_attachment *a);
int state_delete(const char *state_dir, const char *network, const char *cid);
typedef int (*state_cb)(const struct tr_attachment *a, void *ctx);
int state_foreach(const char *state_dir, const char *network, state_cb cb, void *ctx);

/* Take the exclusive state lock (<state_dir>/state.lock). Returns the fd
 * holding the lock (close it to release) or -1. With wait = false it fails
 * at once if someone else holds the lock. Interrupted by signals (EINTR). */
int state_lock(const char *state_dir, bool wait);

/* Every <network> directory below attachments/ and ipam/ (networks that may
 * have state, including ones no longer configured). */
int state_networks(const char *state_dir, struct strv *out);

/* Bridge ownership markers */
int state_mark_bridge(const char *state_dir, const char *bridge, const char *network);
bool state_bridge_marked(const char *state_dir, const char *bridge);
int state_unmark_bridge(const char *state_dir, const char *bridge);

/* IPAM. Returns 0 and the address, or -1 with err set. */
int ipam_allocate(const char *state_dir, const struct tr_network *net, const char *cid,
		  const struct strv *requested, uint32_t *out, char *err, size_t errlen);
int ipam_release(const char *state_dir, const char *network, const char *cid);
int ipam_lookup(const char *state_dir, const char *network, const char *cid, uint32_t *out);
/* Call cb for every lease of a network (owner = container id). */
typedef int (*lease_cb)(uint32_t ip, const char *owner, void *ctx);
int ipam_foreach(const char *state_dir, const char *network, lease_cb cb, void *ctx);
/* Drop one lease file. */
int ipam_release_ip(const char *state_dir, const char *network, uint32_t ip);

#endif
