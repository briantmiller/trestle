/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Authorization and identity checks performed by trestled. */
#ifndef TRESTLE_CHECKS_H
#define TRESTLE_CHECKS_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "../common/util.h"

struct tr_peer {
	pid_t pid;
	uid_t uid;
	gid_t gid;
	char user[TR_MAX_NAME + 1];
	gid_t pw_gid;          /* primary group from passwd */
};

/* SO_PEERCRED + passwd lookup. */
int peer_identify(int sock, struct tr_peer *p, char *err, size_t errlen);

/* /proc/<pid>/exe must resolve to client_binary (after realpath()). */
int peer_verify_client_binary(const struct tr_peer *p, const char *client_binary,
			      char *err, size_t errlen);

/*
 * ACL evaluation for a network's "users" list.
 *   name      allow user
 *   @group    allow members of group
 *   *         allow everybody
 *   !name     deny user      (deny entries always win)
 *   !@group   deny group members
 */
bool acl_allowed(const struct strv *acl, const struct tr_peer *p, char *why, size_t whylen);

/*
 * Validate a network namespace fd received from a client:
 *   - it must be a network namespace,
 *   - it must not be the daemon's own (host) network namespace,
 *   - for non-root peers the namespace must be owned by a user namespace
 *     created by that same user (i.e. it belongs to one of their rootless
 *     containers).
 */
int netns_validate(int nsfd, uid_t peer_uid, char *err, size_t errlen);

/* Open a NETLINK_ROUTE socket inside the given network namespace. */
/* A socket created inside the network namespace nsfd (it stays there). */
int netns_socket(int nsfd, int domain, int type, int proto, char *err, size_t errlen);
int netns_nl_open(int nsfd, char *err, size_t errlen);

#endif
