/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Per-network hook scripts (create_script, setup_script, teardown_script).
 *
 * Scripts run as root in trestled's context with a clean environment made
 * only of TRESTLE_* variables (plus PATH and LANG), stdin from /dev/null and
 * stdout/stderr forwarded to the trestled log. The event name is also passed
 * as the first argument.
 */
#ifndef TRESTLE_HOOKS_H
#define TRESTLE_HOOKS_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "../common/config.h"
#include "../common/util.h"

struct hook_info {
	const char *event;              /* "create", "setup", "teardown" */
	const char *mode;               /* "cni" or "netavark" */
	const char *command;            /* ADD, DEL, create, setup, teardown */
	const struct tr_network *net;
	bool bridge_created;            /* trestle created the bridge in this request */

	const char *user;
	uid_t uid;
	gid_t gid;
	bool rootless;

	const char *container_id;
	const char *container_name;
	const struct strv *aliases;
	const char *k8s_pod_name;
	const char *k8s_pod_namespace;
	const char *podman_network_id;

	const char *host_ifname;
	const char *container_ifname;
	const char *host_mac;
	const char *container_mac;
	bool has_ip;
	uint32_t ip;
	uint8_t prefix;

	const char *netns_path;         /* as given by the runtime */
	int netns_fd;                   /* passed to the script as fd 3, -1 if none */
};

/* Build the environment ("KEY=value" strings). Pure; used by the tests. */
void hook_build_env(const struct hook_info *hi, struct strv *env);

/*
 * Check that a script may be executed: absolute path, regular file,
 * executable, owned by root (or the daemon's uid), not writable by group
 * or others, and its directory not writable by group or others.
 */
int hook_check_script(const char *path, char *err, size_t errlen);

/*
 * Run a script and wait for it (at most timeout seconds, then the whole
 * process group is killed). Returns 0 when it exited with status 0,
 * otherwise -1 with err set.
 */
int hook_run(const char *path, const struct hook_info *hi, int timeout,
	     char *err, size_t errlen);

#endif
