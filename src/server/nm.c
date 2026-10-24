/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "nm.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../common/log.h"
#include "../common/util.h"
#include "exec.h"

#define NM_CMD_TIMEOUT_MS 5000
#define NM_RETRY_TOTAL_MS 3000
#define NM_RETRY_STEP_MS  150

static bool file_has_line(const char *path, const char *key, const char *value)
{
	char *t = tr_read_file(path, 1024 * 1024, NULL);
	if (!t)
		return false;
	bool hit = false;
	char *save = NULL;
	for (char *line = strtok_r(t, "\n", &save); line && !hit; line = strtok_r(NULL, "\n", &save)) {
		char *eq = strchr(line, '=');
		if (!eq)
			continue;
		*eq = '\0';
		if (strcmp(tr_trim(line), key) != 0)
			continue;
		char *v = tr_trim(eq + 1);
		size_t vl = strlen(v);
		if (vl >= 2 && (v[0] == '"' || v[0] == '\'') && v[vl - 1] == v[0]) {
			v[vl - 1] = '\0';
			v++;
		}
		hit = strcmp(v, value) == 0;
	}
	free(t);
	return hit;
}

static bool dir_claims(const char *dir, const char *prefix_filter, const char *key, const char *ifname)
{
	DIR *d = opendir(dir);
	if (!d)
		return false;
	struct dirent *de;
	bool hit = false;
	while (!hit && (de = readdir(d))) {
		if (de->d_name[0] == '.')
			continue;
		if (prefix_filter && strncmp(de->d_name, prefix_filter, strlen(prefix_filter)) != 0)
			continue;
		char p[PATH_MAX];
		snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
		hit = file_has_line(p, key, ifname);
	}
	closedir(d);
	return hit;
}

bool nm_profile_claims(const char *prefix, const char *ifname)
{
	char p[PATH_MAX];
	static const char *keyfile_dirs[] = {
		"/etc/NetworkManager/system-connections",
		"/run/NetworkManager/system-connections",
		"/usr/lib/NetworkManager/system-connections",
	};
	for (size_t i = 0; i < ARRAY_SIZE(keyfile_dirs); i++) {
		snprintf(p, sizeof(p), "%s%s", prefix, keyfile_dirs[i]);
		if (dir_claims(p, NULL, "interface-name", ifname))
			return true;
	}
	/* legacy ifcfg profiles (RHEL 8/9) */
	snprintf(p, sizeof(p), "%s/etc/sysconfig/network-scripts", prefix);
	if (dir_claims(p, "ifcfg-", "DEVICE", ifname))
		return true;
	return false;
}

static bool nm_running(const struct tr_config *cfg)
{
	struct buf out = { 0 };
	char *argv[] = { (char *)cfg->nmcli_binary, "-t", "-f", "RUNNING", "general", NULL };
	int r = tr_run_cmd(argv, NM_CMD_TIMEOUT_MS, &out);
	bool running = r == 0 && out.p && strncmp(tr_trim(out.p), "running", 7) == 0;
	buf_free(&out);
	return running;
}

bool nm_should_unmanage(const struct tr_config *cfg, const char *ifname)
{
	if (cfg->networkmanager == TR_NM_NO)
		return false;
	if (access(cfg->nmcli_binary, X_OK) != 0) {
		if (cfg->networkmanager == TR_NM_YES)
			log_warn("networkmanager = yes but %s is not executable", cfg->nmcli_binary);
		return false;
	}
	if (nm_profile_claims("", ifname)) {
		log_info("a NetworkManager connection profile names %s; leaving it managed by NetworkManager",
			 ifname);
		return false;
	}
	if (!nm_running(cfg)) {
		if (cfg->networkmanager == TR_NM_YES)
			log_warn("networkmanager = yes but NetworkManager is not running");
		else
			log_debug("NetworkManager is not running; not marking %s unmanaged", ifname);
		return false;
	}
	return true;
}

int nm_set_unmanaged(const struct tr_config *cfg, const char *ifname)
{
	char *argv[] = { (char *)cfg->nmcli_binary, "device", "set", (char *)ifname, "managed", "no", NULL };
	long deadline = tr_now_ms() + NM_RETRY_TOTAL_MS;
	struct buf out = { 0 };
	int r;
	/* NetworkManager learns about new links asynchronously; until then
	 * nmcli answers "Device ... not found" */
	for (;;) {
		buf_free(&out);
		r = tr_run_cmd(argv, NM_CMD_TIMEOUT_MS, &out);
		if (r == 0 || tr_now_ms() >= deadline)
			break;
		tr_sleep_ms(NM_RETRY_STEP_MS);
	}
	if (r == 0) {
		log_info("told NetworkManager not to manage %s", ifname);
	} else {
		char *msg = out.p ? tr_trim(out.p) : "";
		log_warn("'nmcli device set %s managed no' failed (status %d)%s%s", ifname, r,
			 *msg ? ": " : "", msg);
	}
	buf_free(&out);
	return r == 0 ? 0 : -1;
}
