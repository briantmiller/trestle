/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "dnsout.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "../common/log.h"
#include "../common/naming.h"
#include "netset.h"
#include "state.h"

/* ---- /etc/hosts -------------------------------------------------------- */

char *hosts_replace_block(const char *orig, const char *block)
{
	struct buf out = { 0 };
	const char *p = orig ? orig : "";
	bool inblock = false;

	while (*p) {
		const char *nl = strchr(p, '\n');
		size_t l = nl ? (size_t)(nl - p) : strlen(p);
		bool is_begin = l == strlen(TR_HOSTS_BEGIN) && !strncmp(p, TR_HOSTS_BEGIN, l);
		bool is_end = l == strlen(TR_HOSTS_END) && !strncmp(p, TR_HOSTS_END, l);
		if (is_begin)
			inblock = true;
		else if (is_end && inblock)
			inblock = false;
		else if (!inblock) {
			buf_append(&out, p, l);
			buf_append(&out, "\n", 1);
		}
		p += l + (nl ? 1 : 0);
	}
	if (block && *block) {
		if (out.len && out.p[out.len - 1] != '\n')
			buf_append(&out, "\n", 1);
		buf_printf(&out, "%s\n%s%s\n", TR_HOSTS_BEGIN, block, TR_HOSTS_END);
	}
	if (!out.p)
		buf_append(&out, "", 0);
	return out.p;
}

/* Write a file atomically while keeping the original's mode, owner and
 * SELinux label (so /etc/hosts stays net_conf_t). */
static int write_like_original(const char *path, const char *data, size_t len, mode_t defmode)
{
	struct stat st;
	bool have = stat(path, &st) == 0;
	char tmp[PATH_MAX];
	snprintf(tmp, sizeof(tmp), "%s.trestle-tmp.%d", path, (int)getpid());
	int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0)
		return -errno;
	int err = 0;
	size_t off = 0;
	while (off < len) {
		ssize_t w = write(fd, data + off, len - off);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			err = -errno;
			break;
		}
		off += (size_t)w;
	}
	if (!err) {
		if (have) {
			if (fchown(fd, st.st_uid, st.st_gid) < 0)
				log_debug("fchown %s: %s", tmp, strerror(errno));
			fchmod(fd, st.st_mode & 07777);
			char label[512];
			ssize_t ll = getxattr(path, "security.selinux", label, sizeof(label));
			if (ll > 0 && fsetxattr(fd, "security.selinux", label, (size_t)ll, 0) < 0)
				log_debug("cannot copy SELinux label to %s: %s", tmp, strerror(errno));
		} else {
			fchmod(fd, defmode);
		}
		if (fsync(fd) < 0)
			err = -errno;
	}
	close(fd);
	if (!err && rename(tmp, path) < 0)
		err = -errno;
	if (err)
		unlink(tmp);
	return err;
}

struct collect_ctx {
	const struct tr_network *net;
	struct buf *hosts;      /* "<ip> <fqdn> <name>" lines */
	struct buf *aardvark;   /* aardvark entry lines */
	int count;
	int nv_count;
};

static int collect_cb(const struct tr_attachment *a, void *ctx)
{
	struct collect_ctx *c = ctx;
	char ip[16], fqdn[300];
	if (!a->has_ip)
		return 0;
	tr_fmt_ipv4(a->ip, ip);
	tr_fqdn(c->net->name, a->user, a->container_name, fqdn, sizeof(fqdn));
	if (c->hosts)
		buf_printf(c->hosts, "%s\t%s\n", ip, fqdn);
	c->count++;
	if (c->aardvark && !strcmp(a->mode, "netavark")) {
		/* Format: ID ipv4s ipv6s names */
		buf_printf(c->aardvark, "%s %s  %s", a->container_id, ip, a->container_name);
		for (size_t i = 0; i < a->aliases.n; i++)
			if (strcmp(a->aliases.v[i], a->container_name))
				buf_printf(c->aardvark, ",%s", a->aliases.v[i]);
		buf_printf(c->aardvark, ",%s\n", fqdn);
		c->nv_count++;
	}
	return 0;
}

int hosts_refresh_all(const struct tr_config *cfg)
{
	struct buf block = { 0 };
	bool any = false;

	struct netset ns;
	netset_load(cfg, &ns);   /* explicit networks and [network:*] instances */
	for (size_t i = 0; i < ns.n; i++) {
		const struct tr_network *n = ns.all[i];
		if (!n->hosts_file)
			continue;
		any = true;
		struct collect_ctx c = { .net = n, .hosts = &block };
		state_foreach(cfg->state_dir, n->name, collect_cb, &c);
	}
	netset_free(&ns);

	char *orig = tr_read_file(cfg->hosts_path, 16 * 1024 * 1024, NULL);
	if (!orig) {
		if (errno != ENOENT) {
			log_err("cannot read %s: %s", cfg->hosts_path, strerror(errno));
			buf_free(&block);
			return -1;
		}
		if (!any || !block.len) {
			buf_free(&block);
			return 0;
		}
	}
	/* nothing to add and no old block to remove: leave the file untouched */
	if ((!block.len) && (!orig || !strstr(orig, TR_HOSTS_BEGIN))) {
		free(orig);
		buf_free(&block);
		return 0;
	}
	char *updated = hosts_replace_block(orig, block.p);
	int r = 0;
	if (!orig || strcmp(orig, updated) != 0) {
		r = write_like_original(cfg->hosts_path, updated, strlen(updated), 0644);
		if (r)
			log_err("cannot update %s: %s", cfg->hosts_path, strerror(-r));
		else
			log_debug("updated %s", cfg->hosts_path);
	}
	free(orig);
	free(updated);
	buf_free(&block);
	return r ? -1 : 0;
}

/* ---- dnsmasq ---------------------------------------------------------- */

static void signal_pidfile(const char *pidfile, const char *what)
{
	char *t = tr_read_file(pidfile, 64, NULL);
	long pid;
	if (!t)
		return;
	if (tr_parse_int(tr_trim(t), 2, INT_MAX, &pid) && kill((pid_t)pid, SIGHUP) == 0)
		log_debug("sent SIGHUP to %s (pid %ld)", what, pid);
	free(t);
}

static void dnsmasq_refresh(const struct tr_config *cfg, const struct tr_network *net)
{
	struct buf b = { 0 };
	struct collect_ctx c = { .net = net, .hosts = &b };
	buf_printf(&b, "# trestle network %s - generated, do not edit\n", net->name);
	state_foreach(cfg->state_dir, net->name, collect_cb, &c);
	char path[PATH_MAX];
	config_expand_path(net->dnsmasq_hosts, net->name, path, sizeof(path));
	int r = write_like_original(path, b.p, b.len, 0644);
	if (r)
		log_err("cannot write %s: %s", path, strerror(-r));
	else if (net->dnsmasq_pid_file[0])
		signal_pidfile(net->dnsmasq_pid_file, "dnsmasq");
	buf_free(&b);
}

/* ---- aardvark-dns ----------------------------------------------------- */

static pid_t aardvark_pid(const struct tr_config *cfg)
{
	char p[PATH_MAX];
	snprintf(p, sizeof(p), "%s/aardvark.pid", cfg->aardvark_dir);
	char *t = tr_read_file(p, 64, NULL);
	long pid = 0;
	if (t) {
		if (!tr_parse_int(tr_trim(t), 2, INT_MAX, &pid))
			pid = 0;
		free(t);
	}
	if (pid > 0 && kill((pid_t)pid, 0) < 0)
		pid = 0;
	if (pid > 0) {
		/* the pid must still be aardvark-dns (not reused, not a zombie) */
		char sp[64], st[512];
		snprintf(sp, sizeof(sp), "/proc/%ld/stat", pid);
		char *s = tr_read_file(sp, sizeof(st), NULL);
		const char *open_p = s ? strchr(s, '(') : NULL, *close_p = s ? strrchr(s, ')') : NULL;
		if (!open_p || !close_p || close_p < open_p || strncmp(open_p + 1, "aardvark-dns", 12) != 0 ||
		    close_p[1] != ' ' || close_p[2] == 'Z' || close_p[2] == 'X')
			pid = 0;
		free(s);
	}
	return (pid_t)pid;
}

static bool aardvark_has_networks(const struct tr_config *cfg)
{
	DIR *d = opendir(cfg->aardvark_dir);
	if (!d)
		return false;
	struct dirent *de;
	bool any = false;
	while ((de = readdir(d)) && !any)
		if (de->d_name[0] != '.' && strcmp(de->d_name, "aardvark.pid") &&
		    !strstr(de->d_name, ".trestle-tmp."))
			any = true;
	closedir(d);
	return any;
}

static int aardvark_start(const struct tr_config *cfg)
{
	char port[16];
	snprintf(port, sizeof(port), "%d", cfg->aardvark_port);
	bool use_systemd = access("/run/systemd/system", F_OK) == 0 &&
			   access("/usr/bin/systemd-run", X_OK) == 0;

	pid_t pid = fork();
	if (pid < 0)
		return -errno;
	if (pid == 0) {
		/* do not leak our ignored signals into aardvark-dns */
		signal(SIGHUP, SIG_DFL);
		signal(SIGPIPE, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGINT, SIG_DFL);
		int null = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (null >= 0) {
			dup2(null, 0);
			dup2(null, 1);
		}
		/* leave stderr: aardvark's errors end up in our journal */
		if (use_systemd)
			execl("/usr/bin/systemd-run", "systemd-run", "-q", "--scope",
			      "--unit=" AARDVARK_SCOPE_NAME, "--collect",
			      cfg->aardvark_binary, "--config", cfg->aardvark_dir, "-p", port, "run",
			      (char *)NULL);
		else
			execl(cfg->aardvark_binary, "aardvark-dns", "--config", cfg->aardvark_dir,
			      "-p", port, "run", (char *)NULL);
		_exit(127);
	}
	int status;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		log_err("aardvark-dns (%s) failed to start (status %d)", cfg->aardvark_binary,
			WIFEXITED(status) ? WEXITSTATUS(status) : -1);
		return -1;
	}
	log_info("started aardvark-dns for %s", cfg->aardvark_dir);
	return 0;
}

/* Write the network's aardvark-dns config from the attachment records.
 * Returns 0, or -1 if it could not be written. */
static int aardvark_write(const struct tr_config *cfg, const struct tr_network *net)
{
	char path[PATH_MAX], gw[16];
	int r = tr_mkdir_p(cfg->aardvark_dir, 0755);
	if (r) {
		log_err("cannot create %s: %s", cfg->aardvark_dir, strerror(-r));
		return -1;
	}
	snprintf(path, sizeof(path), "%s/%s", cfg->aardvark_dir, net->name);
	struct buf entries = { 0 };
	struct collect_ctx c = { .net = net, .aardvark = &entries };
	state_foreach(cfg->state_dir, net->name, collect_cb, &c);
	if (c.nv_count == 0) {
		unlink(path);
	} else {
		struct buf f = { 0 };
		tr_fmt_ipv4(net->gateway, gw);
		buf_printf(&f, "%s\n%s", gw, entries.p);
		r = tr_write_file_atomic(path, f.p, f.len, 0644);
		buf_free(&f);
		if (r) {
			log_err("cannot write %s: %s", path, strerror(-r));
			buf_free(&entries);
			return -1;
		}
	}
	buf_free(&entries);
	return 0;
}

bool aardvark_down(const struct tr_config *cfg)
{
	return aardvark_has_networks(cfg) && aardvark_pid(cfg) == 0;
}

void aardvark_ensure(const struct tr_config *cfg)
{
	struct netset ns;
	struct strv keep = { 0 };
	netset_load(cfg, &ns);
	for (size_t i = 0; i < ns.n; i++)
		if (ns.all[i]->aardvark_dns) {
			aardvark_write(cfg, ns.all[i]);
			strv_push(&keep, ns.all[i]->name);
		}
	netset_free(&ns);
	/* configs of networks that no longer use aardvark-dns */
	DIR *d = opendir(cfg->aardvark_dir);
	if (d) {
		struct dirent *de;
		while ((de = readdir(d)))
			if (de->d_name[0] != '.' && strcmp(de->d_name, "aardvark.pid") &&
			    !strstr(de->d_name, ".trestle-tmp.") && !strv_contains(&keep, de->d_name)) {
				char p[PATH_MAX];
				snprintf(p, sizeof(p), "%s/%s", cfg->aardvark_dir, de->d_name);
				unlink(p);
			}
		closedir(d);
	}
	strv_clear(&keep);
	pid_t pid = aardvark_pid(cfg);
	if (pid > 0) {
		kill(pid, SIGHUP);
	} else if (aardvark_has_networks(cfg)) {
		log_info("aardvark-dns is not running; starting it");
		aardvark_start(cfg);
	}
}

static void aardvark_refresh(const struct tr_config *cfg, const struct tr_network *net)
{
	if (aardvark_write(cfg, net) < 0)
		return;

	pid_t pid = aardvark_pid(cfg);
	if (pid > 0) {
		/* aardvark re-reads its config on SIGHUP and exits when no
		 * networks are left */
		kill(pid, SIGHUP);
	} else if (aardvark_has_networks(cfg)) {
		aardvark_start(cfg);
	}
}

void aardvark_stop(const struct tr_config *cfg)
{
	pid_t pid = aardvark_pid(cfg);
	if (pid > 0)
		kill(pid, SIGTERM);
}

void dns_refresh(const struct tr_config *cfg, const struct tr_network *net)
{
	if (net->hosts_file)
		hosts_refresh_all(cfg);
	if (net->dnsmasq_hosts[0])
		dnsmasq_refresh(cfg, net);
	if (net->aardvark_dns)
		aardvark_refresh(cfg, net);
}

/* ---- status (trestlectl status) --------------------------------------- */

/* systemd unit of a process from /proc/<pid>/cgroup (v2 "0::/...", or the
 * v1 name=systemd hierarchy): the last path component, e.g.
 * "trestle-aardvark-dns.scope". */
void dns_cgroup_unit(const char *cgroup, char *out, size_t outlen)
{
	out[0] = '\0';
	char *t = strdup(cgroup ? cgroup : "");
	if (!t)
		return;
	char *save = NULL, *path = NULL;
	for (char *line = strtok_r(t, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		if (!strncmp(line, "0::", 3))
			path = line + 3;
		else if (strstr(line, ":name=systemd:") && !path)
			path = strstr(line, ":name=systemd:") + 14;
	}
	if (path) {
		const char *last = strrchr(path, '/');
		tr_strlcpy(out, last ? last + 1 : path, outlen);
	}
	free(t);
}

static void process_unit(pid_t pid, char *out, size_t outlen)
{
	char p[64];
	out[0] = '\0';
	snprintf(p, sizeof(p), "/proc/%d/cgroup", (int)pid);
	char *t = tr_read_file(p, 65536, NULL);
	if (t)
		dns_cgroup_unit(t, out, outlen);
	free(t);
}

void aardvark_status(const struct tr_config *cfg, struct aardvark_state *st)
{
	memset(st, 0, sizeof(*st));
	st->needed = aardvark_has_networks(cfg);
	st->pid = aardvark_pid(cfg);
	st->systemd = access("/run/systemd/system", F_OK) == 0 && access("/usr/bin/systemd-run", X_OK) == 0;
	tr_strlcpy(st->expected_unit, AARDVARK_SCOPE, sizeof(st->expected_unit));
	if (st->pid > 0)
		process_unit(st->pid, st->unit, sizeof(st->unit));
	st->in_scope = st->pid > 0 && !strcmp(st->unit, AARDVARK_SCOPE);
}

int dnsmasq_status(const struct tr_network *net, char *file, size_t filelen)
{
	if (!net->dnsmasq_hosts[0])
		return -2;
	config_expand_path(net->dnsmasq_hosts, net->name, file, filelen);
	if (!net->dnsmasq_pid_file[0])
		return -1;
	char *t = tr_read_file(net->dnsmasq_pid_file, 64, NULL);
	long pid = 0;
	if (t) {
		if (!tr_parse_int(tr_trim(t), 2, INT_MAX, &pid))
			pid = 0;
		free(t);
	}
	if (pid <= 0 || kill((pid_t)pid, 0) < 0)
		return 0;
	char p[64];
	snprintf(p, sizeof(p), "/proc/%ld/comm", pid);
	char *comm = tr_read_file(p, 64, NULL);
	bool ok = comm && !strcmp(tr_trim(comm), "dnsmasq");
	free(comm);
	return ok ? (int)pid : 0;
}
