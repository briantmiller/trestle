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

	for (size_t i = 0; i < cfg->nnets; i++) {
		const struct tr_network *n = &cfg->nets[i];
		if (!n->hosts_file)
			continue;
		any = true;
		struct collect_ctx c = { .net = n, .hosts = &block };
		state_foreach(cfg->state_dir, n->name, collect_cb, &c);
	}

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
	int r = write_like_original(net->dnsmasq_hosts, b.p, b.len, 0644);
	if (r)
		log_err("cannot write %s: %s", net->dnsmasq_hosts, strerror(-r));
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
			      "--unit=trestle-aardvark-dns", "--collect",
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

static void aardvark_refresh(const struct tr_config *cfg, const struct tr_network *net)
{
	char path[PATH_MAX], gw[16];
	int r = tr_mkdir_p(cfg->aardvark_dir, 0755);
	if (r) {
		log_err("cannot create %s: %s", cfg->aardvark_dir, strerror(-r));
		return;
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
			return;
		}
	}
	buf_free(&entries);

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
