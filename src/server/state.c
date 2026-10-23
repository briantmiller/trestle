/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "state.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../common/log.h"

static int dir_for(char *out, size_t len, const char *state_dir, const char *kind, const char *network)
{
	int n = network ? snprintf(out, len, "%s/%s/%s", state_dir, kind, network)
			: snprintf(out, len, "%s/%s", state_dir, kind);
	return (n < 0 || (size_t)n >= len) ? -ENAMETOOLONG : 0;
}

void attachment_free(struct tr_attachment *a)
{
	strv_clear(&a->aliases);
}

int state_save(const char *state_dir, const struct tr_attachment *a)
{
	char dir[PATH_MAX], path[PATH_MAX], ip[16] = "";
	int r = dir_for(dir, sizeof(dir), state_dir, "attachments", a->network);
	if (r)
		return r;
	if ((r = tr_mkdir_p(dir, 0700)))
		return r;
	snprintf(path, sizeof(path), "%s/%s", dir, a->container_id);

	struct buf b = { 0 };
	if (a->has_ip)
		tr_fmt_ipv4(a->ip, ip);
	buf_printf(&b, "network=%s\ncontainer_id=%s\ncontainer_name=%s\nuser=%s\nuid=%u\nmode=%s\n"
		       "ifname=%s\nveth=%s\nmac=%s\n",
		   a->network, a->container_id, a->container_name, a->user, (unsigned)a->uid, a->mode,
		   a->ifname, a->veth, a->mac);
	if (a->has_ip)
		buf_printf(&b, "ip=%s/%u\n", ip, a->prefix);
	buf_printf(&b, "aliases=");
	for (size_t i = 0; i < a->aliases.n; i++)
		buf_printf(&b, "%s%s", i ? "," : "", a->aliases.v[i]);
	buf_printf(&b, "\n");
	r = tr_write_file_atomic(path, b.p, b.len, 0600);
	buf_free(&b);
	return r;
}

int state_load(const char *state_dir, const char *network, const char *cid, struct tr_attachment *a)
{
	char dir[PATH_MAX], path[PATH_MAX];
	int r = dir_for(dir, sizeof(dir), state_dir, "attachments", network);
	if (r)
		return r;
	snprintf(path, sizeof(path), "%s/%s", dir, cid);
	char *text = tr_read_file(path, 65536, NULL);
	if (!text)
		return -errno;

	memset(a, 0, sizeof(*a));
	char *save = NULL;
	for (char *line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
		char *eq = strchr(line, '=');
		if (!eq)
			continue;
		*eq = '\0';
		const char *k = line, *v = eq + 1;
		if (!strcmp(k, "network"))
			tr_strlcpy(a->network, v, sizeof(a->network));
		else if (!strcmp(k, "container_id"))
			tr_strlcpy(a->container_id, v, sizeof(a->container_id));
		else if (!strcmp(k, "container_name"))
			tr_strlcpy(a->container_name, v, sizeof(a->container_name));
		else if (!strcmp(k, "user"))
			tr_strlcpy(a->user, v, sizeof(a->user));
		else if (!strcmp(k, "uid"))
			a->uid = (uid_t)strtoul(v, NULL, 10);
		else if (!strcmp(k, "mode"))
			tr_strlcpy(a->mode, v, sizeof(a->mode));
		else if (!strcmp(k, "ifname"))
			tr_strlcpy(a->ifname, v, sizeof(a->ifname));
		else if (!strcmp(k, "veth"))
			tr_strlcpy(a->veth, v, sizeof(a->veth));
		else if (!strcmp(k, "mac"))
			tr_strlcpy(a->mac, v, sizeof(a->mac));
		else if (!strcmp(k, "ip")) {
			struct tr_ipv4net n;
			if (tr_parse_ipv4_cidr(v, &n)) {
				a->has_ip = true;
				a->ip = n.addr;
				a->prefix = n.prefix;
			}
		} else if (!strcmp(k, "aliases") && *v)
			strv_split_push(&a->aliases, v);
	}
	free(text);
	if (strcmp(a->container_id, cid) != 0 || !a->veth[0]) {
		attachment_free(a);
		return -EBADMSG;
	}
	return 0;
}

int state_delete(const char *state_dir, const char *network, const char *cid)
{
	char path[PATH_MAX];
	if (snprintf(path, sizeof(path), "%s/attachments/%s/%s", state_dir, network, cid) >= (int)sizeof(path))
		return -ENAMETOOLONG;
	if (unlink(path) < 0 && errno != ENOENT)
		return -errno;
	return 0;
}

int state_foreach(const char *state_dir, const char *network, state_cb cb, void *ctx)
{
	char dir[PATH_MAX];
	int r = dir_for(dir, sizeof(dir), state_dir, "attachments", network);
	if (r)
		return r;
	DIR *d = opendir(dir);
	if (!d)
		return errno == ENOENT ? 0 : -errno;
	struct strv names = { 0 };
	struct dirent *de;
	while ((de = readdir(d)))
		if (de->d_name[0] != '.' && !strstr(de->d_name, ".trestle-tmp."))
			strv_push(&names, de->d_name);
	closedir(d);
	r = 0;
	for (size_t i = 0; i < names.n && !r; i++) {
		struct tr_attachment a;
		if (state_load(state_dir, network, names.v[i], &a) == 0) {
			r = cb(&a, ctx);
			attachment_free(&a);
		}
	}
	strv_clear(&names);
	return r;
}

int state_mark_bridge(const char *state_dir, const char *bridge, const char *network)
{
	char dir[PATH_MAX], path[PATH_MAX], body[256];
	int r = dir_for(dir, sizeof(dir), state_dir, "bridges", NULL);
	if (r || (r = tr_mkdir_p(dir, 0700)))
		return r;
	snprintf(path, sizeof(path), "%s/%s", dir, bridge);
	int n = snprintf(body, sizeof(body), "network=%s\n", network);
	return tr_write_file_atomic(path, body, (size_t)n, 0600);
}

bool state_bridge_marked(const char *state_dir, const char *bridge)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/bridges/%s", state_dir, bridge);
	return access(path, F_OK) == 0;
}

int state_unmark_bridge(const char *state_dir, const char *bridge)
{
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/bridges/%s", state_dir, bridge);
	if (unlink(path) < 0 && errno != ENOENT)
		return -errno;
	return 0;
}

/* ---- IPAM ------------------------------------------------------------ */

static int lease_owner(const char *dir, uint32_t ip, char *owner, size_t olen)
{
	char path[PATH_MAX], s[16];
	tr_fmt_ipv4(ip, s);
	snprintf(path, sizeof(path), "%s/%s", dir, s);
	char *t = tr_read_file(path, 512, NULL);
	if (!t)
		return -errno;
	tr_strlcpy(owner, tr_trim(t), olen);
	free(t);
	return 0;
}

/* Try to take a lease. 0 = taken, -EEXIST = held by someone else. */
static int lease_take(const char *dir, uint32_t ip, const char *cid)
{
	char path[PATH_MAX], s[16];
	tr_fmt_ipv4(ip, s);
	snprintf(path, sizeof(path), "%s/%s", dir, s);
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0) {
		if (errno == EEXIST) {
			char owner[256];
			if (lease_owner(dir, ip, owner, sizeof(owner)) == 0 && !strcmp(owner, cid))
				return 0;
			return -EEXIST;
		}
		return -errno;
	}
	size_t l = strlen(cid);
	ssize_t w = write(fd, cid, l);
	int e = (w == (ssize_t)l) ? 0 : -EIO;
	if (!e && fsync(fd) < 0)
		e = -errno;
	close(fd);
	if (e)
		unlink(path);
	return e;
}


static int scan_leases(const char *dir, const char *cid, uint32_t *out, bool unlink_matches)
{
	DIR *d = opendir(dir);
	if (!d)
		return errno == ENOENT ? -ENOENT : -errno;
	struct dirent *de;
	int found = -ENOENT;
	while ((de = readdir(d))) {
		uint32_t ip;
		if (de->d_name[0] == '.' || !tr_parse_ipv4(de->d_name, &ip))
			continue;
		char owner[256];
		if (lease_owner(dir, ip, owner, sizeof(owner)) == 0 && !strcmp(owner, cid)) {
			if (out && found != 0)
				*out = ip;
			found = 0;
			if (unlink_matches) {
				char p[PATH_MAX];
				snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
				unlink(p);
			}
		}
	}
	closedir(d);
	return found;
}

int ipam_lookup(const char *state_dir, const char *network, const char *cid, uint32_t *out)
{
	char dir[PATH_MAX];
	int r = dir_for(dir, sizeof(dir), state_dir, "ipam", network);
	if (r)
		return r;
	return scan_leases(dir, cid, out, false);
}

int ipam_release(const char *state_dir, const char *network, const char *cid)
{
	char dir[PATH_MAX];
	int r = dir_for(dir, sizeof(dir), state_dir, "ipam", network);
	if (r)
		return r;
	r = scan_leases(dir, cid, NULL, true);
	return r == -ENOENT ? 0 : r;
}

int ipam_allocate(const char *state_dir, const struct tr_network *net, const char *cid,
		  const struct strv *requested, uint32_t *out, char *err, size_t errlen)
{
	char dir[PATH_MAX], s[16];
	int r = dir_for(dir, sizeof(dir), state_dir, "ipam", net->name);
	if (r || (r = tr_mkdir_p(dir, 0700))) {
		snprintf(err, errlen, "cannot create IPAM directory: %s", strerror(-r));
		return -1;
	}
	uint32_t first = net->netaddr + 1, last = net->broadcast - 1;

	if (requested && requested->n) {
		uint32_t mask = tr_prefix_mask(net->prefix);
		for (size_t i = 0; i < requested->n; i++) {
			uint32_t ip;
			if (!tr_parse_ipv4(requested->v[i], &ip))
				continue;
			if ((ip & mask) != net->netaddr) {
				snprintf(err, errlen, "requested IP %s is not inside the trestle subnet of network '%s'",
					 requested->v[i], net->name);
				return -1;
			}
			if (ip == net->gateway || ip < first || ip > last) {
				snprintf(err, errlen, "requested IP %s is reserved (network, broadcast or bridge address)",
					 requested->v[i]);
				return -1;
			}
			r = lease_take(dir, ip, cid);
			if (r == -EEXIST) {
				snprintf(err, errlen, "requested IP %s is already in use on network '%s'",
					 requested->v[i], net->name);
				return -1;
			}
			if (r) {
				snprintf(err, errlen, "cannot record lease: %s", strerror(-r));
				return -1;
			}
			*out = ip;
			return 0;
		}
		snprintf(err, errlen, "no usable IPv4 address in the requested static IPs");
		return -1;
	}

	/* already holds a lease (e.g. a retried ADD)? */
	if (scan_leases(dir, cid, out, false) == 0)
		return 0;

	char lastp[PATH_MAX];
	snprintf(lastp, sizeof(lastp), "%s/.last", dir);
	uint32_t start = first;
	char *t = tr_read_file(lastp, 64, NULL);
	if (t) {
		uint32_t l;
		if (tr_parse_ipv4(tr_trim(t), &l) && l >= first && l < last)
			start = l + 1;
		free(t);
	}
	uint32_t count = last - first + 1;
	for (uint32_t i = 0; i < count; i++) {
		uint32_t ip = first + ((start - first + i) % count);
		if (ip == net->gateway)
			continue;
		r = lease_take(dir, ip, cid);
		if (r == -EEXIST)
			continue;
		if (r) {
			snprintf(err, errlen, "cannot record lease: %s", strerror(-r));
			return -1;
		}
		tr_fmt_ipv4(ip, s);
		tr_write_file_atomic(lastp, s, strlen(s), 0600);
		*out = ip;
		return 0;
	}
	snprintf(err, errlen, "no free addresses left in the subnet of network '%s'", net->name);
	return -1;
}
