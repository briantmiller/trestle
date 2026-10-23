/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "checks.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/nsfs.h>
#include <pwd.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../common/log.h"
#include "netlink.h"

#ifndef NS_GET_NSTYPE
#define NS_GET_NSTYPE _IO(0xb7, 0x3)
#endif
#ifndef NS_GET_OWNER_UID
#define NS_GET_OWNER_UID _IO(0xb7, 0x4)
#endif

int peer_identify(int sock, struct tr_peer *p, char *err, size_t errlen)
{
	struct ucred cr;
	socklen_t l = sizeof(cr);
	memset(p, 0, sizeof(*p));
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cr, &l) < 0) {
		snprintf(err, errlen, "cannot read peer credentials: %s", strerror(errno));
		return -1;
	}
	p->pid = cr.pid;
	p->uid = cr.uid;
	p->gid = cr.gid;

	struct passwd pw, *res = NULL;
	char buf[4096];
	if (getpwuid_r(cr.uid, &pw, buf, sizeof(buf), &res) != 0 || !res) {
		snprintf(err, errlen, "uid %u has no passwd entry", (unsigned)cr.uid);
		return -1;
	}
	if (tr_strlcpy(p->user, pw.pw_name, sizeof(p->user)) >= sizeof(p->user)) {
		snprintf(err, errlen, "user name of uid %u is too long", (unsigned)cr.uid);
		return -1;
	}
	p->pw_gid = pw.pw_gid;
	return 0;
}

int peer_verify_client_binary(const struct tr_peer *p, const char *client_binary,
			      char *err, size_t errlen)
{
	char want[PATH_MAX], got[PATH_MAX], link[64];

	if (p->pid <= 0) {
		snprintf(err, errlen, "peer pid is not visible to trestled");
		return -1;
	}
	if (!realpath(client_binary, want)) {
		snprintf(err, errlen, "configured client_binary %s: %s", client_binary, strerror(errno));
		return -1;
	}
	snprintf(link, sizeof(link), "/proc/%d/exe", (int)p->pid);
	ssize_t n = readlink(link, got, sizeof(got) - 1);
	if (n < 0) {
		snprintf(err, errlen, "cannot read %s: %s", link, strerror(errno));
		return -1;
	}
	got[n] = '\0';
	if (strcmp(got, want) != 0) {
		snprintf(err, errlen, "connection from pid %d running '%s' rejected: not the trestle client (%s)",
			 (int)p->pid, got, want);
		return -1;
	}
	return 0;
}

static bool user_in_group(const struct tr_peer *p, const char *group)
{
	struct group gr, *res = NULL;
	char buf[16384];
	if (getgrnam_r(group, &gr, buf, sizeof(buf), &res) != 0 || !res)
		return false;
	if (gr.gr_gid == p->pw_gid)
		return true;
	int ng = 256;
	gid_t groups[256];
	if (getgrouplist(p->user, p->pw_gid, groups, &ng) < 0)
		ng = 256;  /* truncated list is still useful */
	for (int i = 0; i < ng; i++)
		if (groups[i] == gr.gr_gid)
			return true;
	return false;
}

bool acl_allowed(const struct strv *acl, const struct tr_peer *p, char *why, size_t whylen)
{
	bool allow = false;
	const char *match = NULL;

	/* deny entries first: they always win */
	for (size_t i = 0; i < acl->n; i++) {
		const char *t = acl->v[i];
		if (t[0] != '!')
			continue;
		t++;
		bool hit = t[0] == '@' ? user_in_group(p, t + 1) : strcmp(t, p->user) == 0;
		if (hit) {
			snprintf(why, whylen, "denied by entry '%s'", acl->v[i]);
			return false;
		}
	}
	for (size_t i = 0; i < acl->n && !allow; i++) {
		const char *t = acl->v[i];
		if (t[0] == '!')
			continue;
		if (!strcmp(t, "*") || (t[0] == '@' && user_in_group(p, t + 1)) || !strcmp(t, p->user)) {
			allow = true;
			match = t;
		}
	}
	if (allow)
		snprintf(why, whylen, "allowed by entry '%s'", match);
	else
		snprintf(why, whylen, "user is not listed");
	return allow;
}

int netns_validate(int nsfd, uid_t peer_uid, char *err, size_t errlen)
{
	int type = ioctl(nsfd, NS_GET_NSTYPE);
	if (type < 0) {
		snprintf(err, errlen, "passed fd is not a namespace: %s", strerror(errno));
		return -1;
	}
	if (type != CLONE_NEWNET) {
		snprintf(err, errlen, "passed namespace is not a network namespace");
		return -1;
	}
	struct stat a, b;
	if (fstat(nsfd, &a) < 0 || stat("/proc/self/ns/net", &b) < 0) {
		snprintf(err, errlen, "stat namespace: %s", strerror(errno));
		return -1;
	}
	if (a.st_dev == b.st_dev && a.st_ino == b.st_ino) {
		snprintf(err, errlen, "refusing to use the host network namespace as a container namespace");
		return -1;
	}
	if (peer_uid == 0)
		return 0;

	int userns = ioctl(nsfd, NS_GET_USERNS);
	if (userns < 0) {
		snprintf(err, errlen, "cannot get owning user namespace: %s", strerror(errno));
		return -1;
	}
	uid_t owner = (uid_t)-1;
	int r = ioctl(userns, NS_GET_OWNER_UID, &owner);
	int e = errno;
	close(userns);
	if (r < 0) {
		snprintf(err, errlen, "cannot get user namespace owner: %s", strerror(e));
		return -1;
	}
	if (owner != peer_uid) {
		snprintf(err, errlen,
			 "network namespace belongs to a user namespace owned by uid %u, not the caller (uid %u)",
			 (unsigned)owner, (unsigned)peer_uid);
		return -1;
	}
	return 0;
}

int netns_nl_open(int nsfd, char *err, size_t errlen)
{
	int self = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (self < 0) {
		snprintf(err, errlen, "open own netns: %s", strerror(errno));
		return -1;
	}
	if (setns(nsfd, CLONE_NEWNET) < 0) {
		snprintf(err, errlen, "cannot enter container network namespace: %s", strerror(errno));
		close(self);
		return -1;
	}
	int fd = nl_open();
	if (setns(self, CLONE_NEWNET) < 0) {
		/* we would keep working in the wrong namespace - unrecoverable */
		log_err("FATAL: cannot return to host network namespace: %s", strerror(errno));
		abort();
	}
	close(self);
	if (fd < 0) {
		snprintf(err, errlen, "netlink socket in container netns: %s", strerror(-fd));
		return -1;
	}
	return fd;
}
