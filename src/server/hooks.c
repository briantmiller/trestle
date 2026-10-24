/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "hooks.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../common/log.h"
#include "../common/naming.h"

#ifndef TRESTLE_VERSION
#define TRESTLE_VERSION "0.2"
#endif

#define HOOK_NETNS_FD 3
#define HOOK_MAX_OUTPUT (64 * 1024)

static void setenv_kv(struct strv *env, const char *k, const char *v)
{
	struct buf b = { 0 };
	buf_printf(&b, "%s=%s", k, v ? v : "");
	strv_push(env, b.p);
	buf_free(&b);
}

static void setenv_opt(struct strv *env, const char *k, const char *v)
{
	if (v && *v)
		setenv_kv(env, k, v);
}

static void setenv_num(struct strv *env, const char *k, long v)
{
	char n[32];
	snprintf(n, sizeof(n), "%ld", v);
	setenv_kv(env, k, n);
}

void hook_build_env(const struct hook_info *hi, struct strv *env)
{
	const struct tr_network *n = hi->net;
	char a[16], b[32];

	setenv_kv(env, "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
	setenv_kv(env, "LANG", "C");
	setenv_kv(env, "TRESTLE_VERSION", TRESTLE_VERSION);
	setenv_kv(env, "TRESTLE_EVENT", hi->event);
	setenv_opt(env, "TRESTLE_MODE", hi->mode);
	setenv_opt(env, "TRESTLE_COMMAND", hi->command);

	/* network */
	setenv_kv(env, "TRESTLE_NETWORK", n->name);
	setenv_kv(env, "TRESTLE_BRIDGE", n->bridge);
	setenv_kv(env, "TRESTLE_BRIDGE_CREATED", hi->bridge_created ? "1" : "0");
	if (n->mtu > 0)
		setenv_num(env, "TRESTLE_MTU", n->mtu);
	if (n->uplink[0])
		setenv_kv(env, "TRESTLE_UPLINK", n->uplink);
	if (n->has_subnet) {
		tr_fmt_ipv4(n->netaddr, a);
		snprintf(b, sizeof(b), "%s/%u", a, n->prefix);
		setenv_kv(env, "TRESTLE_SUBNET", b);
		tr_fmt_ipv4(n->gateway, a);
		setenv_kv(env, "TRESTLE_GATEWAY", a);
		snprintf(b, sizeof(b), "%s/%u", a, n->prefix);
		setenv_kv(env, "TRESTLE_BRIDGE_IP", a);
		setenv_kv(env, "TRESTLE_BRIDGE_IP_CIDR", b);
		setenv_num(env, "TRESTLE_PREFIX", n->prefix);
	}
	setenv_opt(env, "TRESTLE_PODMAN_NETWORK_ID", hi->podman_network_id);

	/* caller */
	setenv_opt(env, "TRESTLE_USER", hi->user);
	setenv_num(env, "TRESTLE_UID", (long)hi->uid);
	setenv_num(env, "TRESTLE_GID", (long)hi->gid);
	setenv_kv(env, "TRESTLE_ROOTLESS", hi->rootless ? "1" : "0");

	/* container */
	setenv_opt(env, "TRESTLE_CONTAINER_ID", hi->container_id);
	setenv_opt(env, "TRESTLE_CONTAINER_NAME", hi->container_name);
	if (hi->aliases && hi->aliases->n) {
		struct buf al = { 0 };
		for (size_t i = 0; i < hi->aliases->n; i++)
			buf_printf(&al, "%s%s", i ? "," : "", hi->aliases->v[i]);
		setenv_kv(env, "TRESTLE_CONTAINER_ALIASES", al.p);
		buf_free(&al);
	}
	setenv_opt(env, "TRESTLE_K8S_POD_NAME", hi->k8s_pod_name);
	setenv_opt(env, "TRESTLE_K8S_POD_NAMESPACE", hi->k8s_pod_namespace);
	if (hi->container_name && hi->user) {
		char fqdn[300];
		tr_fqdn(n->name, hi->user, hi->container_name, fqdn, sizeof(fqdn));
		setenv_kv(env, "TRESTLE_FQDN", fqdn);
	}

	/* interfaces and addressing */
	setenv_opt(env, "TRESTLE_HOST_IFNAME", hi->host_ifname);
	setenv_opt(env, "TRESTLE_CONTAINER_IFNAME", hi->container_ifname);
	setenv_opt(env, "TRESTLE_HOST_MAC", hi->host_mac);
	setenv_opt(env, "TRESTLE_CONTAINER_MAC", hi->container_mac);
	if (hi->has_ip) {
		tr_fmt_ipv4(hi->ip, a);
		snprintf(b, sizeof(b), "%s/%u", a, hi->prefix);
		setenv_kv(env, "TRESTLE_IP", a);
		setenv_kv(env, "TRESTLE_IP_CIDR", b);
	}
	setenv_opt(env, "TRESTLE_NETNS", hi->netns_path);
	if (hi->netns_fd >= 0) {
		setenv_num(env, "TRESTLE_NETNS_FD", HOOK_NETNS_FD);
		snprintf(b, sizeof(b), "/proc/self/fd/%d", HOOK_NETNS_FD);
		setenv_kv(env, "TRESTLE_NETNS_FD_PATH", b);
	}
}

static bool insecure_mode(const struct stat *st)
{
	return (st->st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
	       (st->st_uid != 0 && st->st_uid != geteuid());
}

int hook_check_script(const char *path, char *err, size_t errlen)
{
	char real[PATH_MAX], dir[PATH_MAX];
	struct stat st;

	if (!path || path[0] != '/') {
		snprintf(err, errlen, "hook script must be an absolute path");
		return -1;
	}
	if (!realpath(path, real) || stat(real, &st) < 0) {
		snprintf(err, errlen, "hook script %s: %s", path, strerror(errno));
		return -1;
	}
	if (!S_ISREG(st.st_mode) || !(st.st_mode & S_IXUSR)) {
		snprintf(err, errlen, "hook script %s is not an executable regular file", path);
		return -1;
	}
	if (insecure_mode(&st)) {
		snprintf(err, errlen, "hook script %s must be owned by root and not writable by group/others", path);
		return -1;
	}
	tr_strlcpy(dir, real, sizeof(dir));
	if (stat(dirname(dir), &st) < 0 || insecure_mode(&st)) {
		snprintf(err, errlen, "directory of hook script %s must be owned by root and not writable by group/others",
			 path);
		return -1;
	}
	return 0;
}

static void log_lines(const char *tag, struct buf *pending, bool flush)
{
	char *start = pending->p;
	if (!start)
		return;
	char *nl;
	while ((nl = strchr(start, '\n'))) {
		*nl = '\0';
		if (*start)
			log_info("%s: %s", tag, start);
		start = nl + 1;
	}
	if (flush && *start) {
		log_info("%s: %s", tag, start);
		start += strlen(start);
	}
	size_t rest = strlen(start);
	memmove(pending->p, start, rest + 1);
	pending->len = rest;
}

static long now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

int hook_run(const char *path, const struct hook_info *hi, int timeout, char *err, size_t errlen)
{
	char tag[160];
	snprintf(tag, sizeof(tag), "%s_script[%s]", hi->event, hi->net->name);

	if (hook_check_script(path, err, errlen) < 0)
		return -1;

	struct strv env = { 0 };
	hook_build_env(hi, &env);

	int out[2];
	if (pipe2(out, O_CLOEXEC) < 0) {
		snprintf(err, errlen, "pipe: %s", strerror(errno));
		strv_clear(&env);
		return -1;
	}
	pid_t pid = fork();
	if (pid < 0) {
		snprintf(err, errlen, "fork: %s", strerror(errno));
		close(out[0]);
		close(out[1]);
		strv_clear(&env);
		return -1;
	}
	if (pid == 0) {
		setpgid(0, 0);
		sigset_t none;
		sigemptyset(&none);
		sigprocmask(SIG_SETMASK, &none, NULL);
		for (int s = 1; s < NSIG; s++)
			signal(s, SIG_DFL);
		/* move the netns fd out of the way of 0-3 first */
		int nsfd = hi->netns_fd >= 0 ? fcntl(hi->netns_fd, F_DUPFD_CLOEXEC, 10) : -1;
		int pipew = fcntl(out[1], F_DUPFD_CLOEXEC, 10);

		int null = open("/dev/null", O_RDONLY);
		if (null >= 0 && null != 0) {
			dup2(null, 0);
			close(null);
		}
		dup2(pipew, 1);
		dup2(pipew, 2);
		if (nsfd >= 0)
			dup2(nsfd, HOOK_NETNS_FD);   /* the copy has FD_CLOEXEC cleared */
		else
			close(HOOK_NETNS_FD);
		/* nothing else leaks: all our other descriptors are O_CLOEXEC,
		 * but close anything inherited without the flag to be sure */
		for (int fd = HOOK_NETNS_FD + 1; fd < 1024; fd++)
			close(fd);
		if (chdir("/") < 0)
			_exit(126);
		char *argv[] = { (char *)path, (char *)hi->event, NULL };
		execve(path, argv, env.v);
		fprintf(stderr, "cannot execute %s: %s\n", path, strerror(errno));
		_exit(127);
	}
	close(out[1]);
	strv_clear(&env);

	struct buf pending = { 0 };
	size_t total = 0;
	bool timed_out = false;
	long deadline = now_ms() + (long)timeout * 1000L;
	for (;;) {
		long left = deadline - now_ms();
		if (left <= 0) {
			timed_out = true;
			kill(-pid, SIGKILL);
			kill(pid, SIGKILL);
			break;
		}
		struct pollfd p = { .fd = out[0], .events = POLLIN };
		int r = poll(&p, 1, (int)(left > 1000 ? 1000 : left));
		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (r == 0)
			continue;
		char chunk[4096];
		ssize_t n = read(out[0], chunk, sizeof(chunk));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (n == 0)
			break;   /* script (and everything holding the pipe) finished */
		if (total < HOOK_MAX_OUTPUT) {
			buf_append(&pending, chunk, (size_t)n);
			log_lines(tag, &pending, false);
		}
		total += (size_t)n;
	}
	log_lines(tag, &pending, true);
	buf_free(&pending);
	close(out[0]);

	/* the pipe may close before the process exits (closed fds,
	 * backgrounded children); wait for the script itself with the
	 * remaining time */
	int status = 0;
	for (;;) {
		pid_t w = waitpid(pid, &status, timed_out ? 0 : WNOHANG);
		if (w == pid)
			break;
		if (w < 0 && errno != EINTR)
			break;
		if (w == 0) {
			if (now_ms() >= deadline) {
				timed_out = true;
				kill(-pid, SIGKILL);
				kill(pid, SIGKILL);
				continue;
			}
			struct timespec ts = { 0, 20 * 1000 * 1000 };
			nanosleep(&ts, NULL);
		}
	}

	if (timed_out) {
		snprintf(err, errlen, "%s %s timed out after %d s", hi->event, path, timeout);
		return -1;
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		log_debug("%s: %s finished", tag, path);
		return 0;
	}
	if (WIFSIGNALED(status))
		snprintf(err, errlen, "%s script %s killed by signal %d", hi->event, path, WTERMSIG(status));
	else
		snprintf(err, errlen, "%s script %s exited with status %d", hi->event, path, WEXITSTATUS(status));
	return -1;
}
