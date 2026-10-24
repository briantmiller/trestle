/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "keeper.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../common/log.h"
#include "checks.h"
#include "dhcp.h"
#include "dnsout.h"
#include "exec.h"
#include "netlink.h"
#include "netset.h"
#include "nft.h"

#define KEEPER_FD 3

static void pid_path(const struct tr_config *cfg, const char *veth, char *out, size_t len)
{
	snprintf(out, len, "%s/dhcp/%s.pid", cfg->state_dir, veth);
}

/* Exists and is not a zombie (a dead keeper whose parent did not reap it
 * yet must count as gone). */
static bool alive(pid_t pid)
{
	if (pid <= 1 || kill(pid, 0) != 0)
		return false;
	char p[64], buf[512];
	snprintf(p, sizeof(p), "/proc/%d/stat", (int)pid);
	int fd = open(p, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return false;
	buf[n] = '\0';
	const char *e = strrchr(buf, ')');   /* comm may contain spaces */
	return e && e[1] == ' ' && e[2] != 'Z' && e[2] != 'X';
}

static pid_t read_pid(const struct tr_config *cfg, const char *veth)
{
	char p[PATH_MAX];
	pid_path(cfg, veth, p, sizeof(p));
	char *t = tr_read_file(p, 64, NULL);
	if (!t)
		return 0;
	long v = strtol(t, NULL, 10);
	free(t);
	if (v <= 1 || !alive((pid_t)v))
		return 0;
	/* make sure the pid still is a keeper (pids are reused) */
	char cl[PATH_MAX], buf[512];
	snprintf(cl, sizeof(cl), "/proc/%ld/cmdline", v);
	int fd = open(cl, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	/* just started (between fork and exec it still looks like trestled) */
	struct stat st;
	if (stat(p, &st) == 0 && time(NULL) - st.st_mtime < 30) {
		close(fd);
		return (pid_t)v;
	}
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = '\0';
	for (ssize_t i = 0; i < n; i++)
		if (!buf[i])
			buf[i] = ' ';
	return strstr(buf, "--dhcp-keeper") ? (pid_t)v : 0;
}

bool keeper_running(const struct tr_config *cfg, const char *veth)
{
	return read_pid(cfg, veth) > 0;
}

void keeper_stop(const struct tr_config *cfg, const char *veth)
{
	pid_t pid = read_pid(cfg, veth);
	char p[PATH_MAX];
	pid_path(cfg, veth, p, sizeof(p));
	if (pid > 0 && kill(pid, SIGTERM) == 0) {
		/* the keeper sends DHCPRELEASE and exits */
		for (int i = 0; i < 30 && alive(pid); i++) {
			waitpid(pid, NULL, WNOHANG);
			tr_sleep_ms(100);
		}
		if (alive(pid)) {
			log_warn("DHCP keeper %d for %s did not stop; killing it", (int)pid, veth);
			kill(pid, SIGKILL);
		}
	}
	unlink(p);
}

int keeper_start(const struct tr_config *cfg, const struct tr_attachment *a, int nsfd)
{
	char self[PATH_MAX];
	ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
	if (n <= 0)
		return -errno;
	self[n] = '\0';
	char dir[PATH_MAX], unit[64];
	snprintf(dir, sizeof(dir), "%s/dhcp", cfg->state_dir);
	tr_mkdir_p(dir, 0700);
	snprintf(unit, sizeof(unit), "--unit=trestle-dhcp-%s", a->veth);
	bool use_systemd = access("/run/systemd/system", F_OK) == 0 && access("/usr/bin/systemd-run", X_OK) == 0;

	pid_t pid = fork();
	if (pid < 0)
		return -errno;
	if (pid == 0) {
		for (int s = 1; s < NSIG; s++)
			if (s != SIGKILL && s != SIGSTOP)
				signal(s, SIG_DFL);
		sigset_t none;
		sigemptyset(&none);
		sigprocmask(SIG_SETMASK, &none, NULL);
		setsid();
		if (nsfd != KEEPER_FD) {
			if (dup2(nsfd, KEEPER_FD) < 0)
				_exit(126);
		} else {
			fcntl(KEEPER_FD, F_SETFD, 0);   /* clear close-on-exec */
		}
		int null = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (null >= 0) {
			dup2(null, 0);
			dup2(null, 1);
		}
		/* stderr stays: keeper messages end up in trestled's log */
		if (use_systemd)
			execl("/usr/bin/systemd-run", "systemd-run", "-q", "--scope", unit, "--collect",
			      "--description=trestle DHCP lease keeper", self, "--dhcp-keeper", "-c", cfg->config_path,
			      a->network, a->container_id, (char *)NULL);
		execl(self, "trestled", "--dhcp-keeper", "-c", cfg->config_path, a->network, a->container_id,
		      (char *)NULL);
		_exit(127);
	}
	/* the exec keeps the pid (systemd-run --scope execs the keeper in
	 * place), so record it now: a sweep right after this request must not
	 * start a second keeper */
	char p[PATH_MAX], pidtxt[32];
	pid_path(cfg, a->veth, p, sizeof(p));
	snprintf(pidtxt, sizeof(pidtxt), "%d\n", (int)pid);
	tr_write_file_atomic(p, pidtxt, strlen(pidtxt), 0600);
	return 0;
}

/* ---- keeper process -------------------------------------------------- */

static volatile sig_atomic_t g_stop;
static void on_term(int sig) { (void)sig; g_stop = 1; }

int keeper_configure(int nlc, const char *ifname, uint32_t old_ip, uint8_t old_prefix,
		     uint32_t ip, uint8_t prefix, uint32_t router, char *err, size_t errlen)
{
	struct nl_link c;
	int r = nl_get_link(nlc, ifname, &c);
	if (r) {
		snprintf(err, errlen, "container interface %s: %s", ifname, strerror(-r));
		return -1;
	}
	if (old_ip && (old_ip != ip || old_prefix != prefix))
		nl_addr_del(nlc, c.ifindex, old_ip, old_prefix);
	if (!ip)
		return 0;
	if ((r = nl_addr_add(nlc, c.ifindex, ip, prefix)) && r != -EEXIST) {
		snprintf(err, errlen, "cannot assign address in container: %s", strerror(-r));
		return -1;
	}
	if (router && (r = nl_route_add_default(nlc, c.ifindex, router)) && r != -EEXIST) {
		snprintf(err, errlen, "cannot add default route in container: %s", strerror(-r));
		return -1;
	}
	return 0;
}

/* Write the lease into the attachment record and republish (nftables
 * anti-spoofing sets, DNS outputs). Returns 1 if the record is gone. */
static int publish(const struct tr_config *cfg, const struct tr_network *n, const char *cid,
		   const struct dhcp_lease *l, bool bound, time_t expiry)
{
	int lock = state_lock(cfg->state_dir, true);
	if (lock < 0)
		return g_stop ? 0 : -1;
	struct tr_attachment a;
	if (state_load(cfg->state_dir, n->name, cid, &a) != 0) {
		close(lock);
		return 1;
	}
	bool ip_changed = a.has_ip != bound || (bound && (a.ip != l->ip || a.prefix != l->prefix));
	a.has_ip = bound;
	a.ip = bound ? l->ip : 0;
	a.prefix = bound ? l->prefix : 0;
	a.gateway = bound ? l->router : 0;
	memcpy(a.dns, bound ? l->dns : (uint32_t[3]){ 0 }, sizeof(a.dns));
	a.dhcp_server = bound ? l->server : 0;
	a.lease_expiry = bound ? (long long)expiry : 0;
	int r = state_save(cfg->state_dir, &a);
	if (r)
		log_err("cannot save lease of %s: %s", a.veth, strerror(-r));
	if (ip_changed) {
		nft_apply(cfg);
		dns_refresh(cfg, n);
	}
	attachment_free(&a);
	close(lock);
	return 0;
}

int keeper_main(const char *cfgpath, const char *network, const char *cid, bool debug)
{
	struct tr_config cfg;
	char err[512];
	tlog_init("trestled", tlog_detect_target(1), debug ? LOG_DEBUG : LOG_INFO);
	config_defaults(&cfg);
	if (config_load(&cfg, cfgpath, err, sizeof(err)) < 0) {
		log_err("dhcp keeper: configuration error: %s", err);
		return 1;
	}
	if (!debug)
		tlog_set_level(cfg.log_level);
	struct tr_network storage;
	const struct tr_network *n;
	if (net_resolve(&cfg, network, false, &storage, &n, NULL, err, sizeof(err)) != 0 || !n->dhcp) {
		log_err("dhcp keeper: network %s is not an ipam = dhcp network", network);
		return 1;
	}
	struct tr_attachment a;
	if (state_load(cfg.state_dir, network, cid, &a) != 0 || !a.dhcp) {
		log_err("dhcp keeper: no DHCP attachment %s on %s", cid, network);
		return 1;
	}
	uint8_t mac[6];
	if (!tr_valid_mac(a.mac, mac)) {
		log_err("dhcp keeper: attachment %s has no valid MAC", cid);
		return 1;
	}

	char p[PATH_MAX], pid[32];
	pid_path(&cfg, a.veth, p, sizeof(p));
	snprintf(pid, sizeof(pid), "%d\n", (int)getpid());
	tr_write_file_atomic(p, pid, strlen(pid), 0600);

	struct sigaction sa = { .sa_handler = on_term };   /* no SA_RESTART: flock/poll return EINTR */
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	int hostnl = nl_open();
	int sock = dhcp_socket(KEEPER_FD, a.ifname, err, sizeof(err));
	int nlc = netns_nl_open(KEEPER_FD, err, sizeof(err));
	if (hostnl < 0 || sock < 0 || nlc < 0) {
		log_err("dhcp keeper for %s: %s", a.veth, err);
		unlink(p);
		return 1;
	}
	char host[64] = "";
	if (n->dhcp_hostname)
		dhcp_hostname(a.container_name, host, sizeof(host));

	struct dhcp_lease cur = { 0 };
	bool bound = a.has_ip;
	time_t now = time(NULL), expiry = (time_t)a.lease_expiry, t1, t2, next_try = 0, next_check = 0;
	if (bound) {
		cur.ip = a.ip;
		cur.prefix = a.prefix;
		cur.router = a.gateway;
		memcpy(cur.dns, a.dns, sizeof(cur.dns));
		cur.server = a.dhcp_server;
		long rem = expiry > now ? (long)(expiry - now) : 0;
		t1 = now + rem / 2;
		t2 = now + rem / 8 * 7;
	} else {
		t1 = t2 = 0;
	}
	log_info("DHCP keeper for %s (%s on %s) running", a.veth, a.container_name, network);

	while (!g_stop) {
		now = time(NULL);
		if (now >= next_check) {
			struct nl_link l;
			struct tr_attachment chk;
			if (nl_get_link(hostnl, a.veth, &l) != 0) {
				log_info("DHCP keeper for %s: interface gone, exiting", a.veth);
				break;
			}
			if (state_load(cfg.state_dir, network, cid, &chk) != 0) {
				log_info("DHCP keeper for %s: attachment removed, exiting", a.veth);
				break;
			}
			attachment_free(&chk);
			next_check = now + 10;
		}

		if (bound && now >= expiry) {
			char ip[16];
			tr_fmt_ipv4(cur.ip, ip);
			log_warn("DHCP lease %s of %s expired", ip, a.veth);
			keeper_configure(nlc, a.ifname, cur.ip, cur.prefix, 0, 0, 0, err, sizeof(err));
			bound = false;
			publish(&cfg, n, cid, &cur, false, 0);
			next_try = now;
		}

		struct dhcp_lease l;
		int r = -1;
		if (!bound && now >= next_try) {
			if (dhcp_acquire(sock, mac, host, 10000, &l, err, sizeof(err)) == 0)
				r = 0;
			else if (!g_stop)
				log_warn("DHCP for %s: %s; retrying", a.veth, err);
			next_try = time(NULL) + 30;
		} else if (bound && now >= t1) {
			r = dhcp_renew(sock, mac, host, &cur, now >= t2, 5000, &l);
			if (r < 0) {
				/* retry: halfway to T2 (renewing) or to expiry (rebinding) */
				time_t until = now < t2 ? t2 : expiry;
				time_t step = (until - now) / 2;
				if (step < 30)
					step = 30;
				if (now < t2)
					t1 = now + step;
				else
					t2 = now + step, t1 = t2;
			} else if (r == 1) {
				char ip[16];
				tr_fmt_ipv4(cur.ip, ip);
				log_warn("DHCP server refused to extend %s for %s; getting a new lease", ip, a.veth);
				keeper_configure(nlc, a.ifname, cur.ip, cur.prefix, 0, 0, 0, err, sizeof(err));
				bound = false;
				publish(&cfg, n, cid, &cur, false, 0);
				next_try = time(NULL);
			}
		}
		if (r == 0) {
			now = time(NULL);
			if (keeper_configure(nlc, a.ifname, bound ? cur.ip : 0, cur.prefix, l.ip, l.prefix, l.router,
					     err, sizeof(err)) < 0) {
				log_err("DHCP for %s: %s", a.veth, err);
			} else {
				char ip[16];
				tr_fmt_ipv4(l.ip, ip);
				if (!bound || l.ip != cur.ip)
					log_info("DHCP: %s (%s) now has %s/%u for %u s", a.veth, a.container_name, ip,
						 l.prefix, l.lease_time);
				else
					log_debug("DHCP: renewed %s for %s (%u s)", ip, a.veth, l.lease_time);
				cur = l;
				bound = true;
				expiry = now + l.lease_time;
				t1 = now + l.t1;
				t2 = now + l.t2;
				if (publish(&cfg, n, cid, &cur, true, expiry) == 1)
					break;
			}
		}
		tr_sleep_ms(1000);
	}
	if (g_stop && bound) {
		dhcp_release(sock, mac, &cur);
		log_info("DHCP keeper for %s: released the lease", a.veth);
	}
	close(sock);
	close(nlc);
	close(hostnl);
	unlink(p);
	attachment_free(&a);
	config_free(&cfg);
	return 0;
}
