/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * trestled - privileged daemon behind the trestle CNI / Netavark plugin.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../common/config.h"
#include "../common/log.h"
#include "dnsout.h"
#include "handler.h"
#include "nft.h"

#ifndef TRESTLE_VERSION
#define TRESTLE_VERSION "0.1"
#endif

static volatile sig_atomic_t g_stop, g_reload;
static int g_children;
#define MAX_CHILDREN 64

static void reap_children(void)
{
	while (g_children > 0 && waitpid(-1, NULL, WNOHANG) > 0)
		g_children--;
}

static void on_signal(int sig)
{
	if (sig == SIGHUP)
		g_reload = 1;
	else if (sig != SIGCHLD)
		g_stop = 1;
	/* SIGCHLD only interrupts poll() so finished children are reaped */
}

static void sd_notify(const char *msg)
{
	const char *path = getenv("NOTIFY_SOCKET");
	if (!path || !*path)
		return;
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	size_t l = strlen(path);
	if (l >= sizeof(sa.sun_path))
		return;
	memcpy(sa.sun_path, path, l);
	if (sa.sun_path[0] == '@')
		sa.sun_path[0] = '\0';
	int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return;
	sendto(fd, msg, strlen(msg), MSG_NOSIGNAL, (struct sockaddr *)&sa,
	       (socklen_t)(offsetof(struct sockaddr_un, sun_path) + l));
	close(fd);
}

struct listener {
	int fd;
	char path[PATH_MAX];
	dev_t dev;
	ino_t ino;
};

static int apply_socket_perms(const struct tr_config *cfg, const char *path)
{
	struct passwd *pw = getpwnam(cfg->socket_owner);
	struct group *gr = getgrnam(cfg->socket_group);
	if (!pw) {
		log_err("socket_owner '%s' does not exist", cfg->socket_owner);
		return -1;
	}
	if (!gr) {
		log_err("socket_group '%s' does not exist", cfg->socket_group);
		return -1;
	}
	if (chown(path, pw->pw_uid, gr->gr_gid) < 0) {
		log_err("chown %s: %s", path, strerror(errno));
		return -1;
	}
	if (chmod(path, cfg->socket_mode) < 0) {
		log_err("chmod %s: %s", path, strerror(errno));
		return -1;
	}
	return 0;
}

static int open_listener(const struct tr_config *cfg, struct listener *L)
{
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	struct stat st;

	if (strlen(cfg->socket_path) >= sizeof(sa.sun_path)) {
		log_err("socket path %s is too long", cfg->socket_path);
		return -1;
	}
	/* remove whatever currently sits at the socket path (stale socket,
	 * a socket of another process or a planted file) */
	if (lstat(cfg->socket_path, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			log_err("%s is a directory; refusing to start", cfg->socket_path);
			return -1;
		}
		if (unlink(cfg->socket_path) < 0) {
			log_err("cannot remove existing %s: %s", cfg->socket_path, strerror(errno));
			return -1;
		}
		log_notice("removed existing %s", cfg->socket_path);
	}
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		log_err("socket: %s", strerror(errno));
		return -1;
	}
	tr_strlcpy(sa.sun_path, cfg->socket_path, sizeof(sa.sun_path));
	mode_t old = umask(0177);  /* nobody can connect until perms are set */
	int r = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	umask(old);
	if (r < 0) {
		log_err("bind %s: %s", cfg->socket_path, strerror(errno));
		close(fd);
		return -1;
	}
	if (apply_socket_perms(cfg, cfg->socket_path) < 0 || listen(fd, 64) < 0) {
		close(fd);
		unlink(cfg->socket_path);
		return -1;
	}
	stat(cfg->socket_path, &st);
	L->fd = fd;
	L->dev = st.st_dev;
	L->ino = st.st_ino;
	tr_strlcpy(L->path, cfg->socket_path, sizeof(L->path));
	log_info("listening on %s (owner %s:%s mode %04o)", L->path, cfg->socket_owner,
		 cfg->socket_group, (unsigned)cfg->socket_mode);
	return 0;
}

static void close_listener(struct listener *L)
{
	struct stat st;
	if (L->fd < 0)
		return;
	close(L->fd);
	/* only unlink the path if it is still our socket */
	if (lstat(L->path, &st) == 0 && st.st_dev == L->dev && st.st_ino == L->ino)
		unlink(L->path);
	L->fd = -1;
}

static bool listener_intact(const struct listener *L)
{
	struct stat st;
	return lstat(L->path, &st) == 0 && S_ISSOCK(st.st_mode) && st.st_dev == L->dev && st.st_ino == L->ino;
}

static int prepare_runtime(const struct tr_config *cfg)
{
	int r = tr_mkdir_p(cfg->state_dir, 0700);
	if (r) {
		log_err("cannot create %s: %s", cfg->state_dir, strerror(-r));
		return -1;
	}
	/* leases and records name users and containers: keep them private */
	if (chmod(cfg->state_dir, 0700) < 0)
		log_warn("cannot restrict permissions of %s: %s", cfg->state_dir, strerror(errno));
	if (cfg->ip_forward) {
		int fd = open("/proc/sys/net/ipv4/ip_forward", O_WRONLY | O_CLOEXEC);
		if (fd < 0 || write(fd, "1\n", 2) != 2)
			log_warn("cannot enable IPv4 forwarding: %s", strerror(errno));
		else
			log_info("enabled IPv4 forwarding");
		if (fd >= 0)
			close(fd);
	}
	nft_apply(cfg);
	hosts_refresh_all(cfg);
	return 0;
}

static int load(const char *path, struct tr_config *cfg)
{
	char err[1024];
	config_defaults(cfg);
	if (config_load(cfg, path, err, sizeof(err)) < 0) {
		log_err("configuration error: %s", err);
		config_free(cfg);
		return -1;
	}
	return 0;
}

static void usage(FILE *f)
{
	fprintf(f,
		"Usage: trestled [options]\n"
		"  -c, --config FILE   configuration file (default %s)\n"
		"  -f, --foreground    log to stderr (default when started by systemd)\n"
		"  -d, --debug         debug logging\n"
		"  -t, --test          check the configuration and exit\n"
		"  -V, --version       print version\n"
		"  -h, --help          this help\n",
		TRESTLE_DEFAULT_CONFIG);
}

int main(int argc, char **argv)
{
	const char *cfgpath = TRESTLE_DEFAULT_CONFIG;
	bool fg = false, debug = false, test = false;
	static const struct option opts[] = {
		{ "config", required_argument, NULL, 'c' }, { "foreground", no_argument, NULL, 'f' },
		{ "debug", no_argument, NULL, 'd' },        { "test", no_argument, NULL, 't' },
		{ "version", no_argument, NULL, 'V' },      { "help", no_argument, NULL, 'h' },
		{ 0 }
	};
	int c;
	while ((c = getopt_long(argc, argv, "c:fdtVh", opts, NULL)) != -1) {
		switch (c) {
		case 'c': cfgpath = optarg; break;
		case 'f': fg = true; break;
		case 'd': debug = true; break;
		case 't': test = true; fg = true; break;
		case 'V': printf("trestled %s\n", TRESTLE_VERSION); return 0;
		case 'h': usage(stdout); return 0;
		default: usage(stderr); return 2;
		}
	}

	tlog_init("trestled", tlog_detect_target(fg), debug ? LOG_DEBUG : LOG_INFO);

	struct tr_config cfg;
	if (load(cfgpath, &cfg) < 0)
		return 1;
	if (!debug)
		tlog_set_level(cfg.log_level);
	if (test) {
		struct buf b = { 0 };
		printf("configuration OK: %zu network(s)\n", cfg.nnets);
		for (size_t i = 0; i < cfg.nnets; i++)
			printf("  %-20s bridge %s\n", cfg.nets[i].name, cfg.nets[i].bridge);
		if (nft_build_ruleset(&cfg, &b))
			printf("\nnftables ruleset:\n%s", b.p);
		buf_free(&b);
		config_free(&cfg);
		return 0;
	}
	if (geteuid() != 0) {
		log_err("trestled must run as root");
		return 1;
	}

	if (prepare_runtime(&cfg) < 0)
		return 1;

	/* single instance */
	char lockpath[PATH_MAX];
	snprintf(lockpath, sizeof(lockpath), "%s/trestled.lock", cfg.state_dir);
	int lockfd = open(lockpath, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (lockfd < 0 || flock(lockfd, LOCK_EX | LOCK_NB) < 0) {
		log_err("another trestled is already running (lock %s)", lockpath);
		return 1;
	}

	struct sigaction sa = { .sa_handler = on_signal };
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGCHLD, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);

	struct listener L = { .fd = -1 };
	if (open_listener(&cfg, &L) < 0)
		return 1;

	log_info("trestled %s started with %zu network(s)", TRESTLE_VERSION, cfg.nnets);
	sd_notify("READY=1\nSTATUS=Serving requests");

	while (!g_stop) {
		if (g_reload) {
			g_reload = 0;
			sd_notify("RELOADING=1");
			struct tr_config ncfg;
			if (load(cfgpath, &ncfg) == 0) {
				bool sock_changed = strcmp(ncfg.socket_path, cfg.socket_path) != 0;
				config_free(&cfg);
				cfg = ncfg;
				if (!debug)
					tlog_set_level(cfg.log_level);
				prepare_runtime(&cfg);
				if (sock_changed) {
					close_listener(&L);
					if (open_listener(&cfg, &L) < 0)
						g_stop = 1;
				} else {
					apply_socket_perms(&cfg, L.path);
				}
				log_info("configuration reloaded (%zu network(s))", cfg.nnets);
			} else {
				log_err("reload failed; keeping the previous configuration");
			}
			sd_notify("READY=1");
			continue;
		}

		reap_children();
		struct pollfd p = { .fd = L.fd, .events = POLLIN };
		int r = poll(&p, 1, 30000);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			log_err("poll: %s", strerror(errno));
			break;
		}
		reap_children();
		if (r == 0) {
			/* someone removed or replaced our socket? recreate it */
			if (!listener_intact(&L)) {
				log_warn("%s was removed or replaced; recreating it", L.path);
				close(L.fd);
				L.fd = -1;
				if (open_listener(&cfg, &L) < 0)
					break;
			}
			continue;
		}
		int cfd = accept4(L.fd, NULL, NULL, SOCK_CLOEXEC);
		if (cfd < 0) {
			if (errno != EINTR && errno != EAGAIN && errno != ECONNABORTED)
				log_warn("accept: %s", strerror(errno));
			continue;
		}
		struct timeval tv = { .tv_sec = cfg.request_timeout };
		setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

		/* One child per connection so a slow or stalled client cannot
		 * block others. Children serialize the actual work with a lock
		 * on the state directory (see handler.c). */
		reap_children();
		if (g_children >= MAX_CHILDREN) {
			log_warn("too many concurrent requests (%d); rejecting connection", g_children);
			close(cfd);
			continue;
		}
		pid_t pid = fork();
		if (pid == 0) {
			close(L.fd);
			close(lockfd);
			signal(SIGTERM, SIG_DFL);
			signal(SIGINT, SIG_DFL);
			signal(SIGHUP, SIG_IGN);
			signal(SIGCHLD, SIG_DFL);
			handle_connection(&cfg, cfd);
			close(cfd);
			config_free(&cfg);
			_exit(0);
		}
		if (pid < 0) {
			log_warn("fork: %s; handling request inline", strerror(errno));
			handle_connection(&cfg, cfd);
		} else {
			g_children++;
		}
		close(cfd);
	}
	/* let in-flight requests finish */
	while (g_children > 0 && waitpid(-1, NULL, 0) > 0)
		g_children--;

	sd_notify("STOPPING=1");
	log_info("shutting down");
	close_listener(&L);
	if (cfg.firewall_cleanup)
		nft_cleanup(&cfg);
	config_free(&cfg);
	close(lockfd);
	return 0;
}
