/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * trestle - CNI and Netavark network plugin (client side).
 *
 * This small binary is executed by a CNI runtime (CNI_* environment
 * variables) or by Netavark (`trestle create|setup|teardown|info`). It
 * validates the invocation, optionally opens the container network
 * namespace and hands it over to the privileged trestled daemon through a
 * unix socket. The daemon does all privileged work and returns the exact
 * output (CNI result / Netavark status block) that we print on stdout.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <libgen.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "../common/config.h"
#include "../common/log.h"
#include "../common/proto.h"
#include "../common/request.h"
#include "../common/util.h"

#ifndef TRESTLE_VERSION
#define TRESTLE_VERSION "0.2"
#endif

extern char **environ;

static const char *env_lookup(void *ctx, const char *name)
{
	(void)ctx;
	return getenv(name);
}

static char *read_stdin(size_t max, char *err, size_t errlen)
{
	struct buf b = { 0 };
	char chunk[8192];

	if (isatty(STDIN_FILENO)) {
		buf_append(&b, "", 0);
		return b.p;
	}
	for (;;) {
		ssize_t r = read(STDIN_FILENO, chunk, sizeof(chunk));
		if (r < 0) {
			if (errno == EINTR)
				continue;
			snprintf(err, errlen, "failed to read stdin: %s", strerror(errno));
			buf_free(&b);
			return NULL;
		}
		if (r == 0)
			break;
		if (b.len + (size_t)r > max) {
			snprintf(err, errlen, "stdin exceeds %zu bytes", max);
			buf_free(&b);
			return NULL;
		}
		buf_append(&b, chunk, (size_t)r);
	}
	if (!b.p)
		buf_append(&b, "", 0);
	if (memchr(b.p, '\0', b.len)) {
		snprintf(err, errlen, "stdin contains NUL bytes");
		buf_free(&b);
		return NULL;
	}
	return b.p;
}

/* Print an error in the format the caller understands and exit. */
static void __attribute__((noreturn))
die_mode(enum tr_mode mode, const char *cni_version, int cni_code, const char *msg)
{
	char *s = mode == TR_MODE_CNI ? tr_format_cni_error(cni_version, cni_code, msg, NULL)
				      : tr_format_netavark_error(msg);
	if (s) {
		fputs(s, stdout);
		fputc('\n', stdout);
		free(s);
	}
	fflush(stdout);
	log_debug("error: %s", msg);
	exit(1);
}

static void usage(FILE *f)
{
	fprintf(f,
		"trestle %s - CNI / Netavark plugin for rootless host bridges\n"
		"\n"
		"Netavark plugin usage:\n"
		"  trestle info\n"
		"  trestle create             < network.json\n"
		"  trestle setup <netns>      < plugin-exec.json\n"
		"  trestle teardown <netns>   < plugin-exec.json\n"
		"\n"
		"CNI plugin usage: set CNI_COMMAND and the other CNI_* variables and\n"
		"pass the network configuration on stdin.\n"
		"\n"
		"The privileged work is done by trestled(8). See trestle(8).\n",
		TRESTLE_VERSION);
}

/* ---------------------------------------------------------------------- */

static int connect_socket(const char *path, int timeout_s, char *err, size_t errlen)
{
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	if (tr_strlcpy(sa.sun_path, path, sizeof(sa.sun_path)) >= sizeof(sa.sun_path)) {
		snprintf(err, errlen, "socket path too long");
		return -1;
	}
	int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (s < 0) {
		snprintf(err, errlen, "socket: %s", strerror(errno));
		return -1;
	}
	struct timeval tv = { .tv_sec = timeout_s };
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		snprintf(err, errlen, "cannot connect to trestled at %s: %s (is trestled running?)",
			 path, strerror(errno));
		close(s);
		return -1;
	}
	return s;
}

static bool root_like(uid_t uid, bool in_userns, uid_t ovf)
{
	return uid == 0 || (in_userns && uid == ovf);
}

/*
 * Make sure the process listening on the socket is the real trestle server.
 *
 *  - the peer (SO_PEERCRED) must be root (seen as the overflow uid when we
 *    run inside a rootless user namespace),
 *  - the socket file must be a socket owned by root (same rule),
 *  - /proc/<pid>/exe must point to the configured server binary. Inside a
 *    rootless user namespace the kernel does not allow reading another
 *    user's exe link; in "relaxed" mode we then fall back to checking
 *    /proc/<pid>/comm, in "strict" mode we refuse.
 *  - optionally the SELinux type of the peer (server_selinux_type).
 */
static int verify_server(int sock, const struct tr_config *cfg, char *err, size_t errlen)
{
	struct ucred cr;
	socklen_t cl = sizeof(cr);
	bool in_userns = tr_in_user_namespace();
	uid_t ovf = tr_overflow_uid();

	if (cfg->verify_server == TR_VERIFY_NONE)
		return 0;

	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cr, &cl) < 0) {
		snprintf(err, errlen, "SO_PEERCRED: %s", strerror(errno));
		return -1;
	}
	if (!root_like(cr.uid, in_userns, ovf)) {
		snprintf(err, errlen, "refusing to talk to %s: the listening process (pid %d) runs as uid %u, not root",
			 cfg->socket_path, (int)cr.pid, (unsigned)cr.uid);
		return -1;
	}

	struct stat st;
	if (lstat(cfg->socket_path, &st) < 0 || !S_ISSOCK(st.st_mode)) {
		snprintf(err, errlen, "%s is not a socket", cfg->socket_path);
		return -1;
	}
	if (!strcmp(cfg->socket_owner, "root") && !root_like(st.st_uid, in_userns, ovf)) {
		snprintf(err, errlen, "refusing to use %s: socket file is owned by uid %u, not root",
			 cfg->socket_path, (unsigned)st.st_uid);
		return -1;
	}

	char want[PATH_MAX];
	if (!realpath(cfg->server_binary, want))
		tr_strlcpy(want, cfg->server_binary, sizeof(want));

	bool verified = false;
	if (cr.pid > 0) {
		char p[64], got[PATH_MAX];
		snprintf(p, sizeof(p), "/proc/%d/exe", (int)cr.pid);
		ssize_t n = readlink(p, got, sizeof(got) - 1);
		if (n > 0) {
			got[n] = '\0';
			if (strcmp(got, want) != 0) {
				snprintf(err, errlen, "refusing to talk to %s: server pid %d runs %s, expected %s",
					 cfg->socket_path, (int)cr.pid, got, want);
				return -1;
			}
			verified = true;
		} else if (cfg->verify_server == TR_VERIFY_STRICT) {
			snprintf(err, errlen, "cannot verify trestled binary (%s: %s) and verify_server=strict",
				 p, strerror(errno));
			return -1;
		} else {
			/* relaxed: comm is readable across user namespaces */
			snprintf(p, sizeof(p), "/proc/%d/comm", (int)cr.pid);
			char *comm = tr_read_file(p, 64, NULL);
			if (comm) {
				char base[PATH_MAX];
				tr_strlcpy(base, want, sizeof(base));
				char expect[16];
				tr_strlcpy(expect, basename(base), sizeof(expect)); /* comm is <=15 chars */
				if (strcmp(tr_trim(comm), expect) != 0) {
					snprintf(err, errlen, "refusing to talk to %s: server process name is '%s', expected '%s'",
						 cfg->socket_path, tr_trim(comm), expect);
					free(comm);
					return -1;
				}
				free(comm);
				verified = true;
			}
		}
	} else if (cfg->verify_server == TR_VERIFY_STRICT) {
		snprintf(err, errlen, "server pid is not visible from this pid namespace and verify_server=strict");
		return -1;
	}
	if (!verified)
		log_debug("server binary could not be verified from this namespace; relying on uid checks");

	if (cfg->server_selinux_type[0]) {
		char label[256];
		socklen_t ll = sizeof(label) - 1;
		if (getsockopt(sock, SOL_SOCKET, SO_PEERSEC, label, &ll) < 0) {
			snprintf(err, errlen, "cannot read server SELinux label: %s", strerror(errno));
			return -1;
		}
		label[ll] = '\0';
		char needle[160];
		snprintf(needle, sizeof(needle), ":%s:", cfg->server_selinux_type);
		if (!strstr(label, needle)) {
			snprintf(err, errlen, "refusing to talk to server with SELinux label %s", label);
			return -1;
		}
	}
	return 0;
}

/* ---------------------------------------------------------------------- */

static char *build_request(int argc, char **argv, const struct tr_request *r,
			   const char *stdin_text, bool rootless, bool have_fd)
{
	json_object *o = json_object_new_object();
	json_object_object_add(o, "version", json_object_new_int(TR_PROTO_VERSION));
	json_object_object_add(o, "mode", json_object_new_string(r->mode == TR_MODE_CNI ? "cni" :
								  r->mode == TR_MODE_ADMIN ? "admin" : "netavark"));
	json_object_object_add(o, "command", json_object_new_string(r->command));

	json_object *av = json_object_new_array();
	for (int i = 0; i < argc; i++)
		json_object_array_add(av, json_object_new_string(argv[i]));
	json_object_object_add(o, "argv", av);

	json_object *env = json_object_new_object();
	if (r->mode == TR_MODE_CNI)
		for (char **e = environ; e && *e; e++) {
			if (strncmp(*e, "CNI_", 4) != 0)
				continue;
			const char *eq = strchr(*e, '=');
			if (!eq)
				continue;
			char key[64];
			size_t kl = (size_t)(eq - *e);
			if (kl >= sizeof(key))
				continue;
			memcpy(key, *e, kl);
			key[kl] = '\0';
			json_object_object_add(env, key, json_object_new_string(eq + 1));
		}
	json_object_object_add(o, "env", env);
	json_object_object_add(o, "netns_path", json_object_new_string(r->netns_path));
	json_object_object_add(o, "netns_fd", json_object_new_boolean(have_fd));
	json_object_object_add(o, "rootless", json_object_new_boolean(rootless));
	json_object_object_add(o, "stdin", json_object_new_string(stdin_text ? stdin_text : ""));

	char *s = strdup(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE));
	json_object_put(o);
	return s;
}

static void load_client_config(struct tr_config *cfg)
{
	char err[512];
	const char *path = getenv("TRESTLE_CONFIG");
	if (!path || !*path)
		path = TRESTLE_DEFAULT_CONFIG;
	config_defaults(cfg);
	if (access(path, R_OK) != 0) {
		/* config may be unreadable for unprivileged users: use the
		 * defaults and allow for long-running hook scripts */
		cfg->request_timeout = 600;
		return;
	}
	if (config_load(cfg, path, err, sizeof(err)) < 0) {
		log_warn("ignoring unusable configuration: %s", err);
		config_free(cfg);
		config_defaults(cfg);
	}
}

/* ---- trestlectl -------------------------------------------------------- */

static void ctl_usage(FILE *f)
{
	fprintf(f,
		"trestlectl %s - inspect and clean up trestle attachments\n"
		"\n"
		"  trestlectl status                 networks, attachments, free addresses\n"
		"  trestlectl list [-n NETWORK]      attachments (your own unless root)\n"
		"  trestlectl leases [-n NETWORK]    IP leases (root)\n"
		"  trestlectl gc [-n NETWORK] [--dry-run]\n"
		"                                    remove stale attachments and leases (root)\n"
		"  trestlectl detach NETWORK CONTAINER-ID\n"
		"                                    force-remove an attachment (owner or root)\n"
		"\n"
		"  --json   machine readable output\n",
		TRESTLE_VERSION);
}

static const char *js(json_object *o, const char *k)
{
	json_object *v;
	if (!o || !json_object_object_get_ex(o, k, &v) || !v)
		return "-";
	const char *s = json_object_get_string(v);
	return s && *s ? s : "-";
}

static bool jb(json_object *o, const char *k)
{
	json_object *v;
	return o && json_object_object_get_ex(o, k, &v) && v && json_object_get_boolean(v);
}

static json_object *ja(json_object *o, const char *k)
{
	json_object *v;
	return o && json_object_object_get_ex(o, k, &v) && json_object_is_type(v, json_type_array) ? v : NULL;
}

static void print_strings(const char *title, json_object *arr)
{
	size_t n = arr ? json_object_array_length(arr) : 0;
	printf("%s: %zu\n", title, n);
	for (size_t i = 0; i < n; i++)
		printf("  %s\n", json_object_get_string(json_object_array_get_idx(arr, i)));
}

static void ctl_print(const struct tr_request *r, json_object *o)
{
	switch (r->cmd) {
	case TR_CMD_ADM_STATUS: {
		json_object *a = ja(o, "networks");
		printf("trestled %s, stale state sweep every %s s\n\n", js(o, "version"), js(o, "gc_interval"));
		printf("%-20s %-16s %-18s %-7s %-10s %-9s %8s %6s\n", "NETWORK", "BRIDGE", "SUBNET", "IPAM",
		       "ISOLATION", "ANTISPOOF", "ATTACHED", "FREE");
		for (size_t i = 0; a && i < json_object_array_length(a); i++) {
			json_object *e = json_object_array_get_idx(a, i);
			char br[24];
			snprintf(br, sizeof(br), "%s%s", js(e, "bridge"), jb(e, "bridge_present") ? "" : "*");
			printf("%-20s %-16s %-18s %-7s %-10s %-9s %8s %6s\n", js(e, "name"), br, js(e, "subnet"),
			       js(e, "ipam"), js(e, "isolation"), jb(e, "anti_spoofing") ? "yes" : "no",
			       js(e, "attachments"), js(e, "free_addresses"));
		}
		printf("\n(* = bridge does not exist right now)\n");
		break;
	}
	case TR_CMD_ADM_LIST: {
		json_object *a = ja(o, "attachments");
		printf("%-16s %-14s %-20s %-10s %-16s %-6s %-18s %-17s %s\n", "NETWORK", "CONTAINER", "NAME", "USER",
		       "HOST IF", "IF", "IP", "MAC", "STATE");
		for (size_t i = 0; a && i < json_object_array_length(a); i++) {
			json_object *e = json_object_array_get_idx(a, i);
			char state[64];
			snprintf(state, sizeof(state), "%s%s", jb(e, "present") ? "up" : "STALE",
				 jb(e, "dhcp") ? (jb(e, "keeper") ? ",dhcp" : ",dhcp-no-keeper") : "");
			printf("%-16s %-14.12s %-20s %-10s %-16s %-6s %-18s %-17s %s\n", js(e, "network"),
			       js(e, "container_id"), js(e, "container_name"), js(e, "user"), js(e, "veth"),
			       js(e, "ifname"), js(e, "ip"), js(e, "mac"), state);
		}
		break;
	}
	case TR_CMD_ADM_LEASES: {
		json_object *a = ja(o, "leases");
		printf("%-20s %-16s %-14s %s\n", "NETWORK", "IP", "CONTAINER", "STATE");
		for (size_t i = 0; a && i < json_object_array_length(a); i++) {
			json_object *e = json_object_array_get_idx(a, i);
			printf("%-20s %-16s %-14.12s %s\n", js(e, "network"), js(e, "ip"), js(e, "container_id"),
			       jb(e, "attached") ? "attached" : "ORPHANED");
		}
		break;
	}
	case TR_CMD_ADM_GC:
		if (jb(o, "dry_run"))
			printf("dry run, nothing changed\n");
		print_strings(jb(o, "dry_run") ? "stale attachments" : "removed attachments", ja(o, "removed"));
		print_strings(jb(o, "dry_run") ? "orphaned leases" : "released leases", ja(o, "leases"));
		print_strings(jb(o, "dry_run") ? "DHCP keepers to restart" : "restarted DHCP keepers", ja(o, "keepers"));
		if (strcmp(js(o, "errors"), "0"))
			printf("errors: %s (see the trestled log)\n", js(o, "errors"));
		break;
	case TR_CMD_ADM_DETACH:
		printf("detached %s\n", js(o, "detached"));
		break;
	default:
		break;
	}
}

static int ctl_main(int argc, char **argv)
{
	char err[1024];
	struct tr_request req;
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			ctl_usage(stdout);
			return 0;
		}
		if (!strcmp(argv[i], "--version") || !strcmp(argv[i], "-V")) {
			printf("trestlectl %s\n", TRESTLE_VERSION);
			return 0;
		}
	}
	if (argc > 8) {
		fprintf(stderr, "trestlectl: too many arguments\n");
		return 2;
	}
	if (tr_parse_admin(argc - 1, argv + 1, &req, err, sizeof(err)) < 0) {
		fprintf(stderr, "trestlectl: %s\n\n", err);
		ctl_usage(stderr);
		return 2;
	}
	struct tr_config cfg;
	load_client_config(&cfg);
	int sock = connect_socket(cfg.socket_path, cfg.request_timeout + 60, err, sizeof(err));
	if (sock < 0 || verify_server(sock, &cfg, err, sizeof(err)) < 0) {
		fprintf(stderr, "trestlectl: %s\n", err);
		return 1;
	}
	char *payload = build_request(argc, argv, &req, "", false, false);
	int rc = tr_send_request(sock, payload, strlen(payload), -1);
	free(payload);
	int exit_code = 1;
	char *out = NULL;
	size_t outlen = 0;
	if (rc == 0)
		rc = tr_recv_response(sock, &exit_code, &out, &outlen);
	close(sock);
	if (rc < 0) {
		fprintf(stderr, "trestlectl: no valid response from trestled: %s\n", strerror(-rc));
		return 1;
	}
	json_object *o = out ? tr_json_parse_object(out, "response", err, sizeof(err)) : NULL;
	if (exit_code != 0) {
		fprintf(stderr, "trestlectl: %s\n", o ? js(o, "error") : (out ? out : "request failed"));
	} else if (req.adm_json) {
		fwrite(out, 1, outlen, stdout);
		fputc('\n', stdout);
	} else if (o) {
		ctl_print(&req, o);
	}
	if (o)
		json_object_put(o);
	free(out);
	tr_request_free(&req);
	config_free(&cfg);
	return exit_code;
}

int main(int argc, char **argv)
{
	char err[1024];
	struct tr_request req;
	bool cni = getenv("CNI_COMMAND") != NULL;

	tlog_init("trestle", TLOG_STDERR, getenv("TRESTLE_DEBUG") ? LOG_DEBUG : LOG_WARNING);

	/* one binary: "trestlectl" (symlink) is the admin tool */
	char self[PATH_MAX];
	tr_strlcpy(self, argv[0] ? argv[0] : "", sizeof(self));
	if (!strcmp(basename(self), "trestlectl"))
		return ctl_main(argc, argv);

	if (!cni && argc >= 2) {
		if (!strcmp(argv[1], "--version") || !strcmp(argv[1], "-V")) {
			printf("trestle %s\n", TRESTLE_VERSION);
			return 0;
		}
		if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
			usage(stdout);
			return 0;
		}
	}

	enum tr_mode mode = cni ? TR_MODE_CNI : TR_MODE_NETAVARK;

	/* Netavark "info" (or no args) and CNI "VERSION" are answered locally:
	 * they carry no network work and must work even while trestled is down. */
	if (!cni && (argc == 1 || !strcmp(argv[1], "info"))) {
		if (argc > 2)
			die_mode(mode, NULL, 0, "info takes no arguments");
		printf("{\"version\":\"%s\",\"api_version\":\"1.0.0\",\"description\":"
		       "\"trestle: attach rootless containers to host bridges\"}\n", TRESTLE_VERSION);
		return 0;
	}

	char *stdin_text = read_stdin(TR_MAX_PAYLOAD / 2, err, sizeof(err));
	if (!stdin_text)
		die_mode(mode, NULL, CNI_ERR_IO, err);

	int cni_code = 0;
	int rc = cni ? tr_parse_cni(env_lookup, NULL, stdin_text, &req, err, sizeof(err), &cni_code)
		     : tr_parse_netavark(argc - 1, argv + 1, stdin_text, &req, err, sizeof(err));
	if (rc < 0)
		die_mode(mode, req.cni_version, cni_code ? cni_code : CNI_ERR_INVALID_CONFIG, err);

	if (cni && req.cmd == TR_CMD_CNI_VERSION) {
		const char *v = TR_CNI_LATEST_VERSION;
		json_object *jv;
		if (req.input && json_object_object_get_ex(req.input, "cniVersion", &jv) &&
		    json_object_is_type(jv, json_type_string) &&
		    tr_cni_version_supported(json_object_get_string(jv)))
			v = json_object_get_string(jv);
		printf("{\"cniVersion\":\"%s\",\"supportedVersions\":[" TR_CNI_SUPPORTED_VERSIONS "]}\n", v);
		tr_request_free(&req);
		free(stdin_text);
		return 0;
	}

	struct tr_config cfg;
	load_client_config(&cfg);

	/* Rootless detection: we are either an unprivileged user or uid 0
	 * inside a user namespace (rootless Podman runs Netavark like that). */
	bool rootless = getuid() != 0 || tr_in_user_namespace();
	log_debug("mode=%s command=%s rootless=%d", cni ? "cni" : "netavark", req.command, rootless);

	/* Hand over the container network namespace as an fd. For a rootless
	 * container this is the only way the daemon can reach it, because the
	 * path only exists in our private mount namespace. */
	int nsfd = -1;
	bool need_ns = req.cmd == TR_CMD_NV_SETUP || req.cmd == TR_CMD_CNI_ADD || req.cmd == TR_CMD_CNI_CHECK;
	if (need_ns && req.netns_path[0]) {
		nsfd = open(req.netns_path, O_RDONLY | O_CLOEXEC);
		if (nsfd < 0) {
			if (rootless) {
				snprintf(err, sizeof(err), "cannot open network namespace %s: %s",
					 req.netns_path, strerror(errno));
				die_mode(mode, req.cni_version, CNI_ERR_IO, err);
			}
			log_debug("cannot open %s (%s); the daemon will open it", req.netns_path, strerror(errno));
		}
	}

	/* the daemon may run hook scripts and wait for a DHCP lease before it
	 * answers */
	int sock = connect_socket(cfg.socket_path,
				  cfg.request_timeout + 30 + config_max_script_time(&cfg) + config_max_dhcp_time(&cfg),
				  err, sizeof(err));
	if (sock < 0)
		die_mode(mode, req.cni_version,
			 req.cmd == TR_CMD_CNI_STATUS ? CNI_ERR_NOT_AVAILABLE : CNI_ERR_TRY_AGAIN, err);
	if (verify_server(sock, &cfg, err, sizeof(err)) < 0)
		die_mode(mode, req.cni_version, CNI_ERR_PLUGIN, err);

	char *payload = build_request(argc, argv, &req, stdin_text, rootless, nsfd >= 0);
	rc = tr_send_request(sock, payload, strlen(payload), nsfd);
	free(payload);
	if (nsfd >= 0)
		close(nsfd);
	if (rc < 0) {
		snprintf(err, sizeof(err), "failed to send request to trestled: %s", strerror(-rc));
		die_mode(mode, req.cni_version, CNI_ERR_IO, err);
	}

	int exit_code = 1;
	char *out = NULL;
	size_t outlen = 0;
	rc = tr_recv_response(sock, &exit_code, &out, &outlen);
	close(sock);
	if (rc < 0) {
		snprintf(err, sizeof(err), "no valid response from trestled: %s", strerror(-rc));
		die_mode(mode, req.cni_version, CNI_ERR_IO, err);
	}
	if (outlen) {
		fwrite(out, 1, outlen, stdout);
		if (out[outlen - 1] != '\n')
			fputc('\n', stdout);
	}
	fflush(stdout);
	free(out);
	free(stdin_text);
	tr_request_free(&req);
	config_free(&cfg);
	return exit_code;
}
