/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "harness.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "common/config.h"
#include "common/log.h"
#include "server/hooks.h"

static struct tr_config cfg;

static const struct tr_network *net(void)
{
	char err[256];
	config_defaults(&cfg);
	if (config_parse_text(&cfg,
			      "[network:lab]\nusers=*\nsubnet=10.1.2.1/24\nmtu=1450\n"
			      "setup_script=/x/setup.sh\nscript_timeout=7\nscript_on_error=fail\n",
			      "t", err, sizeof(err)) || config_finalize(&cfg, err, sizeof(err))) {
		fprintf(stderr, "config: %s\n", err);
		exit(2);
	}
	return &cfg.nets[0];
}

static const char *env_get(const struct strv *env, const char *key)
{
	size_t kl = strlen(key);
	for (size_t i = 0; i < env->n; i++)
		if (!strncmp(env->v[i], key, kl) && env->v[i][kl] == '=')
			return env->v[i] + kl + 1;
	return NULL;
}

static struct hook_info sample(const struct tr_network *n, struct strv *aliases)
{
	struct hook_info hi = {
		.event = "setup", .mode = "netavark", .command = "setup", .net = n,
		.user = "alice", .uid = 1000, .gid = 1000, .rootless = true,
		.container_id = "abc123", .container_name = "web", .aliases = aliases,
		.host_ifname = "trv0123456789ab", .container_ifname = "eth0",
		.host_mac = "02:00:00:00:00:01", .container_mac = "02:00:00:00:00:02",
		.has_ip = true, .ip = 0x0a010205, .prefix = 24,
		.netns_path = "/run/user/1000/netns/x", .netns_fd = -1,
	};
	return hi;
}

static void test_config(void)
{
	const struct tr_network *n = net();
	CHECK_STR(n->setup_script, "/x/setup.sh");
	CHECK(n->create_script[0] == '\0');
	CHECK(n->script_timeout == 7);
	CHECK(n->script_fail);
	config_free(&cfg);

	struct tr_config c;
	char err[256] = "";
	config_defaults(&c);
	CHECK(config_parse_text(&c, "[network:a]\nsetup_script=relative.sh\n", "t", err, sizeof(err)) < 0);
	CHECK_CONTAINS(err, "absolute");
	config_free(&c);
	config_defaults(&c);
	CHECK(config_parse_text(&c, "[network:a]\nscript_on_error=maybe\n", "t", err, sizeof(err)) < 0);
	config_free(&c);
	config_defaults(&c);
	CHECK(config_parse_text(&c, "[network:a]\nscript_timeout=0\n", "t", err, sizeof(err)) < 0);
	config_free(&c);
	config_defaults(&c);
	CHECK(config_parse_text(&c, "[network:a]\nusers=*\n", "t", err, sizeof(err)) == 0);
	CHECK(c.nets[0].script_timeout == 30 && !c.nets[0].script_fail);   /* defaults */
	CHECK(config_max_script_time(&c) == 0);
	config_free(&c);
	config_defaults(&c);
	CHECK(config_parse_text(&c, "[network:a]\nusers=*\ncreate_script=/a\nsetup_script=/b\nscript_timeout=20\n",
				"t", err, sizeof(err)) == 0);
	CHECK(config_max_script_time(&c) == 40);
	config_free(&c);
}

static void test_env(void)
{
	const struct tr_network *n = net();
	struct strv al = { 0 }, env = { 0 };
	strv_push(&al, "www");
	strv_push(&al, "api");
	struct hook_info hi = sample(n, &al);
	hook_build_env(&hi, &env);
	CHECK_STR(env_get(&env, "TRESTLE_EVENT"), "setup");
	CHECK_STR(env_get(&env, "TRESTLE_MODE"), "netavark");
	CHECK_STR(env_get(&env, "TRESTLE_NETWORK"), "lab");
	CHECK(!strncmp(env_get(&env, "TRESTLE_BRIDGE"), "tbr", 3));
	CHECK_STR(env_get(&env, "TRESTLE_BRIDGE_CREATED"), "0");
	CHECK_STR(env_get(&env, "TRESTLE_SUBNET"), "10.1.2.0/24");
	CHECK_STR(env_get(&env, "TRESTLE_GATEWAY"), "10.1.2.1");
	CHECK_STR(env_get(&env, "TRESTLE_BRIDGE_IP_CIDR"), "10.1.2.1/24");
	CHECK_STR(env_get(&env, "TRESTLE_MTU"), "1450");
	CHECK_STR(env_get(&env, "TRESTLE_USER"), "alice");
	CHECK_STR(env_get(&env, "TRESTLE_UID"), "1000");
	CHECK_STR(env_get(&env, "TRESTLE_ROOTLESS"), "1");
	CHECK_STR(env_get(&env, "TRESTLE_CONTAINER_ID"), "abc123");
	CHECK_STR(env_get(&env, "TRESTLE_CONTAINER_NAME"), "web");
	CHECK_STR(env_get(&env, "TRESTLE_CONTAINER_ALIASES"), "www,api");
	CHECK_STR(env_get(&env, "TRESTLE_FQDN"), "alice.web.lab.trestle");
	CHECK_STR(env_get(&env, "TRESTLE_HOST_IFNAME"), "trv0123456789ab");
	CHECK_STR(env_get(&env, "TRESTLE_CONTAINER_IFNAME"), "eth0");
	CHECK_STR(env_get(&env, "TRESTLE_HOST_MAC"), "02:00:00:00:00:01");
	CHECK_STR(env_get(&env, "TRESTLE_CONTAINER_MAC"), "02:00:00:00:00:02");
	CHECK_STR(env_get(&env, "TRESTLE_IP"), "10.1.2.5");
	CHECK_STR(env_get(&env, "TRESTLE_IP_CIDR"), "10.1.2.5/24");
	CHECK_STR(env_get(&env, "TRESTLE_NETNS"), "/run/user/1000/netns/x");
	CHECK(env_get(&env, "TRESTLE_NETNS_FD") == NULL);
	CHECK(env_get(&env, "TRESTLE_K8S_POD_NAME") == NULL);
	CHECK(env_get(&env, "HOME") == NULL);   /* clean environment */
	CHECK(env_get(&env, "PATH") != NULL);
	strv_clear(&env);

	/* network-level event without container information */
	struct hook_info c = { .event = "create", .net = n, .user = "alice", .netns_fd = -1,
			       .bridge_created = true };
	hook_build_env(&c, &env);
	CHECK_STR(env_get(&env, "TRESTLE_BRIDGE_CREATED"), "1");
	CHECK(env_get(&env, "TRESTLE_PODMAN_NETWORK_ID") == NULL);
	CHECK(env_get(&env, "TRESTLE_CONTAINER_ID") == NULL);
	CHECK(env_get(&env, "TRESTLE_IP") == NULL);
	CHECK(env_get(&env, "TRESTLE_FQDN") == NULL);
	strv_clear(&env);
	strv_clear(&al);
	config_free(&cfg);
}

static void write_script(const char *path, const char *body, mode_t mode)
{
	FILE *f = fopen(path, "w");
	fprintf(f, "#!/bin/sh\n%s\n", body);
	fclose(f);
	chmod(path, mode);
}

static void test_run(void)
{
	const struct tr_network *n = net();
	char *dir = t_tmpdir(), script[512], out[512], err[512];
	struct hook_info hi = sample(n, NULL);
	snprintf(out, sizeof(out), "%s/env.out", dir);

	/* environment and argument reach the script */
	snprintf(script, sizeof(script), "%s/ok.sh", dir);
	char body[1024];
	snprintf(body, sizeof(body), "env | sort > %s\necho \"arg=$1\" >> %s\necho hello from hook", out, out);
	write_script(script, body, 0755);
	CHECK(hook_run(script, &hi, 5, err, sizeof(err)) == 0);
	char *text = tr_read_file(out, 65536, NULL);
	CHECK_CONTAINS(text, "TRESTLE_IP=10.1.2.5\n");
	CHECK_CONTAINS(text, "TRESTLE_CONTAINER_NAME=web\n");
	CHECK_CONTAINS(text, "arg=setup\n");
	CHECK(text && !strstr(text, "HOME="));
	free(text);

	/* non-zero exit is reported */
	snprintf(script, sizeof(script), "%s/bad.sh", dir);
	write_script(script, "echo failing >&2; exit 3", 0755);
	CHECK(hook_run(script, &hi, 5, err, sizeof(err)) < 0);
	CHECK_CONTAINS(err, "exited with status 3");

	/* timeout kills the script and its children */
	snprintf(script, sizeof(script), "%s/slow.sh", dir);
	write_script(script, "sleep 30 & sleep 30", 0755);
	time_t t0 = time(NULL);
	CHECK(hook_run(script, &hi, 1, err, sizeof(err)) < 0);
	CHECK_CONTAINS(err, "timed out");
	CHECK(time(NULL) - t0 <= 3);

	/* a background child that keeps stdout open does not block a script
	 * that exited successfully beyond the timeout */
	snprintf(script, sizeof(script), "%s/bg.sh", dir);
	write_script(script, "sleep 3 & exit 0", 0755);
	t0 = time(NULL);
	int r = hook_run(script, &hi, 10, err, sizeof(err));
	CHECK(r == 0);
	CHECK(time(NULL) - t0 <= 5);

	/* netns fd is handed over as fd 3 */
	int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	hi.netns_fd = fd;
	snprintf(script, sizeof(script), "%s/fd.sh", dir);
	snprintf(body, sizeof(body), "readlink /proc/self/fd/$TRESTLE_NETNS_FD > %s", out);
	write_script(script, body, 0755);
	CHECK(hook_run(script, &hi, 5, err, sizeof(err)) == 0);
	text = tr_read_file(out, 4096, NULL);
	CHECK_CONTAINS(text, "/dev/null");
	free(text);
	close(fd);
	hi.netns_fd = -1;

	/* insecure scripts are refused */
	snprintf(script, sizeof(script), "%s/ww.sh", dir);
	write_script(script, "exit 0", 0777);
	chmod(script, 0777);
	CHECK(hook_run(script, &hi, 5, err, sizeof(err)) < 0);
	CHECK_CONTAINS(err, "not writable by group/others");
	snprintf(script, sizeof(script), "%s/noexec.sh", dir);
	write_script(script, "exit 0", 0644);
	CHECK(hook_check_script(script, err, sizeof(err)) < 0);
	CHECK(hook_check_script("relative.sh", err, sizeof(err)) < 0);
	CHECK(hook_check_script("/nonexistent/x.sh", err, sizeof(err)) < 0);
	chmod(dir, 0777);
	snprintf(script, sizeof(script), "%s/ok.sh", dir);
	CHECK(hook_check_script(script, err, sizeof(err)) < 0);
	CHECK_CONTAINS(err, "directory");
	chmod(dir, 0700);

	t_rmrf(dir);
	config_free(&cfg);
}

int main(void)
{
	tlog_init("test", TLOG_STDERR, LOG_ERR);
	RUN(test_config);
	RUN(test_env);
	RUN(test_run);
	TEST_MAIN_END();
}
