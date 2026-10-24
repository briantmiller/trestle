/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "harness.h"

#include "common/request.h"

struct env { const char *k[12], *v[12]; };

static const char *lookup(void *ctx, const char *name)
{
	struct env *e = ctx;
	for (int i = 0; i < 12 && e->k[i]; i++)
		if (!strcmp(e->k[i], name))
			return e->v[i];
	return NULL;
}

#define ENV_ADD(cmd) { .k = { "CNI_COMMAND", "CNI_CONTAINERID", "CNI_NETNS", "CNI_IFNAME", "CNI_PATH", "CNI_ARGS" }, \
		       .v = { cmd, "abcdef0123456789", "/var/run/netns/x", "eth0", "/opt/cni/bin", \
			      "IgnoreUnknown=1;K8S_POD_NAMESPACE=prod;K8S_POD_NAME=db-0;IP=10.0.0.9" } }

static const char *CONF = "{\"cniVersion\":\"1.0.0\",\"name\":\"lab\",\"type\":\"trestle\"}";

static void test_cni_add(void)
{
	struct env e = ENV_ADD("ADD");
	struct tr_request r;
	char err[256];
	int code;
	CHECK(tr_parse_cni(lookup, &e, CONF, &r, err, sizeof(err), &code) == 0);
	CHECK(r.cmd == TR_CMD_CNI_ADD);
	CHECK_STR(r.network, "lab");
	CHECK_STR(r.container_name, "prod-db-0");
	CHECK_STR(r.ifname, "eth0");
	CHECK_STR(r.netns_path, "/var/run/netns/x");
	CHECK(r.static_ips.n == 1 && !strcmp(r.static_ips.v[0], "10.0.0.9"));
	tr_request_free(&r);
}

static void test_cni_runtimeconfig(void)
{
	struct env e = ENV_ADD("ADD");
	e.v[5] = "";
	struct tr_request r;
	char err[256];
	int code;
	const char *conf = "{\"cniVersion\":\"0.4.0\",\"name\":\"lab\",\"type\":\"trestle\","
			   "\"runtimeConfig\":{\"ips\":[\"10.0.0.7/24\"],\"mac\":\"02:00:00:00:00:07\"}}";
	CHECK(tr_parse_cni(lookup, &e, conf, &r, err, sizeof(err), &code) == 0);
	CHECK(r.static_ips.n == 1 && !strcmp(r.static_ips.v[0], "10.0.0.7"));
	CHECK_STR(r.static_mac, "02:00:00:00:00:07");
	CHECK_STR(r.container_name, "abcdef012345");   /* no pod name: short container id */
	tr_request_free(&r);
}

static void expect_cni_fail(struct env *e, const char *stdin_text, int want_code, const char *want_msg)
{
	struct tr_request r;
	char err[256] = "";
	int code = 0;
	CHECK(tr_parse_cni(lookup, e, stdin_text, &r, err, sizeof(err), &code) < 0);
	CHECK(code == want_code);
	CHECK_CONTAINS(err, want_msg);
	tr_request_free(&r);
}

static void test_cni_errors(void)
{
	struct env e = ENV_ADD("ADD");
	expect_cni_fail(&e, "{\"cniVersion\":\"1.0.0\",", CNI_ERR_DECODE, "not valid JSON");
	expect_cni_fail(&e, "{\"cniVersion\":\"1.0.0\",\"name\":\"lab\",\"type\":\"t\"} trailing", CNI_ERR_DECODE, "trailing");
	expect_cni_fail(&e, "[1,2]", CNI_ERR_DECODE, "must be an object");
	expect_cni_fail(&e, "{\"cniVersion\":\"9.9.9\",\"name\":\"lab\",\"type\":\"t\"}", CNI_ERR_INCOMPATIBLE_VERSION, "unsupported cniVersion");
	expect_cni_fail(&e, "{\"cniVersion\":\"1.0.0\",\"name\":\"../x\",\"type\":\"t\"}", CNI_ERR_INVALID_CONFIG, "name");
	expect_cni_fail(&e, "{\"cniVersion\":\"1.0.0\",\"name\":\"lab\"}", CNI_ERR_INVALID_CONFIG, "type");

	struct env bad = ENV_ADD("ADD");
	bad.v[3] = "this-name-is-too-long";
	expect_cni_fail(&bad, CONF, CNI_ERR_INVALID_ENV, "CNI_IFNAME");
	bad = (struct env)ENV_ADD("ADD");
	bad.v[2] = "relative/path";
	expect_cni_fail(&bad, CONF, CNI_ERR_INVALID_ENV, "absolute");
	bad = (struct env)ENV_ADD("FROB");
	expect_cni_fail(&bad, CONF, CNI_ERR_INVALID_ENV, "unsupported CNI_COMMAND");
	bad = (struct env)ENV_ADD("ADD");
	bad.v[1] = "bad id!";
	expect_cni_fail(&bad, CONF, CNI_ERR_INVALID_ENV, "CNI_CONTAINERID");
	bad = (struct env)ENV_ADD("ADD");
	bad.v[5] = "IP=10.0.0.300";
	expect_cni_fail(&bad, CONF, CNI_ERR_INVALID_CONFIG, "not a valid IPv4");
	bad = (struct env)ENV_ADD("CHECK");
	expect_cni_fail(&bad, "{\"cniVersion\":\"0.3.1\",\"name\":\"lab\",\"type\":\"t\"}", CNI_ERR_INCOMPATIBLE_VERSION, "CHECK");
	struct env none = { { 0 }, { 0 } };
	expect_cni_fail(&none, CONF, CNI_ERR_INVALID_ENV, "CNI_COMMAND");
}

static void test_cni_del_without_netns(void)
{
	struct env e = { .k = { "CNI_COMMAND", "CNI_CONTAINERID", "CNI_IFNAME" }, .v = { "DEL", "abc", "eth0" } };
	struct tr_request r;
	char err[256];
	int code;
	CHECK(tr_parse_cni(lookup, &e, CONF, &r, err, sizeof(err), &code) == 0);
	CHECK(r.cmd == TR_CMD_CNI_DEL && r.netns_path[0] == '\0');
	tr_request_free(&r);
}

static const char *SETUP =
	"{\"container_id\":\"752947ff91f9\",\"container_name\":\"testctr\",\"port_mappings\":[],"
	"\"network\":{\"name\":\"lab\",\"driver\":\"trestle\",\"id\":\"x\",\"subnets\":[]},"
	"\"network_options\":{\"aliases\":[\"web\",\"bad alias\"],\"interface_name\":\"eth0\","
	"\"static_ips\":[\"10.0.0.50\",\"fd00::5\"],\"static_mac\":\"aa:bb:cc:dd:aa:00\"}}";

static void test_netavark(void)
{
	struct tr_request r;
	char err[256];
	char *setup[] = { "setup", "/run/user/1000/netns/netns-1" };
	CHECK(tr_parse_netavark(2, setup, SETUP, &r, err, sizeof(err)) == 0);
	CHECK(r.cmd == TR_CMD_NV_SETUP);
	CHECK_STR(r.container_name, "testctr");
	CHECK_STR(r.network, "lab");
	CHECK_STR(r.netns_path, "/run/user/1000/netns/netns-1");
	CHECK(r.static_ips.n == 1);                 /* IPv6 ignored */
	CHECK(r.aliases.n == 1);                    /* invalid alias dropped */
	CHECK_STR(r.static_mac, "aa:bb:cc:dd:aa:00");
	tr_request_free(&r);

	char *create[] = { "create" };
	CHECK(tr_parse_netavark(1, create, "{\"name\":\"lab\",\"id\":\"1\",\"driver\":\"trestle\"}", &r, err, sizeof(err)) == 0);
	CHECK(r.cmd == TR_CMD_NV_CREATE);
	tr_request_free(&r);

	char *nons[] = { "setup" };
	CHECK(tr_parse_netavark(1, nons, SETUP, &r, err, sizeof(err)) < 0);
	CHECK_CONTAINS(err, "netns path argument is missing");
	tr_request_free(&r);

	char *rel[] = { "teardown", "netns" };
	CHECK(tr_parse_netavark(2, rel, SETUP, &r, err, sizeof(err)) < 0);
	tr_request_free(&r);

	char *unk[] = { "explode" };
	CHECK(tr_parse_netavark(1, unk, "{}", &r, err, sizeof(err)) < 0);
	CHECK_CONTAINS(err, "unknown subcommand");
	tr_request_free(&r);

	CHECK(tr_parse_netavark(2, setup, "{\"container_id\":\"x\"}", &r, err, sizeof(err)) < 0);
	tr_request_free(&r);
	CHECK(tr_parse_netavark(2, setup, "not json", &r, err, sizeof(err)) < 0);
	tr_request_free(&r);
}

/* hostile input found by the security review */
static void test_hostile(void)
{
	char err[256];
	struct tr_request r;
	uint8_t m[6];

	/* container ids are file names in the state directory */
	CHECK(!tr_valid_container_id("."));
	CHECK(!tr_valid_container_id(".."));
	CHECK(!tr_valid_container_id(".hidden"));
	CHECK(!tr_valid_container_id("-rf"));
	CHECK(!tr_valid_container_id("a/b"));
	CHECK(tr_valid_container_id("abc.def-1_2"));

	/* MAC: only plain hex digits */
	CHECK(!tr_valid_mac("+2:+0:+0:+0:+0:+1", m));
	CHECK(!tr_valid_mac(" 2: 0: 0: 0: 0: 1", m));
	CHECK(!tr_valid_mac("02-00-00-00-00-01", m));
	CHECK(!tr_valid_mac("0x:00:00:00:00:01", m));
	CHECK(tr_valid_mac("0A:bC:00:00:00:fF", m) && m[0] == 0x0a && m[1] == 0xbc && m[5] == 0xff);

	/* \u0000 would truncate C strings (values and keys) */
	CHECK(tr_json_has_nul_escape("{\"a\":\"x\\u0000y\"}"));
	CHECK(tr_json_has_nul_escape("{\"a\\u0000b\":1}"));
	CHECK(!tr_json_has_nul_escape("{\"a\":\"x\\\\u0000y\"}"));   /* escaped backslash, then text */
	CHECK(!tr_json_has_nul_escape("{\"a\":\"\\u0001\"}"));
	CHECK(tr_json_parse_object("{\"a\":\"\\u0000\"}", "x", err, sizeof(err)) == NULL);
	CHECK_CONTAINS(err, "NUL");
	CHECK(tr_json_parse_object("{} {}", "x", err, sizeof(err)) == NULL);
	CHECK(tr_json_parse_object("[]", "x", err, sizeof(err)) == NULL);

	char *setup[] = { "setup", "/run/x" };
	const char *nul_name = "{\"container_id\":\"abc\",\"container_name\":\"web\\u0000evil\","
			       "\"network\":{\"name\":\"lab\"},\"network_options\":{\"interface_name\":\"eth0\"}}";
	CHECK(tr_parse_netavark(2, setup, nul_name, &r, err, sizeof(err)) < 0);
	tr_request_free(&r);
	const char *dot_id = "{\"container_id\":\"..\",\"container_name\":\"web\","
			     "\"network\":{\"name\":\"lab\"},\"network_options\":{\"interface_name\":\"eth0\"}}";
	CHECK(tr_parse_netavark(2, setup, dot_id, &r, err, sizeof(err)) < 0);
	tr_request_free(&r);
	char *nl_path[] = { "setup", "/run/x\n$(id)" };
	CHECK(tr_parse_netavark(2, nl_path, SETUP, &r, err, sizeof(err)) < 0);
	tr_request_free(&r);

	/* control characters in the CNI environment */
	struct env e = ENV_ADD("ADD");
	e.v[5] = "K8S_POD_NAME=a\nb";
	expect_cni_fail(&e, CONF, CNI_ERR_INVALID_ENV, "control characters");
	struct env e2 = ENV_ADD("ADD");
	e2.v[2] = "/var/run/netns/x\n";
	expect_cni_fail(&e2, CONF, CNI_ERR_INVALID_ENV, "control characters");
	struct env e4 = ENV_ADD("ADD");
	e4.v[5] = "IP=10.0.0.9;$(id)";
	expect_cni_fail(&e4, CONF, CNI_ERR_INVALID_ENV, "malformed");
	struct env e5 = ENV_ADD("ADD");
	e5.v[5] = "=x";
	expect_cni_fail(&e5, CONF, CNI_ERR_INVALID_ENV, "malformed");
	static char longpod[200];
	memset(longpod, 'a', sizeof(longpod) - 1);
	memcpy(longpod, "K8S_POD_NAME=", 13);
	struct env e6 = ENV_ADD("ADD");
	e6.v[5] = longpod;                       /* not truncated into a valid name */
	expect_cni_fail(&e6, CONF, CNI_ERR_INVALID_ENV, "too long");
	struct env e3 = ENV_ADD("ADD");
	e3.v[1] = "..";
	expect_cni_fail(&e3, CONF, CNI_ERR_INVALID_ENV, "CNI_CONTAINERID");
}

static void test_error_format(void)
{
	char *s = tr_format_cni_error("0.4.0", 7, "bad \"thing\"", NULL);
	CHECK_STR(s, "{\"cniVersion\":\"0.4.0\",\"code\":7,\"msg\":\"bad \\\"thing\\\"\"}");
	free(s);
	s = tr_format_netavark_error("nope");
	CHECK_STR(s, "{\"error\":\"nope\"}");
	free(s);
}

int main(void)
{
	RUN(test_cni_add);
	RUN(test_cni_runtimeconfig);
	RUN(test_cni_errors);
	RUN(test_cni_del_without_netns);
	RUN(test_netavark);
	RUN(test_hostile);
	RUN(test_error_format);
	TEST_MAIN_END();
}
