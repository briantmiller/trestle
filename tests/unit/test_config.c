/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "harness.h"

#include <sys/stat.h>

#include "common/config.h"
#include "common/log.h"

static int parse(struct tr_config *c, const char *text, char *err, size_t errlen)
{
	config_defaults(c);
	if (config_parse_text(c, text, "test.conf", err, errlen) < 0)
		return -1;
	return config_finalize(c, err, errlen);
}

static void test_defaults(void)
{
	struct tr_config c;
	config_defaults(&c);
	CHECK_STR(c.socket_path, "/tmp/trestle.sock");
	CHECK_STR(c.socket_owner, "root");
	CHECK_STR(c.socket_group, "root");
	CHECK(c.socket_mode == 0777);
	CHECK(c.verify_server == TR_VERIFY_RELAXED);
	config_free(&c);
}

static void test_full(void)
{
	struct tr_config c;
	char err[512] = "";
	const char *text =
		"# comment\n"
		"[global]\n"
		"socket = /tmp/x.sock\n"
		"socket_owner = root\n"
		"socket_group = wheel\n"
		"socket_mode = 0770\n"
		"log_level = debug\n"
		"\n"
		"[network:lab]\n"
		"users = alice, @devs, !mallory\n"
		"subnet = 10.0.0.1/24\n"
		"mtu = 9000\n"
		"hosts_file = yes\n"
		"firewall = yes\n"
		"masquerade = true\n"
		"allow_inbound = tcp:80, udp:5000-5010, icmp\n"
		"nft_rule = ip daddr 169.254.169.254 drop\n"
		"nft_rule = \"tcp dport 25 drop\"\n"
		"\n"
		"[network \"uplinked\"]\n"
		"bridge = br0\n"
		"users = *\n";
	CHECK(parse(&c, text, err, sizeof(err)) == 0);
	if (err[0])
		fprintf(stderr, "    err: %s\n", err);
	CHECK_STR(c.socket_path, "/tmp/x.sock");
	CHECK_STR(c.socket_group, "wheel");
	CHECK(c.socket_mode == 0770);
	CHECK(c.log_level == LOG_DEBUG);
	CHECK(c.nnets == 2);
	const struct tr_network *n = config_find_network(&c, "lab");
	CHECK(n != NULL);
	if (n) {
		CHECK(n->users.n == 3);
		CHECK_STR(n->users.v[2], "!mallory");
		CHECK(n->has_subnet && n->prefix == 24);
		CHECK(n->gateway == 0x0a000001 && n->netaddr == 0x0a000000 && n->broadcast == 0x0a0000ff);
		CHECK(n->mtu == 9000 && n->hosts_file && n->firewall && n->masquerade);
		CHECK(!strncmp(n->bridge, "tbr", 3) && strlen(n->bridge) == 15 && !n->bridge_configured);
	}
	n = config_find_network(&c, "uplinked");
	CHECK(n && n->bridge_configured);
	CHECK(n && !strcmp(n->bridge, "br0"));
	n = config_find_network(&c, "lab");
	CHECK(n && n->nft_rules.n == 2);
	CHECK(n && !strcmp(n->nft_rules.v[1], "tcp dport 25 drop"));
	config_free(&c);
}

static void test_errors(void)
{
	struct { const char *text, *expect; } cases[] = {
		{ "[global]\nbogus = 1\n", "unknown key 'bogus'" },
		{ "[weird]\n", "unknown section" },
		{ "key = value\n", "outside of a section" },
		{ "[network:a]\nsubnet = 10.0.0.0/24\n", "host address" },
		{ "[network:a]\nsubnet = 10.0.0.255/24\n", "host address" },
		{ "[network:a]\nsubnet = 10.0.0.1/31\n", "8-30" },
		{ "[network:a]\nmtu = 20\n", "mtu" },
		{ "[network:a]\nstp = maybe\n", "yes/no" },
		{ "[network:a]\nusers=x\nsubnet=10.0.0.1/24\n[network:b]\nusers=x\nsubnet=10.0.0.9/16\n", "overlapping" },
		{ "[network:a]\nusers=x\nbridge=br0\n[network:b]\nusers=x\nbridge=br0\n", "same bridge" },
		{ "[network:a]\nusers=x\naardvark_dns=yes\n", "requires subnet" },
		{ "[network:a]\nusers=x\nsubnet=10.0.0.1/24\nallow_inbound=ftp:21\n", "allow_inbound" },
		{ "[network:a]\nnft_rule = accept; drop\n", "single rule" },
		{ "[global]\nsocket_mode = 999\n", "octal" },
		{ "[network:-x]\n", "invalid network name" },
		{ "[global]\nsocket = relative\n", "absolute" },
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		struct tr_config c;
		char err[512] = "";
		CHECK(parse(&c, cases[i].text, err, sizeof(err)) < 0);
		CHECK_CONTAINS(err, cases[i].expect);
		config_free(&c);
	}
}

static void test_confd_override(void)
{
	char *dir = t_tmpdir(), path[512], d[512];
	snprintf(path, sizeof(path), "%s/trestle.conf", dir);
	snprintf(d, sizeof(d), "%s/conf.d", dir);
	mkdir(d, 0755);
	FILE *f = fopen(path, "w");
	fputs("[network:lab]\nusers = alice\nsubnet = 10.1.0.1/24\nnft_rule = drop\n", f);
	fclose(f);
	snprintf(path, sizeof(path), "%s/conf.d/20-b.conf", dir);
	f = fopen(path, "w");
	fputs("[network:lab]\nusers = bob\nnft_rule = accept\n", f);
	fclose(f);
	snprintf(path, sizeof(path), "%s/conf.d/10-a.conf", dir);
	f = fopen(path, "w");
	fputs("[network:lab]\nmtu = 1400\n[network:other]\nusers=*\n", f);
	fclose(f);
	snprintf(path, sizeof(path), "%s/conf.d/ignored.txt", dir);
	f = fopen(path, "w");
	fputs("garbage\n", f);
	fclose(f);

	struct tr_config c;
	char err[512] = "";
	config_defaults(&c);
	snprintf(path, sizeof(path), "%s/trestle.conf", dir);
	CHECK(config_load(&c, path, err, sizeof(err)) == 0);
	const struct tr_network *n = config_find_network(&c, "lab");
	CHECK(n && n->users.n == 1 && !strcmp(n->users.v[0], "bob"));   /* later file wins */
	CHECK(n && n->mtu == 1400);
	CHECK(n && n->nft_rules.n == 2);                                  /* accumulates */
	CHECK(config_find_network(&c, "other") != NULL);
	config_free(&c);
	t_rmrf(dir);
}

int main(void)
{
	tlog_init("test", TLOG_STDERR, LOG_ERR);
	RUN(test_defaults);
	RUN(test_full);
	RUN(test_errors);
	RUN(test_confd_override);
	TEST_MAIN_END();
}
