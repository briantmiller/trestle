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

static void test_wildcard(void)
{
	struct tr_config c;
	char err[512] = "";
	CHECK(parse(&c,
		"[network:lab]\nusers = alice\nsubnet = 10.100.0.1/24\n"
		"[network:*]\nusers = @everyone, !mallory\nsubnet_pool = 10.100.0.0/16\nsubnet_prefix = 24\n"
		"masquerade = yes\nhosts_file = yes\ndnsmasq_hosts = /etc/dnsmasq.d/trestle-%n.hosts\n"
		"setup_script = /etc/trestle/hooks/any.sh\nscript_timeout = 50\n",
		err, sizeof(err)) == 0);
	if (err[0])
		fprintf(stderr, "    err: %s\n", err);
	CHECK(c.nnets == 1);                       /* the wildcard is not a regular network */
	CHECK(c.has_wildcard && c.wildcard.has_pool && c.wildcard.subnet_prefix == 24);
	CHECK(config_find_network(&c, "*") == NULL);
	CHECK(config_find_network(&c, "lab") != NULL);
	CHECK(config_max_script_time(&c) == 50);

	struct tr_network n;
	CHECK(config_wildcard_instance(&c, "team-a", &n));
	CHECK_STR(n.name, "team-a");
	CHECK(!strncmp(n.bridge, "tbr", 3) && strlen(n.bridge) == 15);
	CHECK(n.from_wildcard && !n.is_wildcard && !n.has_subnet);
	CHECK(n.users.n == 2 && n.masquerade);    /* settings inherited */
	char path[256];
	config_expand_path(n.dnsmasq_hosts, n.name, path, sizeof(path));
	CHECK_STR(path, "/etc/dnsmasq.d/trestle-team-a.hosts");
	config_free(&c);

	/* without a catch-all there is no instance */
	CHECK(parse(&c, "[network:lab]\nusers = alice\n", err, sizeof(err)) == 0);
	CHECK(!config_wildcard_instance(&c, "x", &n));
	config_free(&c);

	/* quoted form and a pool-less catch-all are fine */
	CHECK(parse(&c, "[network \"*\"]\nusers = *\nstp = yes\n", err, sizeof(err)) == 0);
	CHECK(c.has_wildcard && c.wildcard.stp && !c.wildcard.has_pool);
	config_free(&c);

	struct { const char *text, *expect; } bad[] = {
		{ "[network:*]\nusers=*\nbridge = br0\n", "'bridge' is not allowed" },
		{ "[network:*]\nusers=*\nuplink = eth1\n", "'uplink' is not allowed" },
		{ "[network:*]\nusers=*\nsubnet = 10.0.0.1/24\n", "use subnet_pool" },
		{ "[network:lab]\nsubnet_pool = 10.0.0.0/16\n", "only valid in [network:*]" },
		{ "[network:lab]\nsubnet_prefix = 24\n", "only valid in [network:*]" },
		{ "[network:*]\nsubnet_pool = 10.0.0.1/16\n", "network address" },
		{ "[network:*]\nusers=*\nsubnet_pool = 10.0.0.0/24\nsubnet_prefix = 16\n", "larger than" },
		{ "[network:*]\nusers=*\nsubnet_pool = 10.0.0.0/16\ndnsmasq_hosts = /tmp/x.hosts\n", "%n" },
		{ "[network:*]\nusers=*\nmasquerade = yes\n", "requires subnet" },
	};
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		err[0] = 0;
		CHECK(parse(&c, bad[i].text, err, sizeof(err)) < 0);
		CHECK_CONTAINS(err, bad[i].expect);
		config_free(&c);
	}
}

int main(void)
{
	tlog_init("test", TLOG_STDERR, LOG_ERR);
	RUN(test_defaults);
	RUN(test_full);
	RUN(test_errors);
	RUN(test_confd_override);
	RUN(test_wildcard);
	TEST_MAIN_END();
}
