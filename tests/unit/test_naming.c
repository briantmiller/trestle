/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "harness.h"

#include "common/md5.h"
#include "common/naming.h"
#include "common/util.h"

static void test_md5_rfc1321(void)
{
	static const struct { const char *in, *out; } v[] = {
		{ "", "d41d8cd98f00b204e9800998ecf8427e" },
		{ "a", "0cc175b9c0f1b6a831c399e269772661" },
		{ "abc", "900150983cd24fb0d6963f7d28e17f72" },
		{ "message digest", "f96b697d7cb7938d525a2f31aaf161d0" },
		{ "abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b" },
		{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		  "d174ab98d277d9f5a5611c2c9f419d9f" },
		{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
		  "57edf4a22be3c955ac49da2e2107b67a" },
	};
	char hex[33];
	for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
		trestle_md5_hex(v[i].in, strlen(v[i].in), hex);
		CHECK_STR(hex, v[i].out);
	}
}

static void test_md5_incremental(void)
{
	/* feeding byte by byte must equal one-shot */
	const char *s = "The quick brown fox jumps over the lazy dog, repeatedly, across block boundaries!!";
	trestle_md5_ctx c;
	uint8_t d[16];
	char hex[33], one[33];
	trestle_md5_init(&c);
	for (size_t i = 0; s[i]; i++)
		trestle_md5_update(&c, &s[i], 1);
	trestle_md5_final(&c, d);
	for (int i = 0; i < 16; i++)
		sprintf(hex + 2 * i, "%02x", d[i]);
	trestle_md5_hex(s, strlen(s), one);
	CHECK_STR(hex, one);
}

static void test_names(void)
{
	char n[TR_IFNAMSIZ];
	tr_bridge_name("testnet", n);
	CHECK_STR(n, "tbre9016f0112cf");       /* md5("testnet")[:12] */
	CHECK(strlen(n) == 15);
	tr_veth_name("testnet", "root", "default-web", n);
	CHECK_STR(n, "trvad67e003e02f");       /* md5("testnet:root:default-web")[:12] */
	CHECK(strlen(n) == 15);

	/* different users with the same container name never collide */
	char a[TR_IFNAMSIZ], b[TR_IFNAMSIZ];
	tr_veth_name("net", "alice", "web", a);
	tr_veth_name("net", "bob", "web", b);
	CHECK(strcmp(a, b) != 0);

	char buf[256];
	tr_veth_alias("lab", "alice", "web", buf, sizeof(buf));
	CHECK_STR(buf, "trestle:alice.web.lab");
	tr_fqdn("Lab_Net", "alice", "my.web_1", buf, sizeof(buf));
	CHECK_STR(buf, "alice.my-web-1.lab-net.trestle");
}

static void test_validators(void)
{
	CHECK(tr_valid_network_name("podman-net.1"));
	CHECK(!tr_valid_network_name("-bad"));
	CHECK(!tr_valid_network_name("a/b"));
	CHECK(!tr_valid_network_name(""));
	CHECK(tr_valid_ifname("eth0"));
	CHECK(!tr_valid_ifname("0123456789abcdef"));  /* 16 chars */
	CHECK(!tr_valid_ifname("a/b"));
	CHECK(!tr_valid_ifname("a b"));
	CHECK(!tr_valid_ifname("br\"0"));
	CHECK(!tr_valid_ifname("br\\0"));
	uint8_t m[6];
	CHECK(tr_valid_mac("02:11:22:33:44:55", m) && m[5] == 0x55);
	CHECK(!tr_valid_mac("01:11:22:33:44:55", m));   /* multicast */
	CHECK(!tr_valid_mac("02:11:22:33:44", m));
	struct tr_ipv4net net;
	CHECK(tr_parse_ipv4_cidr("10.0.0.1/24", &net) && net.prefix == 24 && net.addr == 0x0a000001);
	CHECK(!tr_parse_ipv4_cidr("10.0.0.1/33", &net));
	CHECK(!tr_parse_ipv4_cidr("10.0.0.1", &net));
	CHECK(tr_prefix_mask(24) == 0xffffff00u && tr_prefix_mask(0) == 0);
}

int main(void)
{
	RUN(test_md5_rfc1321);
	RUN(test_md5_incremental);
	RUN(test_names);
	RUN(test_validators);
	TEST_MAIN_END();
}
