/* SPDX-License-Identifier: GPL-3.0-or-later */
/* IPAM, attachment records, hosts-file block handling, nftables generation,
 * bridge ownership detection and the wire protocol. */
#include "harness.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/config.h"
#include "common/log.h"
#include "common/proto.h"
#include "server/bridge.h"
#include "server/checks.h"
#include "server/dnsout.h"
#include "server/nft.h"
#include "server/state.h"

static struct tr_network mknet(const char *name, const char *subnet)
{
	struct tr_config c;
	char err[256], text[256];
	config_defaults(&c);
	snprintf(text, sizeof(text), "[network:%s]\nusers=*\nsubnet=%s\n", name, subnet);
	if (config_parse_text(&c, text, "t", err, sizeof(err)) || config_finalize(&c, err, sizeof(err))) {
		fprintf(stderr, "mknet: %s\n", err);
		exit(2);
	}
	struct tr_network n = c.nets[0];
	memset(&n.users, 0, sizeof(n.users));
	config_free(&c);
	return n;
}

static void test_ipam(void)
{
	char *dir = t_tmpdir();
	struct tr_network n = mknet("lab", "10.0.0.1/29");  /* hosts .1-.6, gw .1 */
	uint32_t ip;
	char err[256], s[16];
	struct strv none = { 0 };

	CHECK(ipam_allocate(dir, &n, "c1", &none, &ip, err, sizeof(err)) == 0);
	tr_fmt_ipv4(ip, s);
	CHECK_STR(s, "10.0.0.2");
	CHECK(ipam_allocate(dir, &n, "c2", &none, &ip, err, sizeof(err)) == 0);
	tr_fmt_ipv4(ip, s);
	CHECK_STR(s, "10.0.0.3");
	/* same container again gets the same lease */
	CHECK(ipam_allocate(dir, &n, "c1", &none, &ip, err, sizeof(err)) == 0);
	tr_fmt_ipv4(ip, s);
	CHECK_STR(s, "10.0.0.2");

	struct strv req = { 0 };
	strv_push(&req, "10.0.0.6");
	CHECK(ipam_allocate(dir, &n, "c3", &req, &ip, err, sizeof(err)) == 0);
	tr_fmt_ipv4(ip, s);
	CHECK_STR(s, "10.0.0.6");
	CHECK(ipam_allocate(dir, &n, "c4", &req, &ip, err, sizeof(err)) < 0);
	CHECK_CONTAINS(err, "already in use");
	strv_clear(&req);
	strv_push(&req, "10.0.0.1");
	CHECK(ipam_allocate(dir, &n, "c4", &req, &ip, err, sizeof(err)) < 0);
	CHECK_CONTAINS(err, "reserved");
	strv_clear(&req);
	strv_push(&req, "10.9.0.5");
	CHECK(ipam_allocate(dir, &n, "c4", &req, &ip, err, sizeof(err)) < 0);
	CHECK_CONTAINS(err, "not inside");
	strv_clear(&req);

	/* fill the pool: .4 .5 left */
	CHECK(ipam_allocate(dir, &n, "c5", &none, &ip, err, sizeof(err)) == 0);
	CHECK(ipam_allocate(dir, &n, "c6", &none, &ip, err, sizeof(err)) == 0);
	CHECK(ipam_allocate(dir, &n, "c7", &none, &ip, err, sizeof(err)) < 0);
	CHECK_CONTAINS(err, "no free addresses");

	CHECK(ipam_lookup(dir, "lab", "c2", &ip) == 0);
	tr_fmt_ipv4(ip, s);
	CHECK_STR(s, "10.0.0.3");
	CHECK(ipam_release(dir, "lab", "c2") == 0);
	CHECK(ipam_lookup(dir, "lab", "c2", &ip) == -ENOENT);
	CHECK(ipam_release(dir, "lab", "c2") == 0);   /* idempotent */
	CHECK(ipam_allocate(dir, &n, "c7", &none, &ip, err, sizeof(err)) == 0);
	tr_fmt_ipv4(ip, s);
	CHECK_STR(s, "10.0.0.3");
	t_rmrf(dir);
}

static void test_records(void)
{
	char *dir = t_tmpdir();
	struct tr_attachment a = { 0 }, b;
	strcpy(a.network, "lab");
	strcpy(a.container_id, "abc");
	strcpy(a.container_name, "web");
	strcpy(a.user, "alice");
	a.uid = 1000;
	strcpy(a.mode, "netavark");
	strcpy(a.ifname, "eth0");
	strcpy(a.veth, "trv0123456789ab");
	strcpy(a.mac, "02:00:00:00:00:01");
	a.has_ip = true;
	a.ip = 0x0a000005;
	a.prefix = 24;
	strv_push(&a.aliases, "www");
	CHECK(state_save(dir, &a) == 0);
	CHECK(state_load(dir, "lab", "abc", &b) == 0);
	CHECK_STR(b.container_name, "web");
	CHECK_STR(b.veth, "trv0123456789ab");
	CHECK(b.uid == 1000 && b.has_ip && b.ip == 0x0a000005 && b.prefix == 24);
	CHECK(b.aliases.n == 1 && !strcmp(b.aliases.v[0], "www"));
	attachment_free(&b);
	CHECK(state_load(dir, "lab", "nope", &b) == -ENOENT);
	CHECK(state_delete(dir, "lab", "abc") == 0);
	CHECK(state_load(dir, "lab", "abc", &b) == -ENOENT);

	CHECK(!state_bridge_marked(dir, "tbrx"));
	CHECK(state_mark_bridge(dir, "tbrx", "lab") == 0);
	CHECK(state_bridge_marked(dir, "tbrx"));
	CHECK(state_unmark_bridge(dir, "tbrx") == 0);
	CHECK(!state_bridge_marked(dir, "tbrx"));
	attachment_free(&a);
	t_rmrf(dir);
}

static void test_hosts_block(void)
{
	const char *orig = "127.0.0.1 localhost\n::1 localhost\n";
	char *a = hosts_replace_block(orig, "10.0.0.2\talice.web.lab.trestle\n");
	CHECK_STR(a, "127.0.0.1 localhost\n::1 localhost\n" TR_HOSTS_BEGIN "\n10.0.0.2\talice.web.lab.trestle\n" TR_HOSTS_END "\n");
	/* replace */
	char *b = hosts_replace_block(a, "10.0.0.3\tbob.db.lab.trestle\n");
	CHECK_CONTAINS(b, "bob.db.lab.trestle");
	CHECK(strstr(b, "alice") == NULL);
	/* exactly one managed block */
	const char *first = strstr(b, TR_HOSTS_BEGIN);
	CHECK(first && strstr(first + 1, TR_HOSTS_BEGIN) == NULL);
	/* remove entirely, original content restored */
	char *c = hosts_replace_block(b, "");
	CHECK_STR(c, orig);
	/* file without trailing newline */
	char *d = hosts_replace_block("127.0.0.1 localhost", "1.2.3.4\tx\n");
	CHECK_CONTAINS(d, "127.0.0.1 localhost\n" TR_HOSTS_BEGIN);
	/* user lines after the block are kept */
	char *e = hosts_replace_block("a\n" TR_HOSTS_BEGIN "\nold\n" TR_HOSTS_END "\nb\n", "");
	CHECK_STR(e, "a\nb\n");
	free(a); free(b); free(c); free(d); free(e);
}

static void test_nft(void)
{
	struct tr_config c;
	char err[256];
	struct buf b = { 0 };
	config_defaults(&c);
	CHECK(config_parse_text(&c, "[network:a]\nusers=*\nsubnet=10.0.0.1/24\n", "t", err, sizeof(err)) == 0);
	CHECK(config_finalize(&c, err, sizeof(err)) == 0);
	CHECK(!nft_build_ruleset(&c, &b));       /* nothing requested */
	config_free(&c);

	config_defaults(&c);
	CHECK(config_parse_text(&c,
		"[network:a]\nusers=*\nbridge=br-lab\nsubnet=10.5.0.1/16\nfirewall=yes\nmasquerade=yes\n"
		"inbound_policy=drop\noutbound_policy=drop\nallow_inbound=tcp:80,udp:60-70,icmp\n"
		"allow_inbound_from=192.168.0.0/24\nallow_outbound_to=10.20.0.0/16\nnft_rule=ip daddr 1.2.3.4 drop\n",
		"t", err, sizeof(err)) == 0);
	CHECK(config_finalize(&c, err, sizeof(err)) == 0);
	CHECK(nft_build_ruleset(&c, &b));
	CHECK_CONTAINS(b.p, "table inet trestle\ndelete table inet trestle\n");
	CHECK_CONTAINS(b.p, "chain out_br_lab {");
	CHECK_CONTAINS(b.p, "ip daddr 10.20.0.0/16 accept");
	CHECK_CONTAINS(b.p, "ip saddr 192.168.0.0/24 accept");
	CHECK_CONTAINS(b.p, "tcp dport 80 accept");
	CHECK_CONTAINS(b.p, "udp dport 60-70 accept");
	CHECK_CONTAINS(b.p, "meta l4proto icmp accept");
	CHECK_CONTAINS(b.p, "ip daddr 1.2.3.4 drop");
	CHECK_CONTAINS(b.p, "iifname \"br-lab\" jump out_br_lab");
	CHECK_CONTAINS(b.p, "ip saddr 10.5.0.0/16 oifname != \"br-lab\" masquerade");
	buf_free(&b);
	config_free(&c);
}

static void writefile(const char *path, const char *text)
{
	char dir[512];
	snprintf(dir, sizeof(dir), "%s", path);
	*strrchr(dir, '/') = '\0';
	tr_mkdir_p(dir, 0755);
	FILE *f = fopen(path, "w");
	fputs(text, f);
	fclose(f);
}

static void test_foreign_manager(void)
{
	char *root = t_tmpdir(), p[512];
	CHECK(bridge_foreign_manager(root, "br0", 7) == NULL);

	snprintf(p, sizeof(p), "%s/run/NetworkManager/devices/7", root);
	writefile(p, "[device]\nmanaged=true\n");
	CHECK_STR(bridge_foreign_manager(root, "br0", 7), "NetworkManager");
	CHECK(bridge_foreign_manager(root, "br0", 8) == NULL);

	snprintf(p, sizeof(p), "%s/etc/NetworkManager/system-connections/br1.nmconnection", root);
	writefile(p, "[connection]\nid=br1\ninterface-name=br1\n");
	CHECK_STR(bridge_foreign_manager(root, "br1", 9), "NetworkManager");

	snprintf(p, sizeof(p), "%s/etc/systemd/network/10-br2.netdev", root);
	writefile(p, "[NetDev]\nName=br2\nKind=bridge\n");
	CHECK_STR(bridge_foreign_manager(root, "br2", 10), "systemd-networkd");
	CHECK(bridge_foreign_manager(root, "br22", 10) == NULL);

	snprintf(p, sizeof(p), "%s/etc/libvirt/qemu/networks/default.xml", root);
	writefile(p, "<network><name>default</name><bridge name='virbr0' stp='on'/></network>\n");
	CHECK_STR(bridge_foreign_manager(root, "virbr0", 11), "libvirt");
	t_rmrf(root);
}

static void test_proto(void)
{
	int sv[2];
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
	int fd = open("/dev/null", O_RDONLY);
	const char *msg = "{\"hello\":1}";
	CHECK(tr_send_request(sv[0], msg, strlen(msg), fd) == 0);
	char *got = NULL;
	size_t len;
	int rfd = -1;
	CHECK(tr_recv_request(sv[1], &got, &len, &rfd) == 0);
	CHECK_STR(got, msg);
	CHECK(rfd >= 0 && rfd != fd);
	struct stat a, b;
	CHECK(fstat(fd, &a) == 0 && fstat(rfd, &b) == 0 && a.st_ino == b.st_ino);
	free(got);
	close(rfd);

	/* no fd */
	CHECK(tr_send_request(sv[0], msg, strlen(msg), -1) == 0);
	CHECK(tr_recv_request(sv[1], &got, &len, &rfd) == 0 && rfd == -1);
	free(got);

	CHECK(tr_send_response(sv[1], 3, "out", 3) == 0);
	int code;
	CHECK(tr_recv_response(sv[0], &code, &got, &len) == 0 && code == 3 && len == 3);
	free(got);

	/* garbage header */
	const char junk[12] = "xxxxxxxxxxx";
	CHECK(write(sv[0], junk, sizeof(junk)) == sizeof(junk));
	CHECK(tr_recv_request(sv[1], &got, &len, &rfd) == -EPROTO);
	close(sv[0]);
	close(sv[1]);
	close(fd);
}

static void test_acl(void)
{
	struct tr_peer p = { .uid = 0, .gid = 0, .pw_gid = 0 };
	strcpy(p.user, "root");
	char why[128];
	struct strv l = { 0 };
	CHECK(!acl_allowed(&l, &p, why, sizeof(why)));
	strv_split_push(&l, "alice, bob");
	CHECK(!acl_allowed(&l, &p, why, sizeof(why)));
	strv_clear(&l);
	strv_split_push(&l, "alice, root");
	CHECK(acl_allowed(&l, &p, why, sizeof(why)));
	strv_clear(&l);
	strv_split_push(&l, "@root");                 /* primary group */
	CHECK(acl_allowed(&l, &p, why, sizeof(why)));
	strv_clear(&l);
	strv_split_push(&l, "*, !root");              /* deny wins */
	CHECK(!acl_allowed(&l, &p, why, sizeof(why)));
	CHECK_CONTAINS(why, "!root");
	strv_clear(&l);
	strv_split_push(&l, "root, !@root");
	CHECK(!acl_allowed(&l, &p, why, sizeof(why)));
	strv_clear(&l);
	strv_split_push(&l, "*");
	CHECK(acl_allowed(&l, &p, why, sizeof(why)));
	strv_clear(&l);
	strv_split_push(&l, "@no-such-group-xyz");
	CHECK(!acl_allowed(&l, &p, why, sizeof(why)));
	strv_clear(&l);
}

int main(void)
{
	tlog_init("test", TLOG_STDERR, LOG_ERR);
	RUN(test_ipam);
	RUN(test_records);
	RUN(test_hosts_block);
	RUN(test_nft);
	RUN(test_foreign_manager);
	RUN(test_proto);
	RUN(test_acl);
	TEST_MAIN_END();
}
