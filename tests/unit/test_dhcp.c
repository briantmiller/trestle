/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "harness.h"

#include "server/dhcp.h"

static const uint8_t MAC[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };

/* Build a server reply: header + options given as raw bytes. */
static size_t reply(uint8_t *b, uint32_t xid, uint32_t yiaddr, const uint8_t *opts, size_t olen)
{
	memset(b, 0, 600);
	b[0] = 2;
	b[1] = 1;
	b[2] = 6;
	b[4] = (uint8_t)(xid >> 24); b[5] = (uint8_t)(xid >> 16); b[6] = (uint8_t)(xid >> 8); b[7] = (uint8_t)xid;
	b[16] = (uint8_t)(yiaddr >> 24); b[17] = (uint8_t)(yiaddr >> 16); b[18] = (uint8_t)(yiaddr >> 8); b[19] = (uint8_t)yiaddr;
	memcpy(b + 28, MAC, 6);
	b[236] = 99; b[237] = 130; b[238] = 83; b[239] = 99;
	memcpy(b + 240, opts, olen);
	return 240 + olen;
}

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((b) << 16) | ((c) << 8) | (d))

static void test_build(void)
{
	uint8_t p[DHCP_MAX_PACKET];
	size_t n = dhcp_build(p, sizeof(p), DHCP_DISCOVER, 0x01020304, MAC, 0, 0, 0, "web-1", true);
	CHECK(n >= 300);
	CHECK(p[0] == 1 && p[1] == 1 && p[2] == 6);
	CHECK(p[4] == 1 && p[7] == 4);
	CHECK(p[10] == 0x80);                                  /* broadcast flag */
	CHECK(!memcmp(p + 28, MAC, 6));
	CHECK(p[236] == 99 && p[239] == 99);
	CHECK(p[240] == 53 && p[241] == 1 && p[242] == DHCP_DISCOVER);
	CHECK(p[243] == 61 && p[244] == 7 && p[245] == 1 && !memcmp(p + 246, MAC, 6));
	CHECK(p[252] == 12 && p[253] == 5 && !memcmp(p + 254, "web-1", 5));

	n = dhcp_build(p, sizeof(p), DHCP_REQUEST, 7, MAC, 0, IP(192, 168, 1, 50), IP(192, 168, 1, 1), NULL, true);
	CHECK(p[252] == 54 || p[246 + 6] == 50);               /* option 50 then 54 after the client id */
	CHECK(p[252] == 50 && p[253] == 4 && p[254] == 192 && p[257] == 50);
	CHECK(p[258] == 54 && p[262] == 1);

	char h[64];
	dhcp_hostname("Prod_DB.0", h, sizeof(h));
	CHECK_STR(h, "prod-db-0");
	dhcp_hostname("a__", h, sizeof(h));
	CHECK_STR(h, "a");
}

static void test_parse(void)
{
	uint8_t b[600];
	struct dhcp_lease l;
	static const uint8_t ack[] = {
		53, 1, DHCP_ACK, 54, 4, 192, 168, 1, 1, 1, 4, 255, 255, 255, 0, 3, 8, 192, 168, 1, 1, 192, 168, 1, 2,
		6, 8, 192, 168, 1, 1, 8, 8, 8, 8, 51, 4, 0, 0, 0x0e, 0x10, 255,
	};
	size_t n = reply(b, 42, IP(192, 168, 1, 50), ack, sizeof(ack));
	CHECK(dhcp_parse(b, n, 42, MAC, &l) == DHCP_ACK);
	CHECK(l.ip == IP(192, 168, 1, 50) && l.prefix == 24);
	CHECK(l.router == IP(192, 168, 1, 1));
	CHECK(l.dns[0] == IP(192, 168, 1, 1) && l.dns[1] == IP(8, 8, 8, 8) && l.dns[2] == 0);
	CHECK(l.server == IP(192, 168, 1, 1));
	CHECK(l.lease_time == 3600 && l.t1 == 1800 && l.t2 == 3150);

	/* not for us */
	CHECK(dhcp_parse(b, n, 43, MAC, &l) == -1);
	uint8_t other[6] = { 2, 0, 0, 0, 0, 9 };
	CHECK(dhcp_parse(b, n, 42, other, &l) == -1);
	/* a request (op 1) is not a reply */
	b[0] = 1;
	CHECK(dhcp_parse(b, n, 42, MAC, &l) == -1);
	b[0] = 2;
	/* bad cookie */
	b[236] = 0;
	CHECK(dhcp_parse(b, n, 42, MAC, &l) == -1);
	b[236] = 99;
	/* truncated in the middle of an option */
	CHECK(dhcp_parse(b, 240 + 12, 42, MAC, &l) == -1);
	CHECK(dhcp_parse(b, 100, 42, MAC, &l) == -1);

	/* NAK */
	static const uint8_t nak[] = { 53, 1, DHCP_NAK, 54, 4, 192, 168, 1, 1, 255 };
	n = reply(b, 42, 0, nak, sizeof(nak));
	CHECK(dhcp_parse(b, n, 42, MAC, &l) == DHCP_NAK);

	/* unusable offers are refused */
	static const uint8_t offer[] = { 53, 1, DHCP_OFFER, 54, 4, 10, 0, 0, 1, 1, 4, 255, 255, 255, 0, 255 };
	n = reply(b, 1, IP(10, 0, 0, 0), offer, sizeof(offer));          /* network address */
	CHECK(dhcp_parse(b, n, 1, MAC, &l) == -1);
	n = reply(b, 1, IP(10, 0, 0, 255), offer, sizeof(offer));        /* broadcast */
	CHECK(dhcp_parse(b, n, 1, MAC, &l) == -1);
	n = reply(b, 1, IP(127, 0, 0, 5), offer, sizeof(offer));
	CHECK(dhcp_parse(b, n, 1, MAC, &l) == -1);
	n = reply(b, 1, IP(224, 0, 0, 5), offer, sizeof(offer));
	CHECK(dhcp_parse(b, n, 1, MAC, &l) == -1);
	n = reply(b, 1, IP(10, 0, 0, 7), offer, sizeof(offer));
	CHECK(dhcp_parse(b, n, 1, MAC, &l) == DHCP_OFFER && l.ip == IP(10, 0, 0, 7));
	CHECK(l.lease_time == 3600);                                     /* default */

	/* non-contiguous mask: classful fallback; off-link router dropped */
	static const uint8_t odd[] = { 53, 1, DHCP_ACK, 54, 4, 10, 1, 0, 1, 1, 4, 255, 0, 255, 0,
				       3, 4, 172, 16, 0, 1, 51, 4, 0, 0, 0, 10, 255 };
	n = reply(b, 5, IP(10, 1, 0, 7), odd, sizeof(odd));
	CHECK(dhcp_parse(b, n, 5, MAC, &l) == DHCP_ACK);
	CHECK(l.prefix == 8 && l.router == 0);
	CHECK(l.lease_time == 60);                                       /* minimum */

	/* /31 and /32 are not supported */
	static const uint8_t p32[] = { 53, 1, DHCP_ACK, 54, 4, 10, 0, 0, 1, 1, 4, 255, 255, 255, 255, 255 };
	n = reply(b, 5, IP(10, 0, 0, 7), p32, sizeof(p32));
	CHECK(dhcp_parse(b, n, 5, MAC, &l) == -1);

	/* missing server identifier */
	static const uint8_t nosid[] = { 53, 1, DHCP_ACK, 1, 4, 255, 255, 255, 0, 255 };
	n = reply(b, 5, IP(10, 0, 0, 7), nosid, sizeof(nosid));
	CHECK(dhcp_parse(b, n, 5, MAC, &l) == -1);

	/* infinite lease is capped */
	static const uint8_t inf[] = { 53, 1, DHCP_ACK, 54, 4, 10, 0, 0, 1, 51, 4, 255, 255, 255, 255, 255 };
	n = reply(b, 5, IP(10, 0, 0, 7), inf, sizeof(inf));
	CHECK(dhcp_parse(b, n, 5, MAC, &l) == DHCP_ACK && l.lease_time == 86400);
}

int main(void)
{
	RUN(test_build);
	RUN(test_parse);
	TEST_MAIN_END();
}
