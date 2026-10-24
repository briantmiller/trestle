/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "dhcp.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../common/log.h"
#include "../common/util.h"
#include "checks.h"
#include "exec.h"

/* BOOTP header (RFC 951 / 2131) */
#define OFF_OP      0
#define OFF_HTYPE   1
#define OFF_HLEN    2
#define OFF_XID     4
#define OFF_FLAGS   10
#define OFF_CIADDR  12
#define OFF_YIADDR  16
#define OFF_CHADDR  28
#define OFF_COOKIE  236
#define OFF_OPTIONS 240
static const uint8_t COOKIE[4] = { 99, 130, 83, 99 };

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

static uint32_t get32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

size_t dhcp_build(uint8_t *buf, size_t len, int type, uint32_t xid, const uint8_t mac[6],
		  uint32_t ciaddr, uint32_t requested, uint32_t server, const char *hostname, bool broadcast)
{
	if (len < 300)
		return 0;
	memset(buf, 0, len);
	buf[OFF_OP] = 1;      /* BOOTREQUEST */
	buf[OFF_HTYPE] = 1;   /* Ethernet */
	buf[OFF_HLEN] = 6;
	put32(buf + OFF_XID, xid);
	if (broadcast)
		buf[OFF_FLAGS] = 0x80;   /* ask the server to broadcast its reply */
	put32(buf + OFF_CIADDR, ciaddr);
	memcpy(buf + OFF_CHADDR, mac, 6);
	memcpy(buf + OFF_COOKIE, COOKIE, 4);

	size_t o = OFF_OPTIONS;
	buf[o++] = 53;
	buf[o++] = 1;
	buf[o++] = (uint8_t)type;
	buf[o++] = 61;           /* client identifier: type 1 (Ethernet) + MAC */
	buf[o++] = 7;
	buf[o++] = 1;
	memcpy(buf + o, mac, 6);
	o += 6;
	if (requested) {
		buf[o++] = 50;
		buf[o++] = 4;
		put32(buf + o, requested);
		o += 4;
	}
	if (server) {
		buf[o++] = 54;
		buf[o++] = 4;
		put32(buf + o, server);
		o += 4;
	}
	if (hostname && *hostname && type != DHCP_RELEASE) {
		size_t hl = strlen(hostname);
		if (hl > 63)
			hl = 63;
		buf[o++] = 12;
		buf[o++] = (uint8_t)hl;
		memcpy(buf + o, hostname, hl);
		o += hl;
	}
	if (type == DHCP_DISCOVER || type == DHCP_REQUEST) {
		static const uint8_t prl[] = { 1, 3, 6, 15, 51, 54, 58, 59 };
		buf[o++] = 55;
		buf[o++] = sizeof(prl);
		memcpy(buf + o, prl, sizeof(prl));
		o += sizeof(prl);
		buf[o++] = 57;   /* maximum message size */
		buf[o++] = 2;
		buf[o++] = DHCP_MAX_PACKET >> 8;
		buf[o++] = DHCP_MAX_PACKET & 0xff;
	}
	buf[o++] = 255;
	return o < 300 ? 300 : o;   /* BOOTP minimum size */
}

static bool usable_ip(uint32_t a)
{
	uint8_t top = (uint8_t)(a >> 24);
	return a != 0 && a != 0xffffffffu && top != 127 && top != 0 && top < 224;
}

static int mask_prefix(uint32_t m)
{
	int p = 0;
	while (p < 32 && (m & (0x80000000u >> p)))
		p++;
	if (p < 32 && (m << p) != 0)
		return -1;   /* not contiguous */
	return p;
}

int dhcp_parse(const uint8_t *buf, size_t len, uint32_t xid, const uint8_t mac[6], struct dhcp_lease *out)
{
	if (len < OFF_OPTIONS + 1 || len > 65535)
		return -1;
	if (buf[OFF_OP] != 2 || buf[OFF_HTYPE] != 1 || buf[OFF_HLEN] != 6)
		return -1;
	if (get32(buf + OFF_XID) != xid || memcmp(buf + OFF_CHADDR, mac, 6) != 0)
		return -1;
	if (memcmp(buf + OFF_COOKIE, COOKIE, 4) != 0)
		return -1;

	struct dhcp_lease l;
	memset(&l, 0, sizeof(l));
	l.ip = get32(buf + OFF_YIADDR);
	int type = -1, ndns = 0;
	uint32_t mask = 0;
	bool have_mask = false;

	size_t o = OFF_OPTIONS;
	while (o < len) {
		uint8_t code = buf[o++];
		if (code == 0)
			continue;          /* pad */
		if (code == 255)
			break;
		if (o >= len)
			return -1;
		uint8_t ol = buf[o++];
		if (o + ol > len)
			return -1;         /* option runs past the packet */
		const uint8_t *v = buf + o;
		switch (code) {
		case 53:
			if (ol == 1)
				type = v[0];
			break;
		case 1:
			if (ol == 4) {
				mask = get32(v);
				have_mask = true;
			}
			break;
		case 3:
			if (ol >= 4 && ol % 4 == 0)
				l.router = get32(v);   /* first router */
			break;
		case 6:
			for (int i = 0; i + 4 <= ol && ndns < 3; i += 4) {
				uint32_t d = get32(v + i);
				if (usable_ip(d))
					l.dns[ndns++] = d;
			}
			break;
		case 51:
			if (ol == 4)
				l.lease_time = get32(v);
			break;
		case 54:
			if (ol == 4)
				l.server = get32(v);
			break;
		case 58:
			if (ol == 4)
				l.t1 = get32(v);
			break;
		case 59:
			if (ol == 4)
				l.t2 = get32(v);
			break;
		default:
			break;             /* option overload (52) etc. are not used */
		}
		o += ol;
	}

	if (type == DHCP_NAK)
		return DHCP_NAK;
	if (type != DHCP_OFFER && type != DHCP_ACK)
		return -1;
	if (!usable_ip(l.ip) || !l.server)
		return -1;
	int p = have_mask ? mask_prefix(mask) : -1;
	if (p < 0) {
		/* no or broken mask: classful default as the old clients do */
		uint8_t top = (uint8_t)(l.ip >> 24);
		p = top < 128 ? 8 : top < 192 ? 16 : 24;
	}
	if (p < 1 || p > 30)
		return -1;              /* /31, /32 point-to-point leases are not supported */
	l.prefix = (uint8_t)p;
	uint32_t m = tr_prefix_mask(l.prefix);
	if ((l.ip & ~m) == 0 || (l.ip & ~m) == ~m)
		return -1;              /* network or broadcast address */
	if (l.router && ((l.router & m) != (l.ip & m) || !usable_ip(l.router) || l.router == l.ip))
		l.router = 0;           /* off-link router: ignore */
	/* RFC 2131 defaults; infinite (0xffffffff) is capped at one day so the
	 * keeper still checks in */
	if (l.lease_time == 0 || l.lease_time > 86400)
		l.lease_time = l.lease_time == 0 ? 3600 : 86400;
	if (l.lease_time < 60)
		l.lease_time = 60;
	if (!l.t1 || l.t1 >= l.lease_time)
		l.t1 = l.lease_time / 2;
	if (!l.t2 || l.t2 >= l.lease_time || l.t2 <= l.t1)
		l.t2 = l.lease_time / 8 * 7;
	if (out)
		*out = l;
	return type;
}

int dhcp_socket(int nsfd, const char *ifname, char *err, size_t errlen)
{
	int s = netns_socket(nsfd, AF_INET, SOCK_DGRAM, IPPROTO_UDP, err, errlen);
	if (s < 0)
		return -1;
	int one = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0 ||
	    setsockopt(s, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)) < 0 ||
	    setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, ifname, (socklen_t)strlen(ifname) + 1) < 0) {
		snprintf(err, errlen, "DHCP socket options on %s: %s", ifname, strerror(errno));
		close(s);
		return -1;
	}
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(68), .sin_addr.s_addr = htonl(INADDR_ANY) };
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		snprintf(err, errlen, "cannot bind DHCP client port 68 on %s: %s", ifname, strerror(errno));
		close(s);
		return -1;
	}
	return s;
}

static uint32_t new_xid(void)
{
	uint32_t x;
	if (getrandom(&x, sizeof(x), 0) != sizeof(x))
		x = (uint32_t)tr_now_ms() ^ (uint32_t)getpid() << 16;
	return x;
}

static int send_to(int sock, const uint8_t *pkt, size_t len, uint32_t dst)
{
	struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(67), .sin_addr.s_addr = htonl(dst) };
	return sendto(sock, pkt, len, 0, (struct sockaddr *)&sa, sizeof(sa)) == (ssize_t)len ? 0 : -1;
}

/* Wait for a reply of one of the wanted types until deadline (ms clock). */
static int wait_reply(int sock, uint32_t xid, const uint8_t mac[6], long deadline, bool want_offer,
		      struct dhcp_lease *out)
{
	uint8_t buf[1500];
	for (;;) {
		long left = deadline - tr_now_ms();
		if (left <= 0)
			return -1;
		struct pollfd p = { .fd = sock, .events = POLLIN };
		int r = poll(&p, 1, (int)left);
		if (r < 0 && errno == EINTR)
			return -2;          /* let the caller check for signals */
		if (r <= 0)
			continue;
		ssize_t n = recv(sock, buf, sizeof(buf), 0);
		if (n <= 0)
			continue;
		int t = dhcp_parse(buf, (size_t)n, xid, mac, out);
		if (want_offer ? t == DHCP_OFFER : (t == DHCP_ACK || t == DHCP_NAK))
			return t;
	}
}

int dhcp_acquire(int sock, const uint8_t mac[6], const char *hostname, int timeout_ms,
		 struct dhcp_lease *out, char *err, size_t errlen)
{
	long end = tr_now_ms() + timeout_ms;
	uint8_t pkt[DHCP_MAX_PACKET];
	int naks = 0;
	while (tr_now_ms() < end) {
		uint32_t xid = new_xid();
		struct dhcp_lease offer;
		int got = -1;
		/* DISCOVER with exponential back-off: 1, 2, 4 ... s */
		for (long wait = 1000; tr_now_ms() < end && got != DHCP_OFFER; wait = wait < 8000 ? wait * 2 : wait) {
			size_t len = dhcp_build(pkt, sizeof(pkt), DHCP_DISCOVER, xid, mac, 0, 0, 0, hostname, true);
			if (send_to(sock, pkt, len, INADDR_BROADCAST) < 0) {
				snprintf(err, errlen, "cannot send DHCPDISCOVER: %s", strerror(errno));
				return -1;
			}
			long dl = tr_now_ms() + wait;
			if (dl > end)
				dl = end;
			got = wait_reply(sock, xid, mac, dl, true, &offer);
			if (got == -2)
				break;
		}
		if (got != DHCP_OFFER)
			break;
		for (int tries = 0; tries < 3 && tr_now_ms() < end; tries++) {
			size_t len = dhcp_build(pkt, sizeof(pkt), DHCP_REQUEST, xid, mac, 0, offer.ip, offer.server,
						hostname, true);
			if (send_to(sock, pkt, len, INADDR_BROADCAST) < 0)
				break;
			long dl = tr_now_ms() + 2000;
			if (dl > end)
				dl = end;
			struct dhcp_lease ack;
			int t = wait_reply(sock, xid, mac, dl, false, &ack);
			if (t == DHCP_ACK) {
				if (ack.ip != offer.ip)
					break;   /* inconsistent server: start over */
				*out = ack;
				return 0;
			}
			if (t == DHCP_NAK) {
				naks++;
				break;
			}
		}
	}
	snprintf(err, errlen, "no DHCP lease within %d s%s", timeout_ms / 1000,
		 naks ? " (the server refused the offered address)" : " (is a DHCP server reachable on the bridge?)");
	return -1;
}

int dhcp_renew(int sock, const uint8_t mac[6], const char *hostname, const struct dhcp_lease *cur,
	       bool rebind, int timeout_ms, struct dhcp_lease *out)
{
	uint8_t pkt[DHCP_MAX_PACKET];
	uint32_t xid = new_xid();
	/* RFC 2131 4.3.2: RENEWING/REBINDING put the address in ciaddr and
	 * carry neither option 50 nor 54 */
	size_t len = dhcp_build(pkt, sizeof(pkt), DHCP_REQUEST, xid, mac, cur->ip, 0, 0, hostname, false);
	if (send_to(sock, pkt, len, rebind ? INADDR_BROADCAST : cur->server) < 0)
		return -1;
	struct dhcp_lease l;
	int t = wait_reply(sock, xid, mac, tr_now_ms() + timeout_ms, false, &l);
	if (t == DHCP_NAK)
		return 1;
	if (t != DHCP_ACK)
		return -1;
	*out = l;
	return 0;
}

void dhcp_release(int sock, const uint8_t mac[6], const struct dhcp_lease *cur)
{
	uint8_t pkt[DHCP_MAX_PACKET];
	if (!cur->ip || !cur->server)
		return;
	size_t len = dhcp_build(pkt, sizeof(pkt), DHCP_RELEASE, new_xid(), mac, cur->ip, 0, cur->server, NULL, false);
	/* unicast: the first copy may wait for ARP, and the interface is
	 * deleted right after we return, so give it time and send it twice
	 * (a repeated RELEASE is harmless) */
	/* unicast as RFC 2131 says, plus a broadcast copy: the interface is
	 * deleted right after this, and the unicast may still wait for ARP or
	 * go to a stale gateway MAC. Other servers ignore it (option 54). A
	 * repeated RELEASE is harmless. */
	if (send_to(sock, pkt, len, cur->server) < 0)
		log_warn("cannot send DHCPRELEASE: %s", strerror(errno));
	tr_sleep_ms(200);
	if (send_to(sock, pkt, len, INADDR_BROADCAST) < 0)
		log_warn("cannot send DHCPRELEASE: %s", strerror(errno));
	tr_sleep_ms(100);
}

void dhcp_hostname(const char *name, char *out, size_t outlen)
{
	size_t o = 0;
	for (const char *p = name; *p && o + 1 < outlen && o < 63; p++)
		out[o++] = isalnum((unsigned char)*p) ? (char)tolower((unsigned char)*p) : '-';
	while (o && out[o - 1] == '-')
		o--;
	out[o] = '\0';
}
