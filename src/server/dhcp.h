/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Minimal DHCPv4 client (RFC 2131) used for networks with ipam = dhcp.
 * trestled acts as the client on behalf of a container: the packets are sent
 * from a UDP socket inside the container's network namespace, bound to the
 * container interface, with the container's MAC as chaddr/client id. The LAN
 * DHCP server therefore sees an ordinary client.
 */
#ifndef TRESTLE_DHCP_H
#define TRESTLE_DHCP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
	DHCP_DISCOVER = 1, DHCP_OFFER = 2, DHCP_REQUEST = 3, DHCP_DECLINE = 4,
	DHCP_ACK = 5, DHCP_NAK = 6, DHCP_RELEASE = 7,
};

struct dhcp_lease {
	uint32_t ip;          /* host byte order */
	uint8_t prefix;
	uint32_t router;      /* 0 = none */
	uint32_t dns[3];      /* 0 terminated */
	uint32_t server;      /* server identifier (option 54) */
	uint32_t lease_time;  /* seconds */
	uint32_t t1, t2;      /* renewal / rebinding times (seconds) */
};

#define DHCP_MAX_PACKET 576

/* Build a client message. requested/server may be 0. Returns its length. */
size_t dhcp_build(uint8_t *buf, size_t len, int type, uint32_t xid, const uint8_t mac[6],
		  uint32_t ciaddr, uint32_t requested, uint32_t server, const char *hostname, bool broadcast);

/* Parse a server reply for our xid and MAC. Returns the message type
 * (OFFER, ACK, NAK) and fills *out for OFFER/ACK, or -1 if the packet is not
 * a valid reply to us. Pure function (unit tested and fuzzed). */
int dhcp_parse(const uint8_t *buf, size_t len, uint32_t xid, const uint8_t mac[6], struct dhcp_lease *out);

/* UDP socket inside the network namespace nsfd bound to <ifname>:68.
 * Returns the fd or -1 (err set). */
int dhcp_socket(int nsfd, const char *ifname, char *err, size_t errlen);

/* DISCOVER / OFFER / REQUEST / ACK. Returns 0 with the lease, or -1. */
int dhcp_acquire(int sock, const uint8_t mac[6], const char *hostname, int timeout_ms,
		 struct dhcp_lease *out, char *err, size_t errlen);

/* Extend a lease: unicast REQUEST to the server (renewing) or broadcast
 * (rebinding). Returns 0 = ACK (*out updated), 1 = NAK, -1 = no answer. */
int dhcp_renew(int sock, const uint8_t mac[6], const char *hostname, const struct dhcp_lease *cur,
	       bool rebind, int timeout_ms, struct dhcp_lease *out);

/* Give the address back (best effort). */
void dhcp_release(int sock, const uint8_t mac[6], const struct dhcp_lease *cur);

/* Host name to send: the container name made DNS-safe (max 63). */
void dhcp_hostname(const char *name, char *out, size_t outlen);

#endif
