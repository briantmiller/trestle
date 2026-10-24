/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Fuzz the DHCP reply parser (packets from the LAN). The first 4 bytes
 * become the expected xid; the MAC is taken from the packet itself half of
 * the time so the option parser is reached. */
#include <stdint.h>
#include <string.h>

#include "server/dhcp.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 4)
		return 0;
	uint32_t xid = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
	const uint8_t *pkt = data + 4;
	size_t len = size - 4;
	uint8_t mac[6] = { 2, 0, 0, 0, 0, 1 };
	if (len >= 34 && (xid & 1))
		memcpy(mac, pkt + 28, 6);
	struct dhcp_lease l;
	int t = dhcp_parse(pkt, len, xid, mac, &l);
	if (t == DHCP_ACK || t == DHCP_OFFER) {
		/* invariants the rest of trestled relies on */
		if (l.prefix < 1 || l.prefix > 30 || l.ip == 0 || l.lease_time < 60 || l.t1 >= l.lease_time ||
		    l.t2 >= l.lease_time)
			__builtin_trap();
	}
	return 0;
}
