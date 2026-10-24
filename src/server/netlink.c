/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "netlink.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define NLBUF 8192

struct nlb {
	union {
		struct nlmsghdr n;
		char buf[NLBUF];
	} u;
};

static uint32_t g_seq;

static struct nlmsghdr *nlm_init(struct nlb *b, uint16_t type, uint16_t flags, const void *hdr, size_t hlen)
{
	memset(b, 0, sizeof(*b));
	b->u.n.nlmsg_len = NLMSG_LENGTH(hlen);
	b->u.n.nlmsg_type = type;
	b->u.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	b->u.n.nlmsg_seq = ++g_seq;
	memcpy(NLMSG_DATA(&b->u.n), hdr, hlen);
	return &b->u.n;
}

static struct rtattr *nla_put(struct nlb *b, uint16_t type, const void *data, size_t len)
{
	size_t rl = RTA_LENGTH(len);
	if (NLMSG_ALIGN(b->u.n.nlmsg_len) + RTA_ALIGN(rl) > NLBUF)
		abort(); /* programming error: request too large */
	struct rtattr *rta = (struct rtattr *)((char *)&b->u.n + NLMSG_ALIGN(b->u.n.nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = (unsigned short)rl;
	if (len)
		memcpy(RTA_DATA(rta), data, len);
	b->u.n.nlmsg_len = NLMSG_ALIGN(b->u.n.nlmsg_len) + RTA_ALIGN(rl);
	return rta;
}

static void nla_put_u32(struct nlb *b, uint16_t t, uint32_t v) { nla_put(b, t, &v, sizeof(v)); }
static void nla_put_u8(struct nlb *b, uint16_t t, uint8_t v) { nla_put(b, t, &v, sizeof(v)); }
static void nla_put_str(struct nlb *b, uint16_t t, const char *s) { nla_put(b, t, s, strlen(s) + 1); }

static struct rtattr *nla_nest(struct nlb *b, uint16_t t) { return nla_put(b, t, NULL, 0); }
static void nla_nest_end(struct nlb *b, struct rtattr *nest)
{
	nest->rta_len = (unsigned short)((char *)&b->u.n + b->u.n.nlmsg_len - (char *)nest);
}

/* Append raw bytes (aligned) to the message, used for the veth peer ifinfomsg. */
static void nlm_put_raw(struct nlb *b, const void *data, size_t len)
{
	if (NLMSG_ALIGN(b->u.n.nlmsg_len) + NLMSG_ALIGN(len) > NLBUF)
		abort();
	memcpy((char *)&b->u.n + NLMSG_ALIGN(b->u.n.nlmsg_len), data, len);
	b->u.n.nlmsg_len = NLMSG_ALIGN(b->u.n.nlmsg_len) + NLMSG_ALIGN(len);
}

int nl_open(void)
{
	int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -errno;
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		int e = errno;
		close(fd);
		return -e;
	}
	int one = 1;
	setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one));
	struct timeval tv = { .tv_sec = 5 };
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (!g_seq)
		g_seq = (uint32_t)time(NULL);
	return fd;
}

typedef int (*msg_cb)(struct nlmsghdr *h, void *ctx);

static int nl_talk(int fd, struct nlmsghdr *req, msg_cb cb, void *ctx)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
	ssize_t w;
	do {
		w = sendto(fd, req, req->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa));
	} while (w < 0 && errno == EINTR);
	if (w < 0)
		return -errno;

	char *buf = malloc(65536);
	if (!buf)
		return -ENOMEM;
	int ret = 0;
	bool done = false;
	while (!done) {
		ssize_t r = recv(fd, buf, 65536, 0);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			ret = -errno;
			break;
		}
		for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, (size_t)r); h = NLMSG_NEXT(h, r)) {
			if (h->nlmsg_seq != req->nlmsg_seq)
				continue;
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *e = NLMSG_DATA(h);
				if (e->error && !ret)
					ret = e->error;  /* negative errno */
				done = true;
				break;
			}
			if (h->nlmsg_type == NLMSG_DONE) {
				done = true;
				break;
			}
			if (cb && !ret) {
				int c = cb(h, ctx);
				if (c < 0)
					ret = c;
			}
		}
	}
	free(buf);
	return ret;
}

/* ---- links ----------------------------------------------------------- */

static void parse_link(struct nlmsghdr *h, struct nl_link *l)
{
	struct ifinfomsg *ifi = NLMSG_DATA(h);
	int len = (int)(h->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi)));
	memset(l, 0, sizeof(*l));
	l->ifindex = ifi->ifi_index;
	l->flags = ifi->ifi_flags;
	for (struct rtattr *a = IFLA_RTA(ifi); RTA_OK(a, len); a = RTA_NEXT(a, len)) {
		switch (a->rta_type) {
		case IFLA_IFNAME:
			tr_strlcpy(l->name, RTA_DATA(a), sizeof(l->name));
			break;
		case IFLA_MASTER:
			l->master = (int)*(uint32_t *)RTA_DATA(a);
			break;
		case IFLA_MTU:
			l->mtu = (int)*(uint32_t *)RTA_DATA(a);
			break;
		case IFLA_IFALIAS:
			tr_strlcpy(l->alias, RTA_DATA(a), sizeof(l->alias));
			break;
		case IFLA_ADDRESS:
			if (RTA_PAYLOAD(a) == 6) {
				memcpy(l->mac, RTA_DATA(a), 6);
				l->has_mac = true;
			}
			break;
		case IFLA_LINKINFO: {
			int il = (int)RTA_PAYLOAD(a);
			for (struct rtattr *i = RTA_DATA(a); RTA_OK(i, il); i = RTA_NEXT(i, il))
				if (i->rta_type == IFLA_INFO_KIND)
					tr_strlcpy(l->kind, RTA_DATA(i), sizeof(l->kind));
			break;
		}
		default:
			break;
		}
	}
}

static int get_link_cb(struct nlmsghdr *h, void *ctx)
{
	if (h->nlmsg_type == RTM_NEWLINK)
		parse_link(h, ctx);
	return 0;
}

int nl_get_link(int fd, const char *name, struct nl_link *out)
{
	struct nlb b;
	struct ifinfomsg ifi = { .ifi_family = AF_UNSPEC };
	nlm_init(&b, RTM_GETLINK, 0, &ifi, sizeof(ifi));
	nla_put_str(&b, IFLA_IFNAME, name);
	uint32_t mask = RTEXT_FILTER_VF;  /* keep reply small */
	nla_put_u32(&b, IFLA_EXT_MASK, mask);
	memset(out, 0, sizeof(*out));
	int r = nl_talk(fd, &b.u.n, get_link_cb, out);
	if (r == -ENODEV || (!r && !out->ifindex))
		return -ENODEV;
	return r;
}

int nl_get_link_by_index(int fd, int ifindex, struct nl_link *out)
{
	struct nlb b;
	struct ifinfomsg ifi = { .ifi_family = AF_UNSPEC, .ifi_index = ifindex };
	nlm_init(&b, RTM_GETLINK, 0, &ifi, sizeof(ifi));
	memset(out, 0, sizeof(*out));
	int r = nl_talk(fd, &b.u.n, get_link_cb, out);
	if (r == -ENODEV || (!r && !out->ifindex))
		return -ENODEV;
	return r;
}

struct dump_ctx {
	nl_link_cb cb;
	void *ctx;
};

static int dump_links_cb(struct nlmsghdr *h, void *ctx)
{
	struct dump_ctx *d = ctx;
	struct nl_link l;
	if (h->nlmsg_type != RTM_NEWLINK)
		return 0;
	parse_link(h, &l);
	return d->cb(&l, d->ctx);
}

int nl_dump_links(int fd, nl_link_cb cb, void *ctx)
{
	struct nlb b;
	struct ifinfomsg ifi = { .ifi_family = AF_UNSPEC };
	struct dump_ctx d = { cb, ctx };
	nlm_init(&b, RTM_GETLINK, NLM_F_DUMP, &ifi, sizeof(ifi));
	return nl_talk(fd, &b.u.n, dump_links_cb, &d);
}

int nl_create_bridge(int fd, const char *name, int mtu, bool stp, bool vlan_filtering, const uint8_t *mac)
{
	struct nlb b;
	struct ifinfomsg ifi = { .ifi_family = AF_UNSPEC };
	nlm_init(&b, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &ifi, sizeof(ifi));
	nla_put_str(&b, IFLA_IFNAME, name);
	/* a fixed address: otherwise the bridge takes the lowest port MAC and
	 * the gateway MAC changes whenever containers come and go */
	if (mac)
		nla_put(&b, IFLA_ADDRESS, mac, 6);
	if (mtu > 0)
		nla_put_u32(&b, IFLA_MTU, (uint32_t)mtu);
	struct rtattr *li = nla_nest(&b, IFLA_LINKINFO);
	nla_put_str(&b, IFLA_INFO_KIND, "bridge");
	struct rtattr *data = nla_nest(&b, IFLA_INFO_DATA);
	if (stp)
		nla_put_u32(&b, IFLA_BR_STP_STATE, 1);
	/* only send when wanted: kernels without CONFIG_BRIDGE_VLAN_FILTERING
	 * reject the attribute even when it is 0 */
	if (vlan_filtering)
		nla_put_u8(&b, IFLA_BR_VLAN_FILTERING, 1);
	nla_nest_end(&b, data);
	nla_nest_end(&b, li);
	return nl_talk(fd, &b.u.n, NULL, NULL);
}

int nl_create_veth(int fd, const char *host, const char *peer, int peer_nsfd,
		   int mtu, const uint8_t *peer_mac)
{
	struct nlb b;
	struct ifinfomsg ifi = { .ifi_family = AF_UNSPEC };
	nlm_init(&b, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &ifi, sizeof(ifi));
	nla_put_str(&b, IFLA_IFNAME, host);
	if (mtu > 0)
		nla_put_u32(&b, IFLA_MTU, (uint32_t)mtu);
	struct rtattr *li = nla_nest(&b, IFLA_LINKINFO);
	nla_put_str(&b, IFLA_INFO_KIND, "veth");
	struct rtattr *data = nla_nest(&b, IFLA_INFO_DATA);
	struct rtattr *p = nla_nest(&b, VETH_INFO_PEER);
	struct ifinfomsg pifi = { .ifi_family = AF_UNSPEC };
	nlm_put_raw(&b, &pifi, sizeof(pifi));
	nla_put_str(&b, IFLA_IFNAME, peer);
	if (peer_nsfd >= 0)
		nla_put_u32(&b, IFLA_NET_NS_FD, (uint32_t)peer_nsfd);
	if (mtu > 0)
		nla_put_u32(&b, IFLA_MTU, (uint32_t)mtu);
	if (peer_mac)
		nla_put(&b, IFLA_ADDRESS, peer_mac, 6);
	nla_nest_end(&b, p);
	nla_nest_end(&b, data);
	nla_nest_end(&b, li);
	return nl_talk(fd, &b.u.n, NULL, NULL);
}

static int link_change(int fd, int ifindex, unsigned flags, unsigned change, struct nlb *b)
{
	(void)fd;
	struct ifinfomsg ifi = {
		.ifi_family = AF_UNSPEC, .ifi_index = ifindex,
		.ifi_flags = flags, .ifi_change = change,
	};
	nlm_init(b, RTM_NEWLINK, 0, &ifi, sizeof(ifi));
	return 0;
}

int nl_del_link(int fd, int ifindex)
{
	struct nlb b;
	struct ifinfomsg ifi = { .ifi_family = AF_UNSPEC, .ifi_index = ifindex };
	nlm_init(&b, RTM_DELLINK, 0, &ifi, sizeof(ifi));
	return nl_talk(fd, &b.u.n, NULL, NULL);
}

int nl_set_up(int fd, int ifindex, bool up)
{
	struct nlb b;
	link_change(fd, ifindex, up ? IFF_UP : 0, IFF_UP, &b);
	return nl_talk(fd, &b.u.n, NULL, NULL);
}

int nl_set_master(int fd, int ifindex, int master)
{
	struct nlb b;
	link_change(fd, ifindex, 0, 0, &b);
	nla_put_u32(&b, IFLA_MASTER, (uint32_t)master);
	return nl_talk(fd, &b.u.n, NULL, NULL);
}

int nl_set_alias(int fd, int ifindex, const char *alias)
{
	struct nlb b;
	link_change(fd, ifindex, 0, 0, &b);
	nla_put(&b, IFLA_IFALIAS, alias, strlen(alias));
	return nl_talk(fd, &b.u.n, NULL, NULL);
}

int nl_set_mtu(int fd, int ifindex, int mtu)
{
	struct nlb b;
	link_change(fd, ifindex, 0, 0, &b);
	nla_put_u32(&b, IFLA_MTU, (uint32_t)mtu);
	return nl_talk(fd, &b.u.n, NULL, NULL);
}

/* ---- addresses ------------------------------------------------------- */

int nl_addr_add(int fd, int ifindex, uint32_t addr, uint8_t prefix)
{
	struct nlb b;
	struct ifaddrmsg ifa = {
		.ifa_family = AF_INET, .ifa_prefixlen = prefix,
		.ifa_scope = RT_SCOPE_UNIVERSE, .ifa_index = (unsigned)ifindex,
	};
	uint32_t a = htonl(addr);
	uint32_t bc = htonl(addr | ~tr_prefix_mask(prefix));
	nlm_init(&b, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &ifa, sizeof(ifa));
	nla_put(&b, IFA_LOCAL, &a, 4);
	nla_put(&b, IFA_ADDRESS, &a, 4);
	if (prefix < 31)
		nla_put(&b, IFA_BROADCAST, &bc, 4);
	return nl_talk(fd, &b.u.n, NULL, NULL);
}

int nl_addr_del(int fd, int ifindex, uint32_t addr, uint8_t prefix)
{
	struct nlb b;
	struct ifaddrmsg ifa = {
		.ifa_family = AF_INET, .ifa_prefixlen = prefix,
		.ifa_scope = RT_SCOPE_UNIVERSE, .ifa_index = (unsigned)ifindex,
	};
	uint32_t a = htonl(addr);
	nlm_init(&b, RTM_DELADDR, 0, &ifa, sizeof(ifa));
	nla_put(&b, IFA_LOCAL, &a, 4);
	return nl_talk(fd, &b.u.n, NULL, NULL);
}

struct addr_ctx {
	int ifindex;
	uint32_t want;     /* 0 = first address */
	bool found;
	uint32_t addr;
	uint8_t prefix;
};

static int addr_cb(struct nlmsghdr *h, void *ctx)
{
	struct addr_ctx *c = ctx;
	if (h->nlmsg_type != RTM_NEWADDR || c->found)
		return 0;
	struct ifaddrmsg *ifa = NLMSG_DATA(h);
	if (ifa->ifa_family != AF_INET || (int)ifa->ifa_index != c->ifindex)
		return 0;
	int len = (int)(h->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));
	uint32_t local = 0;
	bool have = false;
	for (struct rtattr *a = IFA_RTA(ifa); RTA_OK(a, len); a = RTA_NEXT(a, len)) {
		if ((a->rta_type == IFA_LOCAL || (a->rta_type == IFA_ADDRESS && !have)) && RTA_PAYLOAD(a) == 4) {
			local = ntohl(*(uint32_t *)RTA_DATA(a));
			have = true;
		}
	}
	if (have && (!c->want || c->want == local)) {
		c->found = true;
		c->addr = local;
		c->prefix = ifa->ifa_prefixlen;
	}
	return 0;
}

static int addr_dump(int fd, struct addr_ctx *c)
{
	struct nlb b;
	struct ifaddrmsg ifa = { .ifa_family = AF_INET };
	nlm_init(&b, RTM_GETADDR, NLM_F_DUMP, &ifa, sizeof(ifa));
	return nl_talk(fd, &b.u.n, addr_cb, c);
}

int nl_addr_has(int fd, int ifindex, uint32_t addr, uint8_t *prefix_out)
{
	struct addr_ctx c = { .ifindex = ifindex, .want = addr };
	int r = addr_dump(fd, &c);
	if (r < 0)
		return r;
	if (c.found && prefix_out)
		*prefix_out = c.prefix;
	return c.found ? 1 : 0;
}

int nl_addr_first(int fd, int ifindex, uint32_t *addr, uint8_t *prefix)
{
	struct addr_ctx c = { .ifindex = ifindex };
	int r = addr_dump(fd, &c);
	if (r < 0)
		return r;
	if (!c.found)
		return -ENOENT;
	*addr = c.addr;
	*prefix = c.prefix;
	return 0;
}

int nl_route_add_default(int fd, int ifindex, uint32_t gw)
{
	struct nlb b;
	struct rtmsg rt = {
		.rtm_family = AF_INET, .rtm_dst_len = 0, .rtm_table = RT_TABLE_MAIN,
		.rtm_protocol = RTPROT_STATIC, .rtm_scope = RT_SCOPE_UNIVERSE,
		.rtm_type = RTN_UNICAST,
	};
	uint32_t g = htonl(gw);
	uint32_t oif = (uint32_t)ifindex;
	nlm_init(&b, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &rt, sizeof(rt));
	nla_put(&b, RTA_GATEWAY, &g, 4);
	nla_put(&b, RTA_OIF, &oif, 4);
	return nl_talk(fd, &b.u.n, NULL, NULL);
}
