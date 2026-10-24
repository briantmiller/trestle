/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "harness.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/proto.h"

static int send_raw(int s, const void *buf, size_t len, const int *fds, int nfds)
{
	char cbuf[CMSG_SPACE(sizeof(int) * 4)] = { 0 };
	struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };
	struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1 };
	if (nfds) {
		m.msg_control = cbuf;
		m.msg_controllen = CMSG_SPACE(sizeof(int) * nfds);
		struct cmsghdr *c = CMSG_FIRSTHDR(&m);
		c->cmsg_level = SOL_SOCKET;
		c->cmsg_type = SCM_RIGHTS;
		c->cmsg_len = CMSG_LEN(sizeof(int) * nfds);
		memcpy(CMSG_DATA(c), fds, sizeof(int) * nfds);
	}
	return (int)sendmsg(s, &m, 0);
}

static int recv_case(const void *buf, size_t len, const int *fds, int nfds, int *fd_out)
{
	int sv[2];
	socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
	send_raw(sv[0], buf, len, fds, nfds);
	shutdown(sv[0], SHUT_WR);
	char *json = NULL;
	size_t l;
	int r = tr_recv_request(sv[1], &json, &l, fd_out);
	free(json);
	close(sv[0]);
	close(sv[1]);
	return r;
}

struct frame { uint32_t magic; uint16_t version, flags; uint32_t len; char body[16]; };

static void test_framing(void)
{
	int fd, devnull = open("/dev/null", O_RDONLY);
	int two[2] = { devnull, devnull };
	struct frame f = { TR_REQ_MAGIC, TR_PROTO_VERSION, 0, 2, "{}" };

	CHECK(recv_case(&f, 14, NULL, 0, &fd) == 0 && fd == -1);
	f.flags = TR_REQ_FLAG_FD;
	CHECK(recv_case(&f, 14, two, 1, &fd) == 0 && fd >= 0);
	close(fd);
	CHECK(recv_case(&f, 14, two, 2, &fd) == -EBADMSG);   /* exactly one fd */
	CHECK(recv_case(&f, 14, NULL, 0, &fd) < 0);           /* flag without fd */
	f.flags = 0;
	CHECK(recv_case(&f, 14, two, 1, &fd) < 0);            /* fd without flag */

	f.flags = 0x8000;
	CHECK(recv_case(&f, 14, NULL, 0, &fd) == -EPROTO);    /* unknown flag bits */
	f.flags = 0;
	struct frame n = { TR_REQ_MAGIC, TR_PROTO_VERSION, 0, 3, "{\0}" };
	CHECK(recv_case(&n, 15, NULL, 0, &fd) == -EBADMSG);   /* raw NUL in body */

	struct frame big = { TR_REQ_MAGIC, TR_PROTO_VERSION, 0, TR_MAX_PAYLOAD + 1, "" };
	CHECK(recv_case(&big, 12, NULL, 0, &fd) == -EMSGSIZE);
	struct frame bad = { 0x41414141, TR_PROTO_VERSION, 0, 2, "{}" };
	CHECK(recv_case(&bad, 14, NULL, 0, &fd) == -EPROTO);
	struct frame shortb = { TR_REQ_MAGIC, TR_PROTO_VERSION, 0, 100, "{}" };
	CHECK(recv_case(&shortb, 14, NULL, 0, &fd) < 0);       /* truncated body */
	CHECK(recv_case(&f, 5, NULL, 0, &fd) < 0);             /* truncated header */

	/* no fd leaked by the rejected cases */
	int probe = open("/dev/null", O_RDONLY);
	CHECK(probe <= devnull + 2);
	close(probe);
	close(devnull);
}

int main(void)
{
	RUN(test_framing);
	TEST_MAIN_END();
}
