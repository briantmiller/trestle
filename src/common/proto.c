/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "proto.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static int write_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	while (len) {
		ssize_t w = send(fd, p, len, MSG_NOSIGNAL);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		p += w;
		len -= (size_t)w;
	}
	return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
	char *p = buf;
	while (len) {
		ssize_t r = recv(fd, p, len, 0);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (r == 0)
			return -ECONNRESET;
		p += r;
		len -= (size_t)r;
	}
	return 0;
}

int tr_send_request(int sock, const char *json, size_t len, int pass_fd)
{
	struct tr_req_hdr h = {
		.magic = TR_REQ_MAGIC,
		.version = TR_PROTO_VERSION,
		.flags = pass_fd >= 0 ? TR_REQ_FLAG_FD : 0,
		.len = (uint32_t)len,
	};
	if (len > TR_MAX_PAYLOAD)
		return -EMSGSIZE;

	struct iovec iov = { .iov_base = &h, .iov_len = sizeof(h) };
	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} cm;
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };

	if (pass_fd >= 0) {
		memset(&cm, 0, sizeof(cm));
		msg.msg_control = cm.buf;
		msg.msg_controllen = sizeof(cm.buf);
		struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
		c->cmsg_level = SOL_SOCKET;
		c->cmsg_type = SCM_RIGHTS;
		c->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(c), &pass_fd, sizeof(int));
	}

	ssize_t w;
	do {
		w = sendmsg(sock, &msg, MSG_NOSIGNAL);
	} while (w < 0 && errno == EINTR);
	if (w < 0)
		return -errno;
	if ((size_t)w < sizeof(h)) {
		int r = write_all(sock, (char *)&h + w, sizeof(h) - (size_t)w);
		if (r)
			return r;
	}
	return write_all(sock, json, len);
}

int tr_recv_request(int sock, char **json_out, size_t *len_out, int *fd_out)
{
	struct tr_req_hdr h;
	union {
		char buf[CMSG_SPACE(sizeof(int) * 4)];
		struct cmsghdr align;
	} cm;
	struct iovec iov = { .iov_base = &h, .iov_len = sizeof(h) };
	struct msghdr msg = {
		.msg_iov = &iov, .msg_iovlen = 1,
		.msg_control = cm.buf, .msg_controllen = sizeof(cm.buf),
	};
	int fd = -1;
	bool extra_fds = false;

	*fd_out = -1;
	*json_out = NULL;
	ssize_t r;
	do {
		r = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
	} while (r < 0 && errno == EINTR);
	if (r < 0)
		return -errno;
	if (r == 0)
		return -ECONNRESET;

	/* collect passed fds; keep at most one, close the rest */
	for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
		if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS)
			continue;
		size_t n = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
		int fds[4];
		if (n > 4)
			n = 4;
		memcpy(fds, CMSG_DATA(c), n * sizeof(int));
		for (size_t i = 0; i < n; i++) {
			if (fd < 0) {
				fd = fds[i];
			} else {
				close(fds[i]);
				extra_fds = true;
			}
		}
	}
	if ((msg.msg_flags & MSG_CTRUNC) || extra_fds) {
		if (fd >= 0)
			close(fd);
		return -EBADMSG;
	}

	int err = 0;
	if ((size_t)r < sizeof(h))
		err = read_all(sock, (char *)&h + r, sizeof(h) - (size_t)r);
	if (!err && (h.magic != TR_REQ_MAGIC || h.version != TR_PROTO_VERSION))
		err = -EPROTO;
	if (!err && h.len > TR_MAX_PAYLOAD)
		err = -EMSGSIZE;
	if (!err && (h.flags & ~TR_REQ_FLAG_FD))
		err = -EPROTO;     /* unknown flags: a newer client we do not understand */
	if (!err && !!(h.flags & TR_REQ_FLAG_FD) != (fd >= 0))
		err = -EBADMSG;
	char *body = NULL;
	if (!err) {
		body = malloc((size_t)h.len + 1);
		if (!body)
			err = -ENOMEM;
	}
	if (!err)
		err = read_all(sock, body, h.len);
	if (err) {
		free(body);
		if (fd >= 0)
			close(fd);
		return err;
	}
	body[h.len] = '\0';
	if (memchr(body, '\0', h.len)) {   /* would silently cut the JSON */
		free(body);
		if (fd >= 0)
			close(fd);
		return -EBADMSG;
	}
	*json_out = body;
	*len_out = h.len;
	*fd_out = fd;
	return 0;
}

int tr_send_response(int sock, int exit_code, const char *out, size_t len)
{
	struct tr_resp_hdr h = { .magic = TR_RESP_MAGIC, .exit_code = exit_code, .len = (uint32_t)len };
	if (len > TR_MAX_PAYLOAD)
		return -EMSGSIZE;
	int r = write_all(sock, &h, sizeof(h));
	if (!r && len)
		r = write_all(sock, out, len);
	return r;
}

int tr_recv_response(int sock, int *exit_code, char **out, size_t *len_out)
{
	struct tr_resp_hdr h;
	int r = read_all(sock, &h, sizeof(h));
	if (r)
		return r;
	if (h.magic != TR_RESP_MAGIC)
		return -EPROTO;
	if (h.len > TR_MAX_PAYLOAD)
		return -EMSGSIZE;
	char *b = malloc((size_t)h.len + 1);
	if (!b)
		return -ENOMEM;
	r = read_all(sock, b, h.len);
	if (r) {
		free(b);
		return r;
	}
	b[h.len] = '\0';
	*exit_code = h.exit_code;
	*out = b;
	*len_out = h.len;
	return 0;
}
