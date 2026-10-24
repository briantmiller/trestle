/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Fuzz the request framing: arbitrary bytes arriving on the socket. */
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common/proto.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int sv[2];
	if (size > 60000 || socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
		return 0;
	if (size && write(sv[0], data, size) < 0) {
		close(sv[0]);
		close(sv[1]);
		return 0;
	}
	shutdown(sv[0], SHUT_WR);   /* EOF after the data instead of blocking */
	char *json = NULL;
	size_t len;
	int fd;
	if (tr_recv_request(sv[1], &json, &len, &fd) == 0) {
		free(json);
		if (fd >= 0)
			close(fd);
	}
	close(sv[0]);
	close(sv[1]);
	return 0;
}
