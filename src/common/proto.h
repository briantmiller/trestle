/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Wire protocol between the trestle client and trestled.
 *
 *   request  : struct tr_req_hdr + <len bytes of JSON>
 *              optional SCM_RIGHTS fd (network namespace) on the first byte
 *   response : struct tr_resp_hdr + <len bytes of output for stdout>
 *
 * The request JSON looks like:
 *   {
 *     "version": 1,
 *     "mode": "cni" | "netavark",
 *     "command": "ADD" | "DEL" | "CHECK" | "create" | "setup" | "teardown",
 *     "argv": [ ... ],                 // full argv of the client
 *     "env": { "CNI_COMMAND": ... },   // only CNI_* variables
 *     "netns_path": "/run/...",        // when given by the runtime
 *     "netns_fd": true|false,          // an fd is attached
 *     "rootless": true|false,          // client detected a rootless caller
 *     "stdin": "<raw JSON text read from stdin>"
 *   }
 */
#ifndef TRESTLE_PROTO_H
#define TRESTLE_PROTO_H

#include <stddef.h>
#include <stdint.h>

#define TR_PROTO_VERSION   1
#define TR_REQ_MAGIC       0x54525354u  /* "TRST" */
#define TR_RESP_MAGIC      0x54525350u  /* "TRSP" */
#define TR_MAX_PAYLOAD     (1024u * 1024u)
#define TR_REQ_FLAG_FD     0x1

struct tr_req_hdr {
	uint32_t magic;
	uint16_t version;
	uint16_t flags;
	uint32_t len;
};

struct tr_resp_hdr {
	uint32_t magic;
	int32_t  exit_code;
	uint32_t len;
};

/* All return 0 on success, -errno on failure. */
int tr_send_request(int sock, const char *json, size_t len, int pass_fd);
int tr_recv_request(int sock, char **json_out, size_t *len_out, int *fd_out);
int tr_send_response(int sock, int exit_code, const char *out, size_t len);
int tr_recv_response(int sock, int *exit_code, char **out, size_t *len_out);

#endif
