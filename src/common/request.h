/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Parsing and validation of CNI / Netavark invocations. Shared by the client
 * (which validates before contacting the server) and the server (which
 * re-validates everything it receives and never trusts the client).
 */
#ifndef TRESTLE_REQUEST_H
#define TRESTLE_REQUEST_H

#include <json-c/json.h>
#include <limits.h>
#include <stdbool.h>

#include "util.h"

enum tr_mode { TR_MODE_CNI, TR_MODE_NETAVARK };

enum tr_cmd {
	TR_CMD_CNI_ADD, TR_CMD_CNI_DEL, TR_CMD_CNI_CHECK, TR_CMD_CNI_VERSION,
	TR_CMD_NV_CREATE, TR_CMD_NV_SETUP, TR_CMD_NV_TEARDOWN, TR_CMD_NV_INFO,
};

/* CNI spec error codes */
enum {
	CNI_ERR_INCOMPATIBLE_VERSION = 1,
	CNI_ERR_UNSUPPORTED_FIELD = 2,
	CNI_ERR_UNKNOWN_CONTAINER = 3,
	CNI_ERR_INVALID_ENV = 4,
	CNI_ERR_IO = 5,
	CNI_ERR_DECODE = 6,
	CNI_ERR_INVALID_CONFIG = 7,
	CNI_ERR_TRY_AGAIN = 11,
	CNI_ERR_PLUGIN = 100,
};

#define TR_CNI_SUPPORTED_VERSIONS "\"0.3.0\",\"0.3.1\",\"0.4.0\",\"1.0.0\""

struct tr_request {
	enum tr_mode mode;
	enum tr_cmd cmd;
	char command[16];

	char cni_version[16];             /* CNI: from config */
	char network[TR_MAX_NAME + 1];
	char container_id[129];
	char container_name[TR_MAX_NAME + 1];
	char ifname[TR_IFNAMSIZ];
	char netns_path[PATH_MAX];

	struct strv static_ips;           /* requested IPv4 addresses (no prefix) */
	char static_mac[18];
	struct strv aliases;              /* Netavark DNS aliases */

	json_object *input;               /* parsed stdin, owned */
};

typedef const char *(*tr_env_fn)(void *ctx, const char *name);

void tr_request_free(struct tr_request *r);

/* Parse and validate a CNI invocation. On failure returns -1, fills err and
 * *cni_code. getenv_fn looks up CNI_* variables. stdin_text may be NULL only
 * for VERSION. */
int tr_parse_cni(tr_env_fn getenv_fn, void *ctx, const char *stdin_text,
		 struct tr_request *out, char *err, size_t errlen, int *cni_code);

/* Parse and validate a Netavark plugin invocation. args are the arguments
 * after the program name (args[0] is the sub command). */
int tr_parse_netavark(int nargs, char *const *args, const char *stdin_text,
		      struct tr_request *out, char *err, size_t errlen);

/* Format an error in the style the caller expects. Caller frees. */
char *tr_format_cni_error(const char *cni_version, int code, const char *msg, const char *details);
char *tr_format_netavark_error(const char *msg);

bool tr_cni_version_supported(const char *v);

#endif
