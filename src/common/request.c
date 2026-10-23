/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "request.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(char *err, size_t errlen, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static int fail(char *err, size_t errlen, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(err, errlen, fmt, ap);
	va_end(ap);
	return -1;
}

void tr_request_free(struct tr_request *r)
{
	strv_clear(&r->static_ips);
	strv_clear(&r->aliases);
	if (r->input)
		json_object_put(r->input);
	r->input = NULL;
}

bool tr_cni_version_supported(const char *v)
{
	static const char *ok[] = { "0.3.0", "0.3.1", "0.4.0", "1.0.0" };
	for (size_t i = 0; i < ARRAY_SIZE(ok); i++)
		if (tr_streq(v, ok[i]))
			return true;
	return false;
}

static json_object *parse_json_object(const char *text, char *err, size_t errlen)
{
	enum json_tokener_error jerr;
	json_tokener *tok;
	json_object *o;

	if (!text || !*text) {
		fail(err, errlen, "no JSON received on stdin");
		return NULL;
	}
	tok = json_tokener_new();
	if (!tok) {
		fail(err, errlen, "out of memory");
		return NULL;
	}
	size_t len = strlen(text);
	o = json_tokener_parse_ex(tok, text, (int)len);
	jerr = json_tokener_get_error(tok);
	if (!o || jerr != json_tokener_success) {
		fail(err, errlen, "stdin is not valid JSON: %s",
		     jerr == json_tokener_continue ? "unexpected end of input" : json_tokener_error_desc(jerr));
		json_tokener_free(tok);
		if (o)
			json_object_put(o);
		return NULL;
	}
	/* reject trailing garbage (whitespace is fine) */
#if defined(JSON_C_VERSION_NUM) && JSON_C_VERSION_NUM >= ((0 << 16) | (15 << 8))
	size_t off = json_tokener_get_parse_end(tok);
#else
	size_t off = (size_t)tok->char_offset;   /* json-c 0.13/0.14 (RHEL 8/9) */
#endif
	json_tokener_free(tok);
	for (; off < len; off++)
		if (!strchr(" \t\r\n", text[off])) {
			json_object_put(o);
			fail(err, errlen, "stdin contains trailing data after the JSON document");
			return NULL;
		}
	if (!json_object_is_type(o, json_type_object)) {
		json_object_put(o);
		fail(err, errlen, "stdin JSON must be an object");
		return NULL;
	}
	return o;
}

static const char *jstr(json_object *o, const char *key)
{
	json_object *v;
	if (!o || !json_object_object_get_ex(o, key, &v) || !json_object_is_type(v, json_type_string))
		return NULL;
	return json_object_get_string(v);
}

static json_object *jobj(json_object *o, const char *key, json_type t)
{
	json_object *v;
	if (!o || !json_object_object_get_ex(o, key, &v) || !json_object_is_type(v, t))
		return NULL;
	return v;
}

/* "K=V;K2=V2" */
static void cni_args_get(const char *args, const char *key, char *out, size_t outlen)
{
	out[0] = '\0';
	if (!args)
		return;
	size_t kl = strlen(key);
	const char *p = args;
	while (*p) {
		const char *end = strchr(p, ';');
		size_t l = end ? (size_t)(end - p) : strlen(p);
		if (l > kl && !strncmp(p, key, kl) && p[kl] == '=') {
			size_t vl = l - kl - 1;
			if (vl >= outlen)
				vl = outlen - 1;
			memcpy(out, p + kl + 1, vl);
			out[vl] = '\0';
			return;
		}
		if (!end)
			break;
		p = end + 1;
	}
}

static int add_static_ip(struct tr_request *r, const char *s, char *err, size_t errlen)
{
	char tmp[64];
	uint32_t a;
	tr_strlcpy(tmp, s, sizeof(tmp));
	char *slash = strchr(tmp, '/');
	if (slash)
		*slash = '\0';
	if (!tr_parse_ipv4(tmp, &a))
		return fail(err, errlen, "requested IP '%s' is not a valid IPv4 address", s);
	if (!strv_contains(&r->static_ips, tmp))
		strv_push(&r->static_ips, tmp);
	return 0;
}

int tr_parse_cni(tr_env_fn getenv_fn, void *ctx, const char *stdin_text,
		 struct tr_request *out, char *err, size_t errlen, int *cni_code)
{
	memset(out, 0, sizeof(*out));
	out->mode = TR_MODE_CNI;
	*cni_code = CNI_ERR_INVALID_ENV;

	const char *cmd = getenv_fn(ctx, "CNI_COMMAND");
	if (!cmd || !*cmd)
		return fail(err, errlen, "CNI_COMMAND is not set");
	if (!strcmp(cmd, "ADD"))
		out->cmd = TR_CMD_CNI_ADD;
	else if (!strcmp(cmd, "DEL"))
		out->cmd = TR_CMD_CNI_DEL;
	else if (!strcmp(cmd, "CHECK"))
		out->cmd = TR_CMD_CNI_CHECK;
	else if (!strcmp(cmd, "VERSION"))
		out->cmd = TR_CMD_CNI_VERSION;
	else
		return fail(err, errlen, "unsupported CNI_COMMAND '%s'", cmd);
	tr_strlcpy(out->command, cmd, sizeof(out->command));

	if (out->cmd == TR_CMD_CNI_VERSION) {
		tr_strlcpy(out->cni_version, "1.0.0", sizeof(out->cni_version));
		/* stdin may carry {"cniVersion": "..."}; validate if present */
		if (stdin_text && *stdin_text) {
			out->input = parse_json_object(stdin_text, err, errlen);
			if (!out->input) {
				*cni_code = CNI_ERR_DECODE;
				return -1;
			}
		}
		return 0;
	}

	const char *cid = getenv_fn(ctx, "CNI_CONTAINERID");
	const char *netns = getenv_fn(ctx, "CNI_NETNS");
	const char *ifname = getenv_fn(ctx, "CNI_IFNAME");
	const char *args = getenv_fn(ctx, "CNI_ARGS");
	const char *path = getenv_fn(ctx, "CNI_PATH");

	if (!cid || !tr_valid_container_id(cid))
		return fail(err, errlen, "CNI_CONTAINERID is missing or invalid");
	tr_strlcpy(out->container_id, cid, sizeof(out->container_id));
	if (!ifname || !tr_valid_ifname(ifname))
		return fail(err, errlen, "CNI_IFNAME is missing or invalid");
	tr_strlcpy(out->ifname, ifname, sizeof(out->ifname));
	if (out->cmd != TR_CMD_CNI_DEL) {
		if (!netns || !*netns)
			return fail(err, errlen, "CNI_NETNS is required for %s", cmd);
		if (!path || !*path)
			return fail(err, errlen, "CNI_PATH is required for %s", cmd);
	}
	if (netns && *netns) {
		if (netns[0] != '/' || strlen(netns) >= sizeof(out->netns_path))
			return fail(err, errlen, "CNI_NETNS must be an absolute path");
		tr_strlcpy(out->netns_path, netns, sizeof(out->netns_path));
	}

	*cni_code = CNI_ERR_DECODE;
	out->input = parse_json_object(stdin_text, err, errlen);
	if (!out->input)
		return -1;

	*cni_code = CNI_ERR_INVALID_CONFIG;
	const char *ver = jstr(out->input, "cniVersion");
	if (!ver)
		return fail(err, errlen, "network configuration has no cniVersion");
	tr_strlcpy(out->cni_version, ver, sizeof(out->cni_version));
	if (!tr_cni_version_supported(ver)) {
		*cni_code = CNI_ERR_INCOMPATIBLE_VERSION;
		return fail(err, errlen, "unsupported cniVersion '%s'", ver);
	}
	if (out->cmd == TR_CMD_CNI_CHECK && strcmp(ver, "0.4.0") < 0) {
		*cni_code = CNI_ERR_INCOMPATIBLE_VERSION;
		return fail(err, errlen, "CHECK requires cniVersion >= 0.4.0");
	}
	const char *name = jstr(out->input, "name");
	if (!name || !tr_valid_network_name(name))
		return fail(err, errlen, "network configuration has a missing or invalid 'name'");
	tr_strlcpy(out->network, name, sizeof(out->network));
	if (!jstr(out->input, "type"))
		return fail(err, errlen, "network configuration has no 'type'");

	/* container name: <namespace>-<pod> from CNI_ARGS, else short container id */
	char pod[TR_MAX_NAME + 1], ns[TR_MAX_NAME + 1], ip[64], mac[32];
	cni_args_get(args, "K8S_POD_NAME", pod, sizeof(pod));
	cni_args_get(args, "K8S_POD_NAMESPACE", ns, sizeof(ns));
	cni_args_get(args, "IP", ip, sizeof(ip));
	cni_args_get(args, "MAC", mac, sizeof(mac));
	if (pod[0] && tr_valid_container_name(pod))
		tr_strlcpy(out->k8s_pod_name, pod, sizeof(out->k8s_pod_name));
	if (ns[0] && tr_valid_container_name(ns))
		tr_strlcpy(out->k8s_pod_namespace, ns, sizeof(out->k8s_pod_namespace));
	if (pod[0] && ns[0])
		snprintf(out->container_name, sizeof(out->container_name), "%s-%s", ns, pod);
	else if (pod[0])
		tr_strlcpy(out->container_name, pod, sizeof(out->container_name));
	else
		snprintf(out->container_name, sizeof(out->container_name), "%.12s", cid);
	if (!tr_valid_container_name(out->container_name)) {
		*cni_code = CNI_ERR_INVALID_ENV;
		return fail(err, errlen, "derived container name '%s' is invalid", out->container_name);
	}

	*cni_code = CNI_ERR_INVALID_CONFIG;
	if (ip[0])
		for (char *save = NULL, *t = strtok_r(ip, ",", &save); t; t = strtok_r(NULL, ",", &save))
			if (add_static_ip(out, t, err, errlen) < 0)
				return -1;
	json_object *rc = jobj(out->input, "runtimeConfig", json_type_object);
	json_object *ips = jobj(rc, "ips", json_type_array);
	for (size_t i = 0; ips && i < json_object_array_length(ips); i++) {
		json_object *e = json_object_array_get_idx(ips, i);
		if (!json_object_is_type(e, json_type_string))
			return fail(err, errlen, "runtimeConfig.ips must be strings");
		if (add_static_ip(out, json_object_get_string(e), err, errlen) < 0)
			return -1;
	}
	const char *rmac = jstr(rc, "mac");
	if (rmac)
		tr_strlcpy(mac, rmac, sizeof(mac));
	if (mac[0]) {
		uint8_t m[6];
		if (!tr_valid_mac(mac, m))
			return fail(err, errlen, "requested MAC '%s' is invalid", mac);
		tr_strlcpy(out->static_mac, mac, sizeof(out->static_mac));
	}
	*cni_code = 0;
	return 0;
}

int tr_parse_netavark(int nargs, char *const *args, const char *stdin_text,
		      struct tr_request *out, char *err, size_t errlen)
{
	memset(out, 0, sizeof(*out));
	out->mode = TR_MODE_NETAVARK;

	if (nargs < 1)
		return fail(err, errlen, "no sub command given");
	const char *cmd = args[0];
	if (!strcmp(cmd, "create"))
		out->cmd = TR_CMD_NV_CREATE;
	else if (!strcmp(cmd, "setup"))
		out->cmd = TR_CMD_NV_SETUP;
	else if (!strcmp(cmd, "teardown"))
		out->cmd = TR_CMD_NV_TEARDOWN;
	else if (!strcmp(cmd, "info"))
		out->cmd = TR_CMD_NV_INFO;
	else
		return fail(err, errlen, "unknown subcommand: %s", cmd);
	tr_strlcpy(out->command, cmd, sizeof(out->command));

	if (out->cmd == TR_CMD_NV_INFO) {
		if (nargs > 1)
			return fail(err, errlen, "info takes no arguments");
		return 0;
	}
	if (out->cmd == TR_CMD_NV_CREATE) {
		if (nargs != 1)
			return fail(err, errlen, "create takes no arguments");
	} else {
		if (nargs < 2)
			return fail(err, errlen, "netns path argument is missing");
		if (nargs > 2)
			return fail(err, errlen, "too many arguments for %s", cmd);
		if (args[1][0] != '/' || strlen(args[1]) >= sizeof(out->netns_path))
			return fail(err, errlen, "netns path must be an absolute path");
		tr_strlcpy(out->netns_path, args[1], sizeof(out->netns_path));
	}

	out->input = parse_json_object(stdin_text, err, errlen);
	if (!out->input)
		return -1;

	if (out->cmd == TR_CMD_NV_CREATE) {
		const char *name = jstr(out->input, "name");
		if (!name || !tr_valid_network_name(name))
			return fail(err, errlen, "network config has a missing or invalid 'name'");
		if (!jstr(out->input, "id") || !jstr(out->input, "driver"))
			return fail(err, errlen, "network config requires 'id' and 'driver'");
		tr_strlcpy(out->network, name, sizeof(out->network));
		return 0;
	}

	/* setup / teardown: NetworkPluginExec */
	const char *cid = jstr(out->input, "container_id");
	const char *cname = jstr(out->input, "container_name");
	json_object *net = jobj(out->input, "network", json_type_object);
	json_object *opts = jobj(out->input, "network_options", json_type_object);
	if (!cid || !tr_valid_container_id(cid))
		return fail(err, errlen, "missing or invalid container_id");
	if (!cname || !tr_valid_container_name(cname))
		return fail(err, errlen, "missing or invalid container_name");
	if (!net || !opts)
		return fail(err, errlen, "'network' and 'network_options' objects are required");
	const char *name = jstr(net, "name");
	if (!name || !tr_valid_network_name(name))
		return fail(err, errlen, "network has a missing or invalid 'name'");
	const char *ifn = jstr(opts, "interface_name");
	if (!ifn || !tr_valid_ifname(ifn))
		return fail(err, errlen, "network_options.interface_name is missing or invalid");

	tr_strlcpy(out->container_id, cid, sizeof(out->container_id));
	tr_strlcpy(out->container_name, cname, sizeof(out->container_name));
	tr_strlcpy(out->network, name, sizeof(out->network));
	tr_strlcpy(out->ifname, ifn, sizeof(out->ifname));

	json_object *ips = jobj(opts, "static_ips", json_type_array);
	for (size_t i = 0; ips && i < json_object_array_length(ips); i++) {
		json_object *e = json_object_array_get_idx(ips, i);
		if (!json_object_is_type(e, json_type_string))
			return fail(err, errlen, "static_ips must be strings");
		const char *s = json_object_get_string(e);
		if (strchr(s, ':'))
			continue;  /* IPv6 is not supported yet; ignore */
		if (add_static_ip(out, s, err, errlen) < 0)
			return -1;
	}
	const char *mac = jstr(opts, "static_mac");
	if (mac && *mac) {
		uint8_t m[6];
		if (!tr_valid_mac(mac, m))
			return fail(err, errlen, "static_mac '%s' is invalid", mac);
		tr_strlcpy(out->static_mac, mac, sizeof(out->static_mac));
	}
	json_object *al = jobj(opts, "aliases", json_type_array);
	for (size_t i = 0; al && i < json_object_array_length(al); i++) {
		json_object *e = json_object_array_get_idx(al, i);
		if (json_object_is_type(e, json_type_string) &&
		    tr_valid_container_name(json_object_get_string(e)))
			strv_push(&out->aliases, json_object_get_string(e));
	}
	return 0;
}

char *tr_format_cni_error(const char *cni_version, int code, const char *msg, const char *details)
{
	json_object *o = json_object_new_object();
	json_object_object_add(o, "cniVersion",
			       json_object_new_string(cni_version && *cni_version ? cni_version : "1.0.0"));
	json_object_object_add(o, "code", json_object_new_int(code));
	json_object_object_add(o, "msg", json_object_new_string(msg ? msg : "error"));
	if (details && *details)
		json_object_object_add(o, "details", json_object_new_string(details));
	char *s = strdup(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE));
	json_object_put(o);
	return s;
}

char *tr_format_netavark_error(const char *msg)
{
	json_object *o = json_object_new_object();
	json_object_object_add(o, "error", json_object_new_string(msg ? msg : "error"));
	char *s = strdup(json_object_to_json_string_ext(o, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE));
	json_object_put(o);
	return s;
}
