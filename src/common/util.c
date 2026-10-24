/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

static void *xrealloc(void *p, size_t n)
{
	void *r = realloc(p, n);
	if (!r && n) {
		fputs("trestle: out of memory\n", stderr);
		abort();
	}
	return r;
}

size_t tr_strlcpy(char *dst, const char *src, size_t size)
{
	size_t len = strlen(src);
	if (size) {
		size_t n = len >= size ? size - 1 : len;
		memcpy(dst, src, n);
		dst[n] = '\0';
	}
	return len;
}

char *tr_trim(char *s)
{
	while (*s && isspace((unsigned char)*s))
		s++;
	char *e = s + strlen(s);
	while (e > s && isspace((unsigned char)e[-1]))
		*--e = '\0';
	return s;
}

bool tr_streq(const char *a, const char *b)
{
	return a && b && strcmp(a, b) == 0;
}

bool tr_parse_bool(const char *s, bool *out)
{
	static const char *t[] = { "1", "yes", "true", "on", "enable", "enabled" };
	static const char *f[] = { "0", "no", "false", "off", "disable", "disabled" };
	for (size_t i = 0; i < ARRAY_SIZE(t); i++)
		if (strcasecmp(s, t[i]) == 0) { *out = true; return true; }
	for (size_t i = 0; i < ARRAY_SIZE(f); i++)
		if (strcasecmp(s, f[i]) == 0) { *out = false; return true; }
	return false;
}

bool tr_parse_int(const char *s, long min, long max, long *out)
{
	char *end;
	errno = 0;
	long v = strtol(s, &end, 0);
	if (errno || end == s || *end || v < min || v > max)
		return false;
	*out = v;
	return true;
}

void strv_push(struct strv *l, const char *s)
{
	char *d = strdup(s);
	if (!d)
		abort();
	l->v = xrealloc(l->v, (l->n + 2) * sizeof(char *));
	l->v[l->n++] = d;
	l->v[l->n] = NULL;
}

void strv_split_push(struct strv *l, const char *csv)
{
	char *dup = strdup(csv), *save = NULL;
	if (!dup)
		abort();
	for (char *tok = strtok_r(dup, ", \t", &save); tok; tok = strtok_r(NULL, ", \t", &save))
		if (*tok)
			strv_push(l, tok);
	free(dup);
}

void strv_clear(struct strv *l)
{
	for (size_t i = 0; i < l->n; i++)
		free(l->v[i]);
	free(l->v);
	l->v = NULL;
	l->n = 0;
}

bool strv_contains(const struct strv *l, const char *s)
{
	for (size_t i = 0; i < l->n; i++)
		if (strcmp(l->v[i], s) == 0)
			return true;
	return false;
}

void buf_append(struct buf *b, const char *s, size_t n)
{
	if (b->len + n + 1 > b->cap) {
		size_t nc = b->cap ? b->cap : 256;
		while (nc < b->len + n + 1)
			nc *= 2;
		b->p = xrealloc(b->p, nc);
		b->cap = nc;
	}
	memcpy(b->p + b->len, s, n);
	b->len += n;
	b->p[b->len] = '\0';
}

void buf_printf(struct buf *b, const char *fmt, ...)
{
	va_list ap;
	char stackbuf[512];
	va_start(ap, fmt);
	int n = vsnprintf(stackbuf, sizeof(stackbuf), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if ((size_t)n < sizeof(stackbuf)) {
		buf_append(b, stackbuf, (size_t)n);
		return;
	}
	char *big = malloc((size_t)n + 1);
	if (!big)
		abort();
	va_start(ap, fmt);
	vsnprintf(big, (size_t)n + 1, fmt, ap);
	va_end(ap);
	buf_append(b, big, (size_t)n);
	free(big);
}

void buf_free(struct buf *b)
{
	free(b->p);
	b->p = NULL;
	b->len = b->cap = 0;
}

static bool charset_ok(const char *s, size_t maxlen, const char *extra, bool first_alnum)
{
	size_t n = 0;
	if (!s || !*s)
		return false;
	if (first_alnum && !isalnum((unsigned char)s[0]))
		return false;
	for (const char *p = s; *p; p++, n++) {
		if (n >= maxlen)
			return false;
		if (!isalnum((unsigned char)*p) && !strchr(extra, *p))
			return false;
	}
	return true;
}

bool tr_valid_network_name(const char *s) { return charset_ok(s, TR_MAX_NAME, "_.-", true); }
bool tr_valid_container_name(const char *s) { return charset_ok(s, TR_MAX_NAME, "_.-", true); }
/* used as a file name in the state directory: no ".", "..", hidden names */
bool tr_valid_container_id(const char *s) { return charset_ok(s, 128, "_.-", true); }
bool tr_valid_hostname_label(const char *s) { return charset_ok(s, 63, "_-", false); }

bool tr_valid_ifname(const char *s)
{
	if (!s || !*s || strlen(s) >= TR_IFNAMSIZ)
		return false;
	if (strcmp(s, ".") == 0 || strcmp(s, "..") == 0)
		return false;
	for (const char *p = s; *p; p++)
		/* quotes and backslashes are legal for the kernel but would end up
		 * in nftables rules and JSON; refuse them */
		if (*p == '/' || *p == ':' || *p == '"' || *p == '\'' || *p == '\\' ||
		    isspace((unsigned char)*p) || !isprint((unsigned char)*p))
			return false;
	return true;
}

bool tr_valid_mac(const char *s, uint8_t out[6])
{
	/* exactly xx:xx:xx:xx:xx:xx; sscanf("%2x") would also take signs and
	 * blanks ("+2: 0:..."), so parse by hand */
	if (!s || strlen(s) != 17)
		return false;
	for (int i = 0; i < 6; i++) {
		const char *p = s + 3 * i;
		if (!isxdigit((unsigned char)p[0]) || !isxdigit((unsigned char)p[1]) || (i < 5 && p[2] != ':'))
			return false;
		char hex[3] = { p[0], p[1], 0 };
		out[i] = (uint8_t)strtoul(hex, NULL, 16);
	}
	if (out[0] & 1)   /* multicast bit must be clear */
		return false;
	return true;
}

bool tr_parse_ipv4(const char *s, uint32_t *out)
{
	struct in_addr a;
	if (!s || inet_pton(AF_INET, s, &a) != 1)
		return false;
	*out = ntohl(a.s_addr);
	return true;
}

bool tr_parse_ipv4_cidr(const char *s, struct tr_ipv4net *out)
{
	char tmp[64];
	long p;
	if (!s || tr_strlcpy(tmp, s, sizeof(tmp)) >= sizeof(tmp))
		return false;
	char *slash = strchr(tmp, '/');
	if (!slash)
		return false;
	*slash = '\0';
	if (!tr_parse_ipv4(tmp, &out->addr) || !tr_parse_int(slash + 1, 0, 32, &p))
		return false;
	out->prefix = (uint8_t)p;
	return true;
}

void tr_fmt_ipv4(uint32_t addr, char out[16])
{
	struct in_addr a = { .s_addr = htonl(addr) };
	inet_ntop(AF_INET, &a, out, 16);
}

uint32_t tr_prefix_mask(uint8_t prefix)
{
	return prefix == 0 ? 0 : (uint32_t)(0xffffffffu << (32 - prefix));
}

int tr_mkdir_p(const char *path, mode_t mode)
{
	char tmp[PATH_MAX];
	if (tr_strlcpy(tmp, path, sizeof(tmp)) >= sizeof(tmp))
		return -ENAMETOOLONG;
	for (char *p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			if (mkdir(tmp, mode) < 0 && errno != EEXIST)
				return -errno;
			*p = '/';
		}
	}
	if (mkdir(tmp, mode) < 0 && errno != EEXIST)
		return -errno;
	return 0;
}

int tr_write_file_atomic(const char *path, const char *data, size_t len, mode_t mode)
{
	char tmp[PATH_MAX];
	int fd, err = 0;

	if (snprintf(tmp, sizeof(tmp), "%s.trestle-tmp.%d", path, (int)getpid()) >= (int)sizeof(tmp))
		return -ENAMETOOLONG;
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, mode);
	if (fd < 0)
		return -errno;
	/* honour the requested mode regardless of umask */
	if (fchmod(fd, mode) < 0)
		err = -errno;
	size_t off = 0;
	while (!err && off < len) {
		ssize_t w = write(fd, data + off, len - off);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			err = -errno;
			break;
		}
		off += (size_t)w;
	}
	if (!err && fsync(fd) < 0)
		err = -errno;
	if (close(fd) < 0 && !err)
		err = -errno;
	if (!err && rename(tmp, path) < 0)
		err = -errno;
	if (err)
		unlink(tmp);
	return err;
}

char *tr_read_file(const char *path, size_t max, size_t *len_out)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	struct buf b = { 0 };
	char chunk[4096];
	for (;;) {
		ssize_t r = read(fd, chunk, sizeof(chunk));
		if (r < 0) {
			if (errno == EINTR)
				continue;
			int e = errno;
			close(fd);
			buf_free(&b);
			errno = e;
			return NULL;
		}
		if (r == 0)
			break;
		if (b.len + (size_t)r > max) {
			close(fd);
			buf_free(&b);
			errno = EFBIG;
			return NULL;
		}
		buf_append(&b, chunk, (size_t)r);
	}
	close(fd);
	if (!b.p)
		buf_append(&b, "", 0);
	if (len_out)
		*len_out = b.len;
	return b.p;
}

bool tr_in_user_namespace(void)
{
	char *m = tr_read_file("/proc/self/uid_map", 4096, NULL);
	if (!m)
		return false;
	unsigned long inside, outside, count;
	bool initial = sscanf(m, "%lu %lu %lu", &inside, &outside, &count) == 3 &&
		       inside == 0 && outside == 0 && count == 4294967295UL;
	free(m);
	return !initial;
}

uid_t tr_overflow_uid(void)
{
	char *s = tr_read_file("/proc/sys/kernel/overflowuid", 64, NULL);
	long v = 65534;
	if (s) {
		long t;
		if (tr_parse_int(tr_trim(s), 0, INT_MAX, &t))
			v = t;
		free(s);
	}
	return (uid_t)v;
}

bool tr_has_ctrl(const char *s)
{
	for (; s && *s; s++)
		if ((unsigned char)*s < 0x20 || *s == 0x7f)
			return true;
	return false;
}

/* Does JSON text contain a \u0000 escape inside a string? json-c accepts it
 * but every consumer here uses C strings, which would silently cut the value
 * (or a key) at that point. */
bool tr_json_has_nul_escape(const char *s)
{
	bool in_str = false;
	for (; s && *s; s++) {
		if (!in_str) {
			if (*s == '"')
				in_str = true;
			continue;
		}
		if (*s == '"') {
			in_str = false;
		} else if (*s == '\\') {
			if (s[1] == 'u' && s[2] == '0' && s[3] == '0' && s[4] == '0' && s[5] == '0')
				return true;
			if (s[1])
				s++;
		}
	}
	return false;
}
