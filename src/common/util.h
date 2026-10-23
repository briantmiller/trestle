/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TRESTLE_UTIL_H
#define TRESTLE_UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define TR_IFNAMSIZ 16          /* IFNAMSIZ incl. NUL */
#define TR_MAX_NAME 64          /* max network / container / user name */

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* --- strings --------------------------------------------------------- */
size_t tr_strlcpy(char *dst, const char *src, size_t size);
char *tr_trim(char *s);
bool tr_streq(const char *a, const char *b);
bool tr_parse_bool(const char *s, bool *out);
bool tr_parse_int(const char *s, long min, long max, long *out);

/* Growable list of strings. */
struct strv {
	char **v;
	size_t n;
};
void strv_push(struct strv *l, const char *s);
void strv_split_push(struct strv *l, const char *csv); /* split on ',' and whitespace */
void strv_clear(struct strv *l);
bool strv_contains(const struct strv *l, const char *s);

/* Growable byte buffer. */
struct buf {
	char *p;
	size_t len, cap;
};
void buf_append(struct buf *b, const char *s, size_t n);
void buf_printf(struct buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void buf_free(struct buf *b);

/* --- validation ------------------------------------------------------ */
bool tr_valid_network_name(const char *s);   /* [A-Za-z0-9][A-Za-z0-9_.-]{0,63} */
bool tr_valid_container_name(const char *s); /* same charset, <=64 */
bool tr_valid_container_id(const char *s);   /* [A-Za-z0-9_.-]{1,128} */
bool tr_valid_ifname(const char *s);         /* 1..15 chars, no '/', ':', ws */
bool tr_valid_hostname_label(const char *s); /* [A-Za-z0-9_-], <=63 */
bool tr_valid_mac(const char *s, uint8_t out[6]);

/* --- IPv4 ------------------------------------------------------------ */
struct tr_ipv4net {
	uint32_t addr;   /* host byte order, the address as written */
	uint8_t prefix;
};
bool tr_parse_ipv4(const char *s, uint32_t *out);           /* host order */
bool tr_parse_ipv4_cidr(const char *s, struct tr_ipv4net *out);
void tr_fmt_ipv4(uint32_t addr, char out[16]);
uint32_t tr_prefix_mask(uint8_t prefix);

/* --- files ----------------------------------------------------------- */
int tr_mkdir_p(const char *path, mode_t mode);
/* Atomically replace path with data (tmp file + fsync + rename). Keeps the
 * mode given. Returns 0 or -errno. */
int tr_write_file_atomic(const char *path, const char *data, size_t len, mode_t mode);
/* Read whole file (NUL-terminated). Returns NULL and sets errno on error. */
char *tr_read_file(const char *path, size_t max, size_t *len_out);

/* --- misc ------------------------------------------------------------ */
/* Is the calling process inside a non-initial user namespace? */
bool tr_in_user_namespace(void);
uid_t tr_overflow_uid(void);

#endif
