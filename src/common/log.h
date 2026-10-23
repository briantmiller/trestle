/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TRESTLE_LOG_H
#define TRESTLE_LOG_H

#include <syslog.h>

/*
 * Logging. When started by systemd (JOURNAL_STREAM is set) messages are
 * written to stderr with sd-daemon "<N>" priority prefixes so journald
 * records the right priority. Otherwise they go to syslog (which on
 * systemd hosts is also journald) and, when running in the foreground,
 * to stderr.
 */
enum trestle_log_target {
	TLOG_STDERR,     /* plain stderr (client, foreground daemon) */
	TLOG_JOURNAL,    /* stderr with <N> prefixes for journald */
	TLOG_SYSLOG,     /* syslog(3) */
};

void tlog_init(const char *ident, enum trestle_log_target target, int level);
void tlog_set_level(int level);
int  tlog_get_level(void);
int  tlog_level_from_string(const char *s); /* -1 if unknown */
enum trestle_log_target tlog_detect_target(int foreground);

void tlog(int prio, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#define log_err(...)   tlog(LOG_ERR, __VA_ARGS__)
#define log_warn(...)  tlog(LOG_WARNING, __VA_ARGS__)
#define log_notice(...) tlog(LOG_NOTICE, __VA_ARGS__)
#define log_info(...)  tlog(LOG_INFO, __VA_ARGS__)
#define log_debug(...) tlog(LOG_DEBUG, __VA_ARGS__)

#endif
