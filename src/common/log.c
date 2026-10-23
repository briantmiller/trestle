/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

static enum trestle_log_target g_target = TLOG_STDERR;
static int g_level = LOG_INFO;
static const char *g_ident = "trestle";

void tlog_init(const char *ident, enum trestle_log_target target, int level)
{
	g_ident = ident;
	g_target = target;
	g_level = level;
	if (target == TLOG_SYSLOG)
		openlog(ident, LOG_PID | LOG_NDELAY, LOG_DAEMON);
}

void tlog_set_level(int level) { g_level = level; }
int tlog_get_level(void) { return g_level; }

int tlog_level_from_string(const char *s)
{
	static const struct { const char *n; int l; } map[] = {
		{ "error", LOG_ERR }, { "err", LOG_ERR }, { "warning", LOG_WARNING },
		{ "warn", LOG_WARNING }, { "notice", LOG_NOTICE }, { "info", LOG_INFO },
		{ "debug", LOG_DEBUG },
	};
	for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); i++)
		if (strcasecmp(s, map[i].n) == 0)
			return map[i].l;
	return -1;
}

enum trestle_log_target tlog_detect_target(int foreground)
{
	if (getenv("JOURNAL_STREAM"))
		return TLOG_JOURNAL;
	return foreground ? TLOG_STDERR : TLOG_SYSLOG;
}

void tlog(int prio, const char *fmt, ...)
{
	char buf[2048];
	va_list ap;

	if (prio > g_level)
		return;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	switch (g_target) {
	case TLOG_SYSLOG:
		syslog(prio, "%s", buf);
		break;
	case TLOG_JOURNAL:
		fprintf(stderr, "<%d>%s\n", prio, buf);
		break;
	case TLOG_STDERR:
	default:
		fprintf(stderr, "%s: %s\n", g_ident, buf);
		break;
	}
}
