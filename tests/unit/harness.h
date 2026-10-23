/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Tiny self-contained unit test harness. */
#ifndef TRESTLE_TEST_HARNESS_H
#define TRESTLE_TEST_HARNESS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int t_fail, t_pass;

#define CHECK(cond) do { \
	if (cond) { t_pass++; } \
	else { t_fail++; fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } \
} while (0)

#define CHECK_STR(a, b) do { \
	const char *_a = (a), *_b = (b); \
	if (_a && _b && strcmp(_a, _b) == 0) { t_pass++; } \
	else { t_fail++; fprintf(stderr, "  FAIL %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, \
				  _a ? _a : "(null)", _b ? _b : "(null)"); } \
} while (0)

#define CHECK_CONTAINS(hay, needle) do { \
	const char *_h = (hay), *_n = (needle); \
	if (_h && strstr(_h, _n)) { t_pass++; } \
	else { t_fail++; fprintf(stderr, "  FAIL %s:%d: \"%s\" not found in \"%s\"\n", __FILE__, __LINE__, \
				  _n, _h ? _h : "(null)"); } \
} while (0)

#define RUN(fn) do { fprintf(stderr, "  %s\n", #fn); fn(); } while (0)

#define TEST_MAIN_END() do { \
	fprintf(stderr, "  %d passed, %d failed\n", t_pass, t_fail); \
	return t_fail ? 1 : 0; \
} while (0)

/* make a private temp directory */
static inline char *t_tmpdir(void)
{
	static char buf[256];
	snprintf(buf, sizeof(buf), "/tmp/trestle-unit-XXXXXX");
	if (!mkdtemp(buf)) {
		perror("mkdtemp");
		exit(2);
	}
	return buf;
}

static inline void t_rmrf(const char *dir)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
	if (system(cmd) != 0)
		fprintf(stderr, "warning: cleanup of %s failed\n", dir);
}

#endif
