/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Running helper programs (nmcli, firewall-cmd). */
#ifndef TRESTLE_EXEC_H
#define TRESTLE_EXEC_H

#include "../common/util.h"

long tr_now_ms(void);
void tr_sleep_ms(long ms);

/* Run argv[0] (absolute path, no shell) with a minimal environment and a
 * timeout. stdout and stderr are captured into out (may be NULL, at most
 * 8 KiB). Returns the exit status, or -1 if it could not run, was killed
 * or timed out. */
int tr_run_cmd(char *const argv[], int timeout_ms, struct buf *out);

#endif
