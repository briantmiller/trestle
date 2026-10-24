/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include "exec.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

long tr_now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

void tr_sleep_ms(long ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
	while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
		;
}

int tr_run_cmd(char *const argv[], int timeout_ms, struct buf *out)
{
	int p[2];
	if (pipe2(p, O_CLOEXEC) < 0)
		return -1;
	pid_t pid = fork();
	if (pid < 0) {
		close(p[0]);
		close(p[1]);
		return -1;
	}
	if (pid == 0) {
		signal(SIGPIPE, SIG_DFL);
		signal(SIGHUP, SIG_DFL);
		int null = open("/dev/null", O_RDONLY);
		if (null > 0) {
			dup2(null, 0);
			close(null);
		}
		dup2(p[1], 1);
		dup2(p[1], 2);
		char *env[] = { "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", NULL };
		execve(argv[0], argv, env);
		_exit(127);
	}
	close(p[1]);
	long deadline = tr_now_ms() + timeout_ms;
	bool timed_out = false;
	for (;;) {
		long left = deadline - tr_now_ms();
		if (left <= 0) {
			timed_out = true;
			kill(pid, SIGKILL);
			break;
		}
		struct pollfd pf = { .fd = p[0], .events = POLLIN };
		int r = poll(&pf, 1, (int)left);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			continue;
		char chunk[1024];
		ssize_t n = read(p[0], chunk, sizeof(chunk));
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		if (out && out->len < 8192)
			buf_append(out, chunk, (size_t)n);
	}
	close(p[0]);
	int status = 0;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	if (timed_out || !WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status);
}

