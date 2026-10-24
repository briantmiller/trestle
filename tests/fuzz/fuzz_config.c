/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Fuzz the configuration parser, the hosts-file block editor and the
 * nftables ruleset generator fed by whatever configuration parses. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/config.h"
#include "common/log.h"
#include "server/dnsout.h"
#include "server/nft.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int init;
	if (!init) {
		tlog_init("fuzz", TLOG_STDERR, LOG_EMERG);
		init = 1;
	}
	if (size > 65536)
		return 0;
	char *s = malloc(size + 1);
	memcpy(s, data, size);
	s[size] = '\0';

	struct tr_config c;
	char err[512];
	config_defaults(&c);
	tr_strlcpy(c.state_dir, "/nonexistent-trestle-fuzz", sizeof(c.state_dir));
	if (config_parse_text(&c, s, "fuzz", err, sizeof(err)) == 0 &&
	    config_finalize(&c, err, sizeof(err)) == 0) {
		struct buf b = { 0 };
		nft_build_ruleset(&c, &b);
		buf_free(&b);
	}
	config_free(&c);

	char *h = hosts_replace_block(s, "10.0.0.2\tx.y.z.trestle\n");
	free(h);
	h = hosts_replace_block(s, "");
	free(h);
	free(s);
	return 0;
}
