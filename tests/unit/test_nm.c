/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "harness.h"

#include <sys/stat.h>
#include <time.h>

#include "common/config.h"
#include "common/log.h"
#include "server/bridge.h"
#include "server/nm.h"

static void writefile(const char *path, const char *text, mode_t mode)
{
	char dir[512];
	snprintf(dir, sizeof(dir), "%s", path);
	*strrchr(dir, '/') = '\0';
	tr_mkdir_p(dir, 0755);
	FILE *f = fopen(path, "w");
	fputs(text, f);
	fclose(f);
	chmod(path, mode);
}

static void test_config(void)
{
	struct tr_config c;
	char err[256] = "";
	config_defaults(&c);
	CHECK(c.networkmanager == TR_NM_AUTO);
	CHECK_STR(c.nmcli_binary, "/usr/bin/nmcli");
	CHECK(config_parse_text(&c, "[global]\nnetworkmanager = no\nnmcli_binary = /opt/nmcli\n", "t", err, sizeof(err)) == 0);
	CHECK(c.networkmanager == TR_NM_NO);
	CHECK_STR(c.nmcli_binary, "/opt/nmcli");
	CHECK(config_parse_text(&c, "[global]\nnetworkmanager = yes\n", "t", err, sizeof(err)) == 0);
	CHECK(c.networkmanager == TR_NM_YES);
	CHECK(config_parse_text(&c, "[global]\nnetworkmanager = auto\n", "t", err, sizeof(err)) == 0);
	CHECK(c.networkmanager == TR_NM_AUTO);
	CHECK(config_parse_text(&c, "[global]\nnetworkmanager = maybe\n", "t", err, sizeof(err)) < 0);
	CHECK(config_parse_text(&c, "[global]\nnmcli_binary = nmcli\n", "t", err, sizeof(err)) < 0);
	config_free(&c);
}

static void test_profiles(void)
{
	char *root = t_tmpdir(), p[512];
	CHECK(!nm_profile_claims(root, "br1"));

	snprintf(p, sizeof(p), "%s/etc/NetworkManager/system-connections/br1.nmconnection", root);
	writefile(p, "[connection]\nid=lan\ntype=bridge\ninterface-name=br1\n", 0600);
	CHECK(nm_profile_claims(root, "br1"));
	CHECK(!nm_profile_claims(root, "br10"));       /* exact name, not a prefix */
	CHECK(!nm_profile_claims(root, "br"));

	snprintf(p, sizeof(p), "%s/run/NetworkManager/system-connections/x.nmconnection", root);
	writefile(p, "[connection]\ninterface-name = tbrabc\n", 0600);
	CHECK(nm_profile_claims(root, "tbrabc"));

	snprintf(p, sizeof(p), "%s/etc/sysconfig/network-scripts/ifcfg-br3", root);
	writefile(p, "TYPE=Bridge\nDEVICE=\"br3\"\nONBOOT=yes\n", 0644);
	CHECK(nm_profile_claims(root, "br3"));
	snprintf(p, sizeof(p), "%s/etc/sysconfig/network-scripts/route-br4", root);
	writefile(p, "DEVICE=br4\n", 0644);                  /* not an ifcfg file */
	CHECK(!nm_profile_claims(root, "br4"));

	/* the removal check uses the same profile detection */
	CHECK_STR(bridge_foreign_manager(root, "br3", 0), "NetworkManager");
	t_rmrf(root);
}

static void test_nmcli(void)
{
	char *dir = t_tmpdir(), nmcli[512], state[512], log[512], body[2048];
	struct tr_config c;
	config_defaults(&c);
	snprintf(nmcli, sizeof(nmcli), "%s/nmcli", dir);
	snprintf(state, sizeof(state), "%s/state", dir);
	snprintf(log, sizeof(log), "%s/log", dir);
	tr_strlcpy(c.nmcli_binary, nmcli, sizeof(c.nmcli_binary));

	/* fake nmcli: "running"; "device set" fails twice (device not known
	 * yet) and then succeeds */
	snprintf(body, sizeof(body),
		 "#!/bin/sh\n"
		 "echo \"$*\" >> %s\n"
		 "case \"$1 $2\" in\n"
		 "'-t -f') echo \"${NM_STATE:-running}\" ;;\n"
		 "'device set') n=$(cat %s 2>/dev/null || echo 0); n=$((n+1)); echo $n > %s;\n"
		 "  if [ $n -lt 3 ]; then echo \"Error: Device '$3' not found.\" >&2; exit 10; fi ;;\n"
		 "esac\n", log, state, state);
	writefile(nmcli, body, 0755);

	c.networkmanager = TR_NM_AUTO;
	CHECK(nm_should_unmanage(&c, "tbr123"));
	c.networkmanager = TR_NM_NO;
	CHECK(!nm_should_unmanage(&c, "tbr123"));
	c.networkmanager = TR_NM_YES;
	CHECK(nm_should_unmanage(&c, "tbr123"));

	CHECK(nm_set_unmanaged(&c, "tbr123") == 0);
	char *l = tr_read_file(log, 65536, NULL);
	CHECK_CONTAINS(l, "-t -f RUNNING general\n");
	CHECK_CONTAINS(l, "device set tbr123 managed no\n");
	free(l);

	/* NetworkManager not running */
	snprintf(body, sizeof(body), "#!/bin/sh\necho stopped\n");
	writefile(nmcli, body, 0755);
	c.networkmanager = TR_NM_AUTO;
	CHECK(!nm_should_unmanage(&c, "tbr123"));

	/* nmcli missing */
	tr_strlcpy(c.nmcli_binary, "/nonexistent/nmcli", sizeof(c.nmcli_binary));
	CHECK(!nm_should_unmanage(&c, "tbr123"));

	/* nmcli keeps failing: gives up after the retry period */
	snprintf(body, sizeof(body), "#!/bin/sh\necho 'Error: Device not found.' >&2\nexit 10\n");
	writefile(nmcli, body, 0755);
	tr_strlcpy(c.nmcli_binary, nmcli, sizeof(c.nmcli_binary));
	time_t t0 = time(NULL);
	CHECK(nm_set_unmanaged(&c, "tbr123") < 0);
	CHECK(time(NULL) - t0 <= 6);
	config_free(&c);
	t_rmrf(dir);
}

int main(void)
{
	tlog_init("test", TLOG_STDERR, LOG_ERR);
	RUN(test_config);
	RUN(test_profiles);
	RUN(test_nmcli);
	TEST_MAIN_END();
}
