/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "harness.h"

#include <sys/stat.h>
#include <unistd.h>

#include "common/config.h"
#include "common/log.h"
#include "server/firewalld.h"

static char dir[256], fwcmd[512], zonefile[512], logfile[512], runfile[512];

/* Fake firewall-cmd keeping one interface->zone binding in a file. */
static void install_fake(void)
{
	char body[2048];
	snprintf(body, sizeof(body),
		 "#!/bin/sh\n"
		 "echo \"$*\" >> %s\n"
		 "[ -f %s ] || { echo 'FirewallD is not running'; exit 252; }\n"
		 "case \"$1\" in\n"
		 "--get-zone-of-interface=*) if [ -s %s ]; then cat %s; exit 0; fi; echo 'no zone'; exit 2 ;;\n"
		 "--zone=*) z=${1#--zone=}\n"
		 "  case \"$2\" in\n"
		 "  --change-interface=*) echo \"$z\" > %s; echo success ;;\n"
		 "  --remove-interface=*) : > %s; echo success ;;\n"
		 "  esac ;;\n"
		 "esac\n", logfile, runfile, zonefile, zonefile, zonefile, zonefile);
	FILE *f = fopen(fwcmd, "w");
	fputs(body, f);
	fclose(f);
	chmod(fwcmd, 0755);
}

static void set_running(bool on)
{
	if (on) {
		FILE *f = fopen(runfile, "w");
		fclose(f);
	} else {
		unlink(runfile);
	}
}

static void set_zone(const char *z)
{
	FILE *f = fopen(zonefile, "w");
	if (z && *z)
		fprintf(f, "%s\n", z);
	fclose(f);
}

static char *read_zone(void)
{
	char *t = tr_read_file(zonefile, 256, NULL);
	if (t)
		tr_trim(t);
	return t;
}

static int log_lines(void)
{
	char *t = tr_read_file(logfile, 65536, NULL);
	int n = 0;
	for (char *p = t; p && *p; p++)
		n += *p == '\n';
	free(t);
	return n;
}

static void test_config(void)
{
	struct tr_config c;
	char err[256] = "";
	config_defaults(&c);
	CHECK_STR(c.firewall_cmd, "/usr/bin/firewall-cmd");
	CHECK(config_parse_text(&c, "[global]\nfirewall_cmd=/opt/fw\n[network:a]\nusers=*\nfirewalld_zone=trusted\n"
				"[network:*]\nusers=*\nfirewalld_zone=internal\n", "t", err, sizeof(err)) == 0);
	CHECK(config_finalize(&c, err, sizeof(err)) == 0);
	CHECK_STR(c.firewall_cmd, "/opt/fw");
	CHECK_STR(c.nets[0].firewalld_zone, "trusted");
	struct tr_network w;
	CHECK(config_wildcard_instance(&c, "x", &w));
	CHECK_STR(w.firewalld_zone, "internal");          /* inherited by [network:*] networks */
	CHECK(config_parse_text(&c, "[network:a]\nfirewalld_zone=bad zone\n", "t", err, sizeof(err)) < 0);
	CHECK(config_parse_text(&c, "[global]\nfirewall_cmd=firewall-cmd\n", "t", err, sizeof(err)) < 0);
	config_free(&c);
}

static void test_bind(void)
{
	snprintf(dir, sizeof(dir), "%s", t_tmpdir());
	snprintf(fwcmd, sizeof(fwcmd), "%s/firewall-cmd", dir);
	snprintf(zonefile, sizeof(zonefile), "%s/zone", dir);
	snprintf(logfile, sizeof(logfile), "%s/log", dir);
	snprintf(runfile, sizeof(runfile), "%s/running", dir);
	install_fake();

	struct tr_config c;
	config_defaults(&c);
	tr_strlcpy(c.firewall_cmd, fwcmd, sizeof(c.firewall_cmd));
	struct tr_network n = { 0 };
	strcpy(n.name, "lab");
	strcpy(n.bridge, "tbr0123456789ab");

	/* no zone configured: firewall-cmd is never called */
	set_running(true);
	CHECK(fwd_bind(&c, &n) == 0);
	CHECK(log_lines() == 0);

	strcpy(n.firewalld_zone, "trusted");
	set_zone("");
	CHECK(fwd_bind(&c, &n) == 0);
	char *z = read_zone();
	CHECK_STR(z, "trusted");
	free(z);
	int calls = log_lines();
	CHECK(calls == 2);                        /* query + change */

	/* already in the zone: only the query */
	CHECK(fwd_bind(&c, &n) == 0);
	CHECK(log_lines() == calls + 1);

	/* in another zone (e.g. after firewall-cmd --reload put it back in
	 * the default zone): moved */
	set_zone("public");
	CHECK(fwd_bind(&c, &n) == 0);
	z = read_zone();
	CHECK_STR(z, "trusted");
	free(z);

	/* unbind only removes our own zone */
	set_zone("public");
	fwd_unbind(&c, &n);
	z = read_zone();
	CHECK_STR(z, "public");
	free(z);
	set_zone("trusted");
	fwd_unbind(&c, &n);
	z = read_zone();
	CHECK(z && !*z);
	free(z);

	/* firewalld not running: nothing happens, no error */
	set_running(false);
	set_zone("");
	CHECK(fwd_bind(&c, &n) == 0);
	z = read_zone();
	CHECK(z && !*z);
	free(z);

	/* firewall-cmd missing */
	tr_strlcpy(c.firewall_cmd, "/nonexistent/firewall-cmd", sizeof(c.firewall_cmd));
	CHECK(fwd_bind(&c, &n) < 0);
	config_free(&c);
	t_rmrf(dir);
}

int main(void)
{
	tlog_init("test", TLOG_STDERR, LOG_ERR);
	RUN(test_config);
	RUN(test_bind);
	TEST_MAIN_END();
}
