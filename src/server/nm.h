/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * NetworkManager integration for bridges that trestle creates.
 *
 * Before a bridge is created trestle checks whether NetworkManager is meant
 * to manage an interface of that name (a connection profile names it). If
 * not, and NetworkManager is running, the new bridge is handed to
 * "nmcli device set <bridge> managed no" right after it was created, so
 * NetworkManager does not take it over (addresses, DHCP, auto-connect).
 * The setting is runtime only, which matches the life time of the bridge.
 */
#ifndef TRESTLE_NM_H
#define TRESTLE_NM_H

#include <stdbool.h>

#include "../common/config.h"

/* Does a NetworkManager connection profile name this interface? Looks at
 * keyfiles (/etc and /run NetworkManager/system-connections) and legacy
 * ifcfg files. prefix redirects the paths for tests ("" normally). */
bool nm_profile_claims(const char *prefix, const char *ifname);

/* Should a bridge about to be created be marked unmanaged? false when the
 * integration is disabled, nmcli is missing, NetworkManager is not running
 * or a profile claims the name. Logs the reason. */
bool nm_should_unmanage(const struct tr_config *cfg, const char *ifname);

/* Run "nmcli device set <ifname> managed no", retrying for a short while
 * until NetworkManager has noticed the new device. 0 on success. */
int nm_set_unmanaged(const struct tr_config *cfg, const char *ifname);

#endif
