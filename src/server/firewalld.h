/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * firewalld integration: put a network's bridge into the firewalld zone
 * named by firewalld_zone (runtime binding, like
 * "firewall-cmd --zone=Z --change-interface=BR").
 *
 * Runtime bindings disappear on "firewall-cmd --reload", so the binding is
 * checked again on every attach and on trestled start/reload. Nothing is
 * done when firewalld is not running.
 */
#ifndef TRESTLE_FIREWALLD_H
#define TRESTLE_FIREWALLD_H

#include "../common/config.h"

/* Make sure net->bridge is in net->firewalld_zone. 0 = ok or nothing to do. */
int fwd_bind(const struct tr_config *cfg, const struct tr_network *net);

/* Remove the bridge from its zone (before the bridge is deleted). */
void fwd_unbind(const struct tr_config *cfg, const struct tr_network *net);

/* fwd_bind() for every known network whose bridge exists (start/reload). */
void fwd_bind_all(const struct tr_config *cfg);

#endif
