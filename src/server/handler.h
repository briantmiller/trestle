/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef TRESTLE_HANDLER_H
#define TRESTLE_HANDLER_H

#include "../common/config.h"

/* Serve one client connection: read request, check, act, respond. */
void handle_connection(const struct tr_config *cfg, int sock);

#endif
