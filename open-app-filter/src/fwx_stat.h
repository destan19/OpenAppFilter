// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>
 */

#ifndef __FWX_STAT_H__
#define __FWX_STAT_H__

#include <json-c/json.h>

int fwx_stat_read_conntrack_count(void);
void fwx_session_stat_tick(void);
struct json_object *fwx_api_get_history_session(struct json_object *req_obj);

#endif
