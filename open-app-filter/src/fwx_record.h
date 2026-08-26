// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#ifndef __FWX_RECORD_H__
#define __FWX_RECORD_H__

#include "fwx.h"

struct json_object *fwx_api_get_record_whitelist(struct json_object *req_obj);
struct json_object *fwx_api_add_record_whitelist(struct json_object *req_obj);
struct json_object *fwx_api_del_record_whitelist(struct json_object *req_obj);
struct json_object *fwx_api_set_record_whitelist(struct json_object *req_obj);

#endif
