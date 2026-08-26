// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#ifndef __FWX_APP_FILTER_H__
#define __FWX_APP_FILTER_H__

#include "fwx.h"

int fwx_app_filter_init(void);
void update_oaf_status(void);

struct json_object *fwx_api_get_filter_rules(struct json_object *req_obj);
struct json_object *fwx_api_add_filter_rule(struct json_object *req_obj);
struct json_object *fwx_api_update_filter_rule(struct json_object *req_obj);
struct json_object *fwx_api_delete_filter_rule(struct json_object *req_obj);


struct json_object *fwx_api_get_appfilter_whitelist(struct json_object *req_obj);
struct json_object *fwx_api_del_appfilter_whitelist(struct json_object *req_obj);
struct json_object *fwx_api_add_appfilter_whitelist(struct json_object *req_obj);


struct json_object *fwx_api_get_app_filter_base(struct json_object *req_obj);
struct json_object *fwx_api_set_app_filter_base(struct json_object *req_obj);


struct json_object *fwx_api_get_app_filter_adv(struct json_object *req_obj);
struct json_object *fwx_api_set_app_filter_adv(struct json_object *req_obj);

#endif
