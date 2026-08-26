// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __FWX_FEATURE_ONLINE_H__
#define __FWX_FEATURE_ONLINE_H__

#include <json-c/json.h>

#define FWX_FEATURE_UPGRADE_LOCK_PATH "/tmp/feature_upgrade.lock"

int fwx_feature_online_init(void);
void fwx_feature_online_cleanup(void);
struct json_object *fwx_api_get_feature_online_config(struct json_object *req_obj);
struct json_object *fwx_api_set_feature_online_config(struct json_object *req_obj);
struct json_object *fwx_api_get_feature_online_list(struct json_object *req_obj);
struct json_object *fwx_api_start_feature_online_update(struct json_object *req_obj);
struct json_object *fwx_api_get_feature_online_update_status(struct json_object *req_obj);

#endif
