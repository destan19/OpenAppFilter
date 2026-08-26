// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef __FWX_FEATURE_H__
#define __FWX_FEATURE_H__

#include <stddef.h>

#define FWX_FEATURE_BIN_PATH "/etc/fwxd/feature.bin"
#define FWX_FEATURE_BACKUP_PATH "/etc/fwxd/feature.bin.bak"
#define FWX_FEATURE_LIST_CACHE_PATH "/etc/fwxd/feature_list.json"
#define FWX_FEATURE_CANDIDATE_PATH "/tmp/feature.bin"
#define FWX_FEATURE_INFO_PATH "/tmp/feature_info.json"
#define FWX_FEATURE_UPGRADE_STATUS_PATH "/tmp/feature_upgrade.status"
#define FWX_FEATURE_DATA_FORMAT "v4.0"
#define FWX_FEATURE_MAX_SIZE (20U * 1024U * 1024U)

#define FWX_FEATURE_VALIDATE_DECRYPT_FAILED -1
#define FWX_FEATURE_VALIDATE_INFO_INVALID -2
#define FWX_FEATURE_APPLY_BACKUP_FAILED -1
#define FWX_FEATURE_APPLY_TARGET_FAILED -2

int fwx_feature_decrypt_file(const char *path, char **data, size_t *data_len);
int fwx_feature_validate_candidate(char *version, size_t version_len,
                                   char *format, size_t format_len);
int fwx_feature_apply_candidate(void);
int fwx_feature_restore_backup(void);
int fwx_feature_process_candidate(char *version, size_t version_len,
                                  char *format, size_t format_len,
                                  int *status_code,
                                  void (*stage_callback)(const char *stage));
int test_encrypt_feature_file(void);

void fwx_feature_replace_data(char *data, size_t data_len);
const char *fwx_feature_get_data(size_t *data_len);
int fwx_feature_next_line(const char *data, size_t data_len, size_t *offset,
                          char *line, size_t line_size);

#endif
