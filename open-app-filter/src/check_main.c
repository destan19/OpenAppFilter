
// SPDX-License-Identifier: GPL-2.0-or-later
/* 
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>  
*/
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "fwx.h"
#include "fwx_utils.h"
#include "check_main.h"

#define CHECK_INTERVAL 30
#define LOG_DIR_PATH "/tmp/log"
#define LOG_DIR_MAX_SIZE_KB 10240

static pthread_t check_thread;
static int check_thread_running = 0;
static int check_thread_exit = 0;

static void check_and_cleanup_log_dir(void) {
    char cmd_buf[256];
    char result_buf[64];
    memset(result_buf, 0, sizeof(result_buf));
    snprintf(cmd_buf, sizeof(cmd_buf), "du -sk %s 2>/dev/null | awk '{print $1}'", LOG_DIR_PATH);
    exec_with_result_line(cmd_buf, result_buf, sizeof(result_buf));
    if (result_buf[0] == '\0')
        return;
    int size_kb = atoi(result_buf);
    LOG_INFO("check_and_cleanup_log_dir: log dir size = %d KB\n", size_kb);
    if (size_kb <= LOG_DIR_MAX_SIZE_KB)
        return;
    snprintf(cmd_buf, sizeof(cmd_buf), "rm -rf %s/*", LOG_DIR_PATH);
    system(cmd_buf);
}

static void* check_thread_func(void *arg) {
    LOG_DEBUG("check_thread: thread function started\n");
    
    check_thread_running = 1;
    LOG_DEBUG("check_thread: running\n");
    
    check_and_cleanup_log_dir();
    
    while (!check_thread_exit) {
        sleep(CHECK_INTERVAL);
        
        if (!check_thread_exit) {
            check_and_cleanup_log_dir();
        }
    }
    
    check_thread_running = 0;
    LOG_DEBUG("check_thread: exited\n");
    return NULL;
}

int start_check_thread(void) {
    int ret;
    
    check_thread_exit = 0;
    check_thread_running = 0;
    
    ret = pthread_create(&check_thread, NULL, check_thread_func, NULL);
    if (ret != 0) {
        LOG_ERROR("Failed to create check_thread: %s\n", strerror(ret));
        return -1;
    }
    LOG_INFO("check_thread: created\n");
    return 0;
}

void stop_check_thread(void) {
    if (!check_thread_running) {
        return;
    }
    check_thread_exit = 1;
    pthread_join(check_thread, NULL);

}
