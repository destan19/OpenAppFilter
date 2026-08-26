// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright(c) 2026 destan19(TT) <www.fanchmwrt.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fwx.h"
#include "fwx_stat.h"

#define SESSION_MAX_POINTS (24 * 60)
#define SESSION_SAMPLE_INTERVAL_SEC 5
#define SESSION_DETAIL_MAX_POINTS (5 * 60 / SESSION_SAMPLE_INTERVAL_SEC)
#define SESSION_SAMPLES_PER_MINUTE (60 / SESSION_SAMPLE_INTERVAL_SEC)

typedef struct session_point {
    int value;
} session_point_t;

typedef struct session_ring {
    session_point_t *points;
    int max_points;
    int start;
    int count;
} session_ring_t;

typedef struct session_stat_ctx {
    session_point_t minute_points[SESSION_MAX_POINTS];
    session_point_t detail_points[SESSION_DETAIL_MAX_POINTS];
    session_ring_t minute_ring;
    session_ring_t detail_ring;
    int detail_sample_count;
    int inited;
} session_stat_ctx_t;

static session_stat_ctx_t g_session_stat;

static void session_stat_init(void)
{
    if (g_session_stat.inited) {
        return;
    }

    memset(&g_session_stat, 0, sizeof(g_session_stat));
    g_session_stat.minute_ring.points = g_session_stat.minute_points;
    g_session_stat.minute_ring.max_points = SESSION_MAX_POINTS;
    g_session_stat.detail_ring.points = g_session_stat.detail_points;
    g_session_stat.detail_ring.max_points = SESSION_DETAIL_MAX_POINTS;
    g_session_stat.inited = 1;
}

int fwx_stat_read_conntrack_count(void)
{
    const char *path = "/proc/sys/net/netfilter/nf_conntrack_count";
    char line[64] = {0};
    FILE *fp = fopen(path, "r");
    char *endptr = NULL;
    long v;

    if (!fp) {
        return 0;
    }

    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return 0;
    }
    fclose(fp);

    v = strtol(line, &endptr, 10);
    if (endptr == line || v < 0) {
        return 0;
    }

    return (int)v;
}

static void session_ring_append(session_ring_t *ring, int value)
{
    int idx;
    if (!ring || !ring->points || ring->max_points <= 0) {
        return;
    }

    if (ring->count < ring->max_points) {
        idx = (ring->start + ring->count) % ring->max_points;
        ring->count++;
    } else {
        idx = ring->start;
        ring->start = (ring->start + 1) % ring->max_points;
    }
    ring->points[idx].value = value;
}

void fwx_session_stat_tick(void)
{
    int current = fwx_stat_read_conntrack_count();
    session_stat_init();
    session_ring_append(&g_session_stat.detail_ring, current);
    g_session_stat.detail_sample_count++;
    if (g_session_stat.detail_sample_count >= SESSION_SAMPLES_PER_MINUTE) {
        session_ring_append(&g_session_stat.minute_ring, current);
        g_session_stat.detail_sample_count = 0;
    }
}

struct json_object *fwx_api_get_history_session(struct json_object *req_obj)
{
    const char *range = "hour";
    int minutes = 60;
    int current;
    int i;
    int start_offset = 0;
    struct json_object *data_obj = json_object_new_object();
    struct json_object *list_obj = json_object_new_array();
    long long sum = 0;
    int sample_count = 0;
    int peak = 0;
    int avg = 0;
    int is_5min = 0;
    int total_count = 0;
    int ring_start = 0;
    int ring_max = 0;
    session_point_t *points = NULL;
    struct json_object *range_obj = req_obj ? json_object_object_get(req_obj, "range") : NULL;
    struct json_object *minutes_obj = req_obj ? json_object_object_get(req_obj, "minutes") : NULL;
    session_ring_t *ring = NULL;

    session_stat_init();

    if (range_obj) {
        const char *range_str = json_object_get_string(range_obj);
        if (range_str && strlen(range_str) > 0) {
            range = range_str;
        }
    }

    if (range && (!strcmp(range, "5min") || !strcmp(range, "5m"))) {
        is_5min = 1;
        minutes = 5;
    } else if (minutes_obj) {
        int tmp = json_object_get_int(minutes_obj);
        if (tmp > 0) {
            minutes = tmp;
        }
    } else if (range && strcmp(range, "day") == 0) {
        minutes = 24 * 60;
    } else {
        minutes = 60;
    }

    if (is_5min) {
        ring = &g_session_stat.detail_ring;
    } else {
        ring = &g_session_stat.minute_ring;
        if (minutes > SESSION_MAX_POINTS) {
            minutes = SESSION_MAX_POINTS;
        }
        if (minutes < 1) {
            minutes = 1;
        }
    }

    total_count = ring->count;
    ring_start = ring->start;
    ring_max = ring->max_points;
    points = ring->points;

    current = fwx_stat_read_conntrack_count();

    if (is_5min) {
        if (total_count > SESSION_DETAIL_MAX_POINTS) {
            start_offset = total_count - SESSION_DETAIL_MAX_POINTS;
        }
    } else if (total_count > minutes) {
        start_offset = total_count - minutes;
    }

    for (i = start_offset; i < total_count; i++) {
        int idx = (ring_start + i) % ring_max;
        session_point_t *pt = &points[idx];
        json_object_array_add(list_obj, json_object_new_int(pt->value));
        sum += pt->value;
        sample_count++;
        if (sample_count == 1 || pt->value > peak) {
            peak = pt->value;
        }
    }

    if (sample_count == 0) {
        json_object_array_add(list_obj, json_object_new_int(current));
        avg = current;
        peak = current;
    } else {
        avg = (int)((sum + (sample_count / 2)) / sample_count);
        if (current > peak) {
            peak = current;
        }
    }

    if (is_5min) {
        json_object_object_add(data_obj, "range", json_object_new_string("5min"));
        json_object_object_add(data_obj, "minutes", json_object_new_int(5));
    } else {
        json_object_object_add(data_obj, "range", json_object_new_string((minutes >= 24 * 60) ? "day" : "hour"));
        json_object_object_add(data_obj, "minutes", json_object_new_int(minutes));
    }
    json_object_object_add(data_obj, "current", json_object_new_int(current));
    json_object_object_add(data_obj, "avg", json_object_new_int(avg));
    json_object_object_add(data_obj, "peak", json_object_new_int(peak));
    json_object_object_add(data_obj, "list", list_obj);
    return fwx_gen_api_response_data(API_CODE_SUCCESS, data_obj);
}
