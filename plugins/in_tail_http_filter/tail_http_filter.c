/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_config_map.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_upstream.h>
#include <fluent-bit/flb_pack.h>

#include "tail_http_filter.h"
#include "../in_tail/tail.h"
#include "../in_tail/tail_config.h"
#include "../in_tail/tail_scan.h"
#include "../in_tail/tail_file.h"

struct pattern_entry {
    flb_sds_t pattern;
    struct mk_list _head;
};

static int in_tail_http_filter_collect_pending(struct flb_input_instance *ins,
                                              struct flb_config *config, void *in_context)
{
    struct flb_tail_http_filter_config *ctx = in_context;
    return in_tail_collect_event(ctx->tail_config, config);
}

static int in_tail_http_filter_collect_static(struct flb_input_instance *ins,
                                             struct flb_config *config, void *in_context)
{
    struct flb_tail_http_filter_config *ctx = in_context;
    return in_tail_collect_event(ctx->tail_config, config);
}

static int in_tail_http_filter_watcher_callback(struct flb_input_instance *ins,
                                               struct flb_config *config, void *context)
{
    struct flb_tail_http_filter_config *ctx = context;
    return in_tail_collect_event(ctx->tail_config, config);
}

static int in_tail_http_filter_scan_callback(struct flb_input_instance *ins,
                                            struct flb_config *config, void *context)
{
    struct flb_tail_http_filter_config *ctx = context;
    time_t now = time(NULL);
    
    if (now - ctx->last_fetch_time > ctx->refresh_interval) {
        fetch_http_data(ctx, config);
    }
    
    return flb_tail_scan(ctx->tail_config->path_list, ctx->tail_config);
}

int fetch_http_data(struct flb_tail_http_filter_config *ctx, struct flb_config *config)
{
    int ret;
    struct flb_connection *conn;
    struct flb_http_client *client;
    size_t bytes;
    int i;
    yyjson_doc *json_doc;
    yyjson_val *json_root;
    yyjson_val *json_array;
    yyjson_val *json_item;
    time_t now = time(NULL);

    if (!ctx->upstream) {
        flb_plg_error(ctx->tail_config->ins, "upstream not initialized");
        return -1;
    }

    conn = flb_upstream_conn_get(ctx->upstream);
    if (!conn) {
        flb_plg_error(ctx->tail_config->ins, "failed to get upstream connection");
        return -1;
    }

    client = flb_http_client(conn, FLB_HTTP_GET, "/", NULL, 0,
                             NULL, 0, NULL, FLB_HTTP_11);
    if (!client) {
        flb_plg_error(ctx->tail_config->ins, "failed to create http client");
        flb_upstream_conn_release(conn);
        return -1;
    }

    flb_http_set_response_timeout(client, ctx->http_timeout);

    ret = flb_http_do(client, &bytes);
    if (ret != 0) {
        flb_plg_error(ctx->tail_config->ins, "http request failed: %d", ret);
        flb_http_client_destroy(client);
        flb_upstream_conn_release(conn);
        return -1;
    }

    if (client->resp.status != 200) {
        flb_plg_error(ctx->tail_config->ins, "http request returned status: %d", client->resp.status);
        flb_http_client_destroy(client);
        flb_upstream_conn_release(conn);
        return -1;
    }

    json_doc = yyjson_read(client->resp.payload, client->resp.payload_size, 0);
    if (!json_doc) {
        flb_plg_error(ctx->tail_config->ins, "failed to parse json response");
        flb_http_client_destroy(client);
        flb_upstream_conn_release(conn);
        return -1;
    }

    json_root = yyjson_doc_get_root(json_doc);
    json_array = yyjson_obj_get(json_root, ctx->http_key);
    if (!json_array || !yyjson_is_arr(json_array)) {
        flb_plg_error(ctx->tail_config->ins, "invalid json structure: %s is not an array", ctx->http_key);
        yyjson_doc_free(json_doc);
        flb_http_client_destroy(client);
        flb_upstream_conn_release(conn);
        return -1;
    }

    struct pattern_entry *entry;
    struct mk_list *curr, *next;
    mk_list_foreach_safe(curr, next, &ctx->allowed_patterns) {
        entry = mk_list_entry(curr, struct pattern_entry, _head);
        flb_sds_destroy(entry->pattern);
        mk_list_del(&entry->_head);
        flb_free(entry);
    }

    size_t array_size = yyjson_arr_size(json_array);
    for (i = 0; i < array_size; i++) {
        json_item = yyjson_arr_get(json_array, i);
        if (yyjson_is_str(json_item)) {
            entry = flb_calloc(1, sizeof(struct pattern_entry));
            if (entry) {
                entry->pattern = flb_sds_create(yyjson_get_str(json_item));
                if (entry->pattern) {
                    mk_list_add(&entry->_head, &ctx->allowed_patterns);
                } else {
                    flb_free(entry);
                }
            }
        }
    }

    yyjson_doc_free(json_doc);
    flb_http_client_destroy(client);
    flb_upstream_conn_release(conn);
    ctx->last_fetch_time = now;

    return 0;
}

int is_file_allowed(const char *file_path, struct flb_tail_http_filter_config *ctx)
{
    struct pattern_entry *entry;
    struct mk_list *curr;
    
    if (mk_list_is_empty(&ctx->allowed_patterns)) {
        return FLB_FALSE;
    }
    
    mk_list_foreach(curr, &ctx->allowed_patterns) {
        entry = mk_list_entry(curr, struct pattern_entry, _head);
        if (strstr(file_path, entry->pattern)) {
            return FLB_TRUE;
        }
    }
    
    return FLB_FALSE;
}

int in_tail_http_filter_init(struct flb_input_instance *ins,
                             struct flb_config *config, void *data)
{
    int ret;
    struct flb_tail_http_filter_config *ctx;
    struct flb_tail_config *tail_config;
    
    ctx = flb_calloc(1, sizeof(struct flb_tail_http_filter_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    
    ctx->http_url = flb_sds_create("http://localhost:8080");
    ctx->http_key = flb_sds_create("allowed_patterns");
    ctx->http_timeout = 5;
    ctx->refresh_interval = 60;
    ctx->last_fetch_time = 0;
    mk_list_init(&ctx->allowed_patterns);
    
    ret = flb_input_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_plg_error(ins, "configuration error");
        flb_sds_destroy(ctx->http_url);
        flb_sds_destroy(ctx->http_key);
        flb_free(ctx);
        return -1;
    }
    
    tail_config = flb_tail_config_create(ins, config);
    if (!tail_config) {
        flb_plg_error(ins, "failed to create tail config");
        flb_sds_destroy(ctx->http_url);
        flb_sds_destroy(ctx->http_key);
        flb_free(ctx);
        return -1;
    }
    
    ctx->tail_config = tail_config;
    ctx->tail_config->ins = ins;
    
    ctx->upstream = flb_upstream_create_url(config, ctx->http_url, FLB_IO_TCP, NULL);
    if (!ctx->upstream) {
        flb_plg_error(ins, "failed to create upstream");
        flb_tail_config_destroy(tail_config);
        flb_sds_destroy(ctx->http_url);
        flb_sds_destroy(ctx->http_key);
        flb_free(ctx);
        return -1;
    }
    
    ret = flb_tail_fs_init(ins, tail_config, config);
    if (ret == -1) {
        flb_plg_error(ins, "failed to initialize filesystem watcher");
        flb_upstream_destroy(ctx->upstream);
        flb_tail_config_destroy(tail_config);
        flb_sds_destroy(ctx->http_url);
        flb_sds_destroy(ctx->http_key);
        flb_free(ctx);
        return -1;
    }
    
    fetch_http_data(ctx, config);
    
    flb_input_set_context(ins, ctx);
    
    ret = flb_input_set_collector_event(ins, in_tail_http_filter_collect_static,
                                       tail_config->ch_manager[0], config);
    if (ret == -1) {
        flb_plg_error(ins, "failed to set static collector");
        flb_upstream_destroy(ctx->upstream);
        flb_tail_config_destroy(tail_config);
        flb_sds_destroy(ctx->http_url);
        flb_sds_destroy(ctx->http_key);
        flb_free(ctx);
        return -1;
    }
    
    ret = flb_input_set_collector_time(ins, in_tail_http_filter_scan_callback,
                                      tail_config->refresh_interval_sec,
                                      tail_config->refresh_interval_nsec,
                                      config);
    if (ret == -1) {
        flb_plg_error(ins, "failed to set scan collector");
        flb_upstream_destroy(ctx->upstream);
        flb_tail_config_destroy(tail_config);
        flb_sds_destroy(ctx->http_url);
        flb_sds_destroy(ctx->http_key);
        flb_free(ctx);
        return -1;
    }
    
    ret = flb_input_set_collector_time(ins, in_tail_http_filter_watcher_callback,
                                      tail_config->watcher_interval, 0, config);
    if (ret == -1) {
        flb_plg_error(ins, "failed to set watcher collector");
        flb_upstream_destroy(ctx->upstream);
        flb_tail_config_destroy(tail_config);
        flb_sds_destroy(ctx->http_url);
        flb_sds_destroy(ctx->http_key);
        flb_free(ctx);
        return -1;
    }
    
    ret = flb_input_set_collector_event(ins, in_tail_http_filter_collect_pending,
                                       tail_config->ch_pending[0], config);
    if (ret == -1) {
        flb_plg_error(ins, "failed to set pending collector");
        flb_upstream_destroy(ctx->upstream);
        flb_tail_config_destroy(tail_config);
        flb_sds_destroy(ctx->http_url);
        flb_sds_destroy(ctx->http_key);
        flb_free(ctx);
        return -1;
    }
    
    return 0;
}

int in_tail_http_filter_pre_run(struct flb_input_instance *ins,
                                struct flb_config *config, void *in_context)
{
    struct flb_tail_http_filter_config *ctx = in_context;
    return in_tail_collect_event(ctx->tail_config, config);
}

int in_tail_http_filter_exit(void *data, struct flb_config *config)
{
    struct flb_tail_http_filter_config *ctx = data;
    
    if (ctx) {
        if (ctx->upstream) {
            flb_upstream_destroy(ctx->upstream);
        }
        
        struct pattern_entry *entry;
        struct mk_list *curr, *next;
        mk_list_foreach_safe(curr, next, &ctx->allowed_patterns) {
            entry = mk_list_entry(curr, struct pattern_entry, _head);
            flb_sds_destroy(entry->pattern);
            mk_list_del(&entry->_head);
            flb_free(entry);
        }
        
        flb_sds_destroy(ctx->http_url);
        flb_sds_destroy(ctx->http_key);
        
        if (ctx->tail_config) {
            flb_tail_config_destroy(ctx->tail_config);
        }
        
        flb_free(ctx);
    }
    
    return 0;
}

void in_tail_http_filter_pause(void *data, struct flb_config *config)
{
    struct flb_tail_http_filter_config *ctx = data;
    if (ctx && ctx->tail_config) {
        flb_input_collector_pause(ctx->tail_config->coll_fd_static, ctx->tail_config->ins);
        flb_input_collector_pause(ctx->tail_config->coll_fd_pending, ctx->tail_config->ins);
    }
}

void in_tail_http_filter_resume(void *data, struct flb_config *config)
{
    struct flb_tail_http_filter_config *ctx = data;
    if (ctx && ctx->tail_config) {
        flb_input_collector_resume(ctx->tail_config->coll_fd_static, ctx->tail_config->ins);
        flb_input_collector_resume(ctx->tail_config->coll_fd_pending, ctx->tail_config->ins);
    }
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "http_url", "http://localhost:8080",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, http_url),
     "HTTP URL to fetch allowed patterns"
    },
    {
     FLB_CONFIG_MAP_STR, "http_key", "allowed_patterns",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, http_key),
     "Key in JSON response that contains allowed patterns array"
    },
    {
     FLB_CONFIG_MAP_INT, "http_timeout", "5",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, http_timeout),
     "HTTP request timeout in seconds"
    },
    {
     FLB_CONFIG_MAP_INT, "refresh_interval", "60",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, refresh_interval),
     "Interval to refresh allowed patterns from HTTP URL"
    },
    
    {0}
};

struct flb_input_plugin in_tail_http_filter_plugin = {
    .name         = "tail_http_filter",
    .description  = "Tail files with HTTP-based filtering",
    .cb_init      = in_tail_http_filter_init,
    .cb_pre_run   = in_tail_http_filter_pre_run,
    .cb_collect   = NULL,
    .cb_flush_buf = NULL,
    .cb_pause     = in_tail_http_filter_pause,
    .cb_resume    = in_tail_http_filter_resume,
    .cb_exit      = in_tail_http_filter_exit,
    .config_map   = config_map,
    .flags        = 0
};
