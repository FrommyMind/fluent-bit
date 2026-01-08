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
#include <errno.h>

#ifdef FLB_SYSTEM_WINDOWS
#include <shlwapi.h>
#else
#include <glob.h>
#include <fnmatch.h>
#include <unistd.h>
#endif

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
#include "../in_tail/tail_signal.h"
#include "../in_tail/tail_file_internal.h"
#include "../in_tail/tail_fs.h"

struct pattern_entry
{
    flb_sds_t pattern;
    struct mk_list _head;
};

/* Global list to store http filter configs for lookup */
static struct mk_list http_filter_configs;
static int http_filter_configs_initialized = 0;

/* Forward declarations */
static int tail_http_filter_scan(struct mk_list *path_list,
                                 struct flb_tail_http_filter_config *http_ctx);

/* Helper function to find http_ctx from tail_config */
static struct flb_tail_http_filter_config *get_http_ctx_from_tail_config(
    struct flb_tail_config *tail_config)
{
    struct mk_list *head;
    struct flb_tail_http_filter_config *http_ctx;

    mk_list_foreach(head, &http_filter_configs)
    {
        http_ctx = mk_list_entry(head, struct flb_tail_http_filter_config, _head);
        if (http_ctx->tail_config == tail_config)
        {
            return http_ctx;
        }
    }
    return NULL;
}

static inline int consume_byte(flb_pipefd_t fd)
{
    int ret;
    uint64_t val;

    ret = flb_pipe_r(fd, (char *)&val, sizeof(val));
    if (ret <= 0)
    {
        flb_pipe_error();
        return -1;
    }

    return 0;
}

/* Collect pending event files */
static int in_tail_http_filter_collect_pending(struct flb_input_instance *ins,
                                               struct flb_config *config, void *in_context)
{
    int ret;
    int active = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tail_config *ctx = in_context;
    struct flb_tail_file *file;
    struct stat st;
    uint64_t pre;
    uint64_t total_processed = 0;

    /* Iterate promoted event files with pending bytes */
    mk_list_foreach_safe(head, tmp, &ctx->files_event)
    {
        file = mk_list_entry(head, struct flb_tail_file, _head);

        if (file->watch_fd == -1 || (file->offset >= file->size))
        {
            ret = fstat(file->fd, &st);
            if (ret == -1)
            {
                flb_errno();
                flb_tail_file_remove(file);
                continue;
            }
            file->size = st.st_size;
            file->pending_bytes = (file->size - file->offset);
        }
        else
        {
            memset(&st, 0, sizeof(struct stat));
        }

        if (file->pending_bytes <= 0)
        {
            if (file->decompression_context == NULL ||
                file->decompression_context->input_buffer_length == 0)
            {
                continue;
            }
        }

        if (ctx->event_batch_size > 0 && total_processed >= ctx->event_batch_size)
        {
            break;
        }

        pre = file->offset;
        ret = flb_tail_file_chunk(file);

        if (file->offset > pre)
        {
            total_processed += (file->offset - pre);
        }

        switch (ret)
        {
        case FLB_TAIL_ERROR:
            flb_tail_file_remove(file);
            break;
        case FLB_TAIL_OK:
        case FLB_TAIL_BUSY:
            if (file->offset < file->size)
            {
                file->pending_bytes = (file->size - file->offset);
                active++;
            }
            else if (file->decompression_context != NULL &&
                     file->decompression_context->input_buffer_length > 0)
            {
                active++;
            }
            else
            {
                file->pending_bytes = 0;
            }
            break;
        }
    }

    if (active == 0)
    {
        tail_consume_pending(ctx);
    }

    return 0;
}

/* Collect static files */
static int in_tail_http_filter_collect_static(struct flb_input_instance *ins,
                                              struct flb_config *config, void *in_context)
{
    int ret;
    int active = 0;
    int completed = FLB_FALSE;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tail_config *ctx = in_context;
    struct flb_tail_file *file;
    uint64_t pre;
    uint64_t total_processed = 0;

    mk_list_foreach_safe(head, tmp, &ctx->files_static)
    {
        file = mk_list_entry(head, struct flb_tail_file, _head);

        if (ctx->static_batch_size > 0 && total_processed >= ctx->static_batch_size)
        {
            break;
        }

        pre = file->stream_offset;
        ret = flb_tail_file_chunk(file);

        if (file->stream_offset > pre)
        {
            total_processed += (file->stream_offset - pre);
        }

        switch (ret)
        {
        case FLB_TAIL_ERROR:
            flb_tail_file_remove(file);
            break;
        case FLB_TAIL_OK:
        case FLB_TAIL_BUSY:
            active++;
            break;
        case FLB_TAIL_WAIT:
            if (file->decompression_context != NULL &&
                file->decompression_context->input_buffer_length > 0)
            {
                active++;
                break;
            }

            if (file->config->exit_on_eof)
            {
                flb_plg_info(ctx->ins, "inode=%" PRIu64 " file=%s ended, stop",
                             file->inode, file->name);
                if (ctx->files_static_count == 1)
                {
                    flb_engine_exit(config);
                }
            }
            flb_plg_debug(ctx->ins, "inode=%" PRIu64 " file=%s promote to TAIL_EVENT",
                          file->inode, file->name);
            ret = flb_tail_file_to_event(file);
            if (ret == -1)
            {
                flb_plg_debug(ctx->ins, "file=%s cannot promote, unregistering",
                              file->name);
                flb_tail_file_remove(file);
            }
            break;
        }
    }

    if (active == 0)
    {
        consume_byte(ctx->ch_manager[0]);
        ctx->ch_reads++;
        completed = FLB_TRUE;
    }

    return 0;
}

/* Watcher callback to check for rotated files */
static int in_tail_http_filter_watcher_callback(struct flb_input_instance *ins,
                                                struct flb_config *config, void *context)
{
    int ret = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_tail_config *ctx = context;
    struct flb_tail_file *file;
    (void)config;

    mk_list_foreach_safe(head, tmp, &ctx->files_event)
    {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        if (file->is_link == FLB_TRUE)
        {
            ret = flb_tail_file_is_rotated(ctx, file);
            if (ret == FLB_FALSE)
            {
                continue;
            }
            flb_tail_file_rotated(file);
        }
    }
    return ret;
}

static int in_tail_http_filter_scan_callback(struct flb_input_instance *ins,
                                             struct flb_config *config, void *context)
{
    struct flb_tail_config *tail_ctx = context;
    struct flb_tail_http_filter_config *http_ctx;
    time_t now = time(NULL);

    http_ctx = get_http_ctx_from_tail_config(tail_ctx);
    if (!http_ctx)
    {
        flb_plg_error(ins, "http_ctx not found for tail_config");
        return -1;
    }

    /* Refresh HTTP patterns if interval has passed */
    if (now - http_ctx->last_fetch_time > http_ctx->refresh_interval)
    {
        fetch_http_data(http_ctx, config);
    }

    /* Use custom scan function with HTTP filtering */
    return tail_http_filter_scan(tail_ctx->path_list, http_ctx);
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

    if (!ctx->upstream)
    {
        flb_plg_error(ctx->tail_config->ins, "upstream not initialized");
        return -1;
    }

    conn = flb_upstream_conn_get(ctx->upstream);
    if (!conn)
    {
        flb_plg_error(ctx->tail_config->ins, "failed to get upstream connection");
        return -1;
    }

    client = flb_http_client(conn, FLB_HTTP_GET, "/", NULL, 0,
                             NULL, 0, NULL, FLB_HTTP_11);
    if (!client)
    {
        flb_plg_error(ctx->tail_config->ins, "failed to create http client");
        flb_upstream_conn_release(conn);
        return -1;
    }

    flb_http_set_response_timeout(client, ctx->http_timeout);

    ret = flb_http_do(client, &bytes);
    if (ret != 0)
    {
        flb_plg_warn(ctx->tail_config->ins, "http request failed: %d", ret);
        flb_http_client_destroy(client);
        flb_upstream_conn_release(conn);
        return 0;
    }

    if (client->resp.status != 200)
    {
        flb_plg_warn(ctx->tail_config->ins, "http request returned status: %d", client->resp.status);
        flb_http_client_destroy(client);
        flb_upstream_conn_release(conn);
        return 0;
    }

    json_doc = yyjson_read(client->resp.payload, client->resp.payload_size, 0);
    if (!json_doc)
    {
        flb_plg_error(ctx->tail_config->ins, "failed to parse json response");
        flb_http_client_destroy(client);
        flb_upstream_conn_release(conn);
        return -1;
    }

    json_root = yyjson_doc_get_root(json_doc);
    json_array = yyjson_obj_get(json_root, ctx->http_key);
    /* 打印获取到的对应 http_key 的 value */
    flb_plg_info(ctx->tail_config->ins, "http获取的key结果: %s", yyjson_val_write(json_array, 0, NULL));
    if (!json_array || !yyjson_is_arr(json_array))
    {
        flb_plg_error(ctx->tail_config->ins, "invalid json structure: %s is not an array", ctx->http_key);
        yyjson_doc_free(json_doc);
        flb_http_client_destroy(client);
        flb_upstream_conn_release(conn);
        return -1;
    }

    struct pattern_entry *entry;
    struct mk_list *curr, *next;
    mk_list_foreach_safe(curr, next, &ctx->allowed_patterns)
    {
        entry = mk_list_entry(curr, struct pattern_entry, _head);
        flb_sds_destroy(entry->pattern);
        mk_list_del(&entry->_head);
        flb_free(entry);
    }

    size_t array_size = yyjson_arr_size(json_array);
    for (i = 0; i < array_size; i++)
    {
        json_item = yyjson_arr_get(json_array, i);
        if (yyjson_is_str(json_item))
        {
            entry = flb_calloc(1, sizeof(struct pattern_entry));
            if (entry)
            {
                entry->pattern = flb_sds_create(yyjson_get_str(json_item));
                if (entry->pattern)
                {
                    mk_list_add(&entry->_head, &ctx->allowed_patterns);
                }
                else
                {
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

    if (mk_list_is_empty(&ctx->allowed_patterns))
    {
        /* If no patterns fetched from HTTP, allow none files */
        return FLB_FALSE;
    }

    mk_list_foreach(curr, &ctx->allowed_patterns)
    {
        entry = mk_list_entry(curr, struct pattern_entry, _head);
        if (strstr(file_path, entry->pattern))
        {
            return FLB_TRUE;
        }
    }
    
    flb_debug("file %s not match any pattern", file_path);

    return FLB_FALSE;
}

/* Check if file is in exclude list */
static int tail_http_filter_is_excluded(char *path, struct flb_tail_config *ctx)
{
    struct mk_list *head;
    struct flb_slist_entry *pattern;

    if (!ctx->exclude_list)
    {
        return FLB_FALSE;
    }

    mk_list_foreach(head, ctx->exclude_list)
    {
        pattern = mk_list_entry(head, struct flb_slist_entry, _head);
#ifdef FLB_SYSTEM_WINDOWS
        if (PathMatchSpecA(path, pattern->str))
        {
            return FLB_TRUE;
        }
#else
        if (fnmatch(pattern->str, path, 0) == 0)
        {
            return FLB_TRUE;
        }
#endif
    }

    return FLB_FALSE;
}

#ifdef FLB_SYSTEM_WINDOWS
/*
 * Windows: Register a file with HTTP filtering
 */
static int tail_http_filter_register_file(const char *target,
                                          struct flb_tail_http_filter_config *http_ctx,
                                          time_t ts)
{
    int64_t mtime;
    struct stat st;
    char path[MAX_PATH];
    ssize_t ignored_file_size;
    struct flb_tail_config *ctx = http_ctx->tail_config;

    ignored_file_size = -1;

    if (_fullpath(path, target, MAX_PATH) == NULL)
    {
        flb_plg_error(ctx->ins, "cannot get absolute path of %s", target);
        return -1;
    }

    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
    {
        return -1;
    }

    /* HTTP filter check */
    if (is_file_allowed(path, http_ctx) == FLB_FALSE)
    {
        flb_plg_debug(ctx->ins, "http_filter excluded=%s", path);
        return -1;
    }

    if (ctx->ignore_older > 0)
    {
        mtime = flb_tail_stat_mtime(&st);
        if (mtime > 0)
        {
            if ((ts - ctx->ignore_older) > mtime)
            {
                flb_plg_debug(ctx->ins, "excluded=%s (ignore_older)", target);
                flb_tail_scan_register_ignored_file_size(ctx, path, strlen(path), st.st_size);
                return -1;
            }
        }
    }

    if (tail_http_filter_is_excluded(path, ctx) == FLB_TRUE)
    {
        flb_plg_trace(ctx->ins, "skip '%s' (excluded)", path);
        return -1;
    }

    if (ctx->ignore_older > 0)
    {
        ignored_file_size = flb_tail_scan_fetch_ignored_file_size(ctx, path, strlen(path));
        flb_tail_scan_unregister_ignored_file_size(ctx, path, strlen(path));
    }

    return flb_tail_file_append(path, &st, FLB_TAIL_STATIC, ignored_file_size, ctx);
}

/*
 * Windows: Scan pattern with HTTP filtering
 */
static int tail_http_filter_scan_pattern(const char *path,
                                         struct flb_tail_http_filter_config *http_ctx)
{
    char *star, *p0, *p1;
    char pattern[MAX_PATH];
    char buf[MAX_PATH];
    int ret;
    int n_added = 0;
    time_t now;
    HANDLE h;
    WIN32_FIND_DATA data;
    struct flb_tail_config *ctx = http_ctx->tail_config;

    if (strlen(path) > MAX_PATH - 1)
    {
        flb_plg_error(ctx->ins, "path too long '%s'", path);
        return -1;
    }

    star = strchr(path, '*');
    if (star == NULL)
    {
        return -1;
    }

    p0 = star;
    while (path <= p0 && *p0 != '\\')
    {
        p0--;
    }

    p1 = star;
    while (*p1 && *p1 != '\\')
    {
        p1++;
    }

    memcpy(pattern, path, (p1 - path));
    pattern[p1 - path] = '\0';

    h = FindFirstFileA(pattern, &data);
    if (h == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    now = time(NULL);
    do
    {
        if (!strcmp(".", data.cFileName) || !strcmp("..", data.cFileName))
        {
            continue;
        }

        if (strchr(data.cFileName, '*'))
        {
            continue;
        }

        memcpy(buf, path, p0 - path + 1);
        buf[p0 - path + 1] = '\0';

        if (strlen(buf) + strlen(data.cFileName) + strlen(p1) > MAX_PATH - 1)
        {
            flb_plg_warn(ctx->ins, "'%s%s%s' is too long", buf, data.cFileName, p1);
            continue;
        }
        strcat(buf, data.cFileName);
        strcat(buf, p1);

        if (strchr(p1, '*'))
        {
            ret = tail_http_filter_scan_pattern(buf, http_ctx);
            if (ret >= 0)
            {
                n_added += ret;
            }
            continue;
        }

        ret = tail_http_filter_register_file(buf, http_ctx, now);
        if (ret == 0)
        {
            n_added++;
        }
    } while (FindNextFileA(h, &data) != 0);

    FindClose(h);
    return n_added;
}

/*
 * Windows: Scan path with HTTP filtering
 */
static int tail_http_filter_scan_path(const char *path,
                                      struct flb_tail_http_filter_config *http_ctx)
{
    int ret;
    int n_added = 0;
    time_t now;

    if (strchr(path, '*'))
    {
        return tail_http_filter_scan_pattern(path, http_ctx);
    }

    now = time(NULL);
    ret = tail_http_filter_register_file(path, http_ctx, now);
    if (ret == 0)
    {
        n_added++;
    }

    return n_added;
}

#else  /* Linux/Unix */

/*
 * Linux/Unix: Scan path with HTTP filtering using glob
 */
static int tail_http_filter_scan_path(const char *path,
                                      struct flb_tail_http_filter_config *http_ctx)
{
    int i;
    int ret;
    int count = 0;
    glob_t globbuf;
    time_t now;
    int64_t mtime;
    struct stat st;
    ssize_t ignored_file_size;
    struct flb_tail_config *ctx = http_ctx->tail_config;

    ignored_file_size = -1;

    flb_plg_debug(ctx->ins, "http_filter scanning path %s", path);

    globbuf.gl_pathv = NULL;

    ret = glob(path, GLOB_TILDE | GLOB_ERR, NULL, &globbuf);
    if (ret != 0)
    {
        switch (ret)
        {
        case GLOB_NOSPACE:
            flb_plg_error(ctx->ins, "no memory space available");
            return -1;
        case GLOB_ABORTED:
            flb_plg_error(ctx->ins, "read error, check permissions: %s", path);
            return -1;
        case GLOB_NOMATCH:
            ret = stat(path, &st);
            if (ret == -1)
            {
                flb_plg_debug(ctx->ins, "cannot read info from: %s", path);
            }
            else
            {
                ret = access(path, R_OK);
                if (ret == -1 && errno == EACCES)
                {
                    flb_plg_error(ctx->ins, "NO read access for path: %s", path);
                }
                else
                {
                    flb_plg_debug(ctx->ins, "NO matches for path: %s", path);
                }
            }
            return 0;
        }
    }

    now = time(NULL);
    for (i = 0; i < globbuf.gl_pathc; i++)
    {
        ret = stat(globbuf.gl_pathv[i], &st);
        if (ret == 0 && S_ISREG(st.st_mode))
        {
            /* HTTP filter check */
            if (is_file_allowed(globbuf.gl_pathv[i], http_ctx) == FLB_FALSE)
            {
                flb_plg_debug(ctx->ins, "http_filter excluded=%s", globbuf.gl_pathv[i]);
                continue;
            }

            /* Check if file is in exclude list */
            if (tail_http_filter_is_excluded(globbuf.gl_pathv[i], ctx) == FLB_TRUE)
            {
                flb_plg_debug(ctx->ins, "excluded=%s", globbuf.gl_pathv[i]);
                continue;
            }

            if (ctx->ignore_older > 0)
            {
                mtime = flb_tail_stat_mtime(&st);
                if (mtime > 0)
                {
                    if ((now - ctx->ignore_older) > mtime)
                    {
                        flb_plg_debug(ctx->ins, "excluded=%s (ignore_older)",
                                      globbuf.gl_pathv[i]);
                        flb_tail_scan_register_ignored_file_size(
                            ctx, globbuf.gl_pathv[i], strlen(globbuf.gl_pathv[i]), st.st_size);
                        continue;
                    }
                }
            }

            if (ctx->ignore_older > 0)
            {
                ignored_file_size = flb_tail_scan_fetch_ignored_file_size(
                    ctx, globbuf.gl_pathv[i], strlen(globbuf.gl_pathv[i]));
                flb_tail_scan_unregister_ignored_file_size(
                    ctx, globbuf.gl_pathv[i], strlen(globbuf.gl_pathv[i]));
            }

            ret = flb_tail_file_append(globbuf.gl_pathv[i], &st,
                                       FLB_TAIL_STATIC, ignored_file_size, ctx);

            if (ret == 0)
            {
                flb_plg_debug(ctx->ins, "http_filter scan add(): %s, inode %" PRIu64,
                              globbuf.gl_pathv[i], (uint64_t)st.st_ino);
                count++;
            }
            else
            {
                flb_plg_debug(ctx->ins, "http_filter scan add(): dismissed: %s",
                              globbuf.gl_pathv[i]);
            }
        }
        else
        {
            flb_plg_debug(ctx->ins, "skip (invalid) entry=%s", globbuf.gl_pathv[i]);
        }
    }

    if (count > 0)
    {
        tail_signal_manager(ctx);
    }

    globfree(&globbuf);
    return count;
}
#endif /* FLB_SYSTEM_WINDOWS */

/*
 * Custom scan function with HTTP filtering
 */
static int tail_http_filter_scan(struct mk_list *path_list,
                                 struct flb_tail_http_filter_config *http_ctx)
{
    int ret;
    struct mk_list *head;
    struct flb_slist_entry *pattern;
    struct flb_tail_config *ctx = http_ctx->tail_config;

    mk_list_foreach(head, path_list)
    {
        pattern = mk_list_entry(head, struct flb_slist_entry, _head);
        ret = tail_http_filter_scan_path(pattern->str, http_ctx);
        if (ret == -1)
        {
            flb_plg_warn(ctx->ins, "error scanning path: %s", pattern->str);
        }
        else
        {
            flb_plg_debug(ctx->ins, "%i new files found on path '%s' (http filtered)",
                          ret, pattern->str);
        }
    }

    return 0;
}

int in_tail_http_filter_init(struct flb_input_instance *ins,
                             struct flb_config *config, void *data)
{
    int ret;
    struct flb_tail_http_filter_config *ctx;
    struct flb_tail_config *tail_config;

    ctx = flb_calloc(1, sizeof(struct flb_tail_http_filter_config));
    if (!ctx)
    {
        flb_errno();
        return -1;
    }

    /* Set defaults before config_map_set which may override them */
    ctx->http_url = flb_sds_create("http://localhost:8080");
    ctx->http_key = flb_sds_create("allowed_patterns");
    ctx->http_timeout = 5;
    ctx->refresh_interval = 60;
    ctx->last_fetch_time = 0;

    ret = flb_input_config_map_set(ins, (void *)ctx);
    if (ret == -1)
    {
        flb_plg_error(ins, "configuration error");
        flb_sds_destroy(ctx->http_url);
        flb_sds_destroy(ctx->http_key);
        flb_free(ctx);
        return -1;
    }

    /* Initialize allowed_patterns list AFTER config_map_set to avoid being overwritten */
    mk_list_init(&ctx->allowed_patterns);

    /* Initialize global config list if needed */
    if (!http_filter_configs_initialized)
    {
        mk_list_init(&http_filter_configs);
        http_filter_configs_initialized = 1;
    }

    tail_config = flb_tail_config_create(ins, config);
    if (!tail_config)
    {
        flb_plg_error(ins, "failed to create tail config");
        flb_sds_destroy(ctx->http_url);
        flb_sds_destroy(ctx->http_key);
        flb_free(ctx);
        return -1;
    }

    ctx->tail_config = tail_config;
    ctx->tail_config->ins = ins;

    ctx->upstream = flb_upstream_create_url(config, ctx->http_url, FLB_IO_TCP, NULL);
    if (!ctx->upstream)
    {
        flb_plg_error(ins, "failed to create upstream");
        flb_tail_config_destroy(tail_config);
        flb_sds_destroy(ctx->http_url);
        flb_sds_destroy(ctx->http_key);
        flb_free(ctx);
        return -1;
    }

    ret = flb_tail_fs_init(ins, tail_config, config);
    if (ret == -1)
    {
        flb_plg_error(ins, "failed to initialize filesystem watcher");
        flb_upstream_destroy(ctx->upstream);
        flb_tail_config_destroy(tail_config);
        flb_sds_destroy(ctx->http_url);
        flb_sds_destroy(ctx->http_key);
        flb_free(ctx);
        return -1;
    }

    /* Fetch HTTP filter patterns */
    fetch_http_data(ctx, config);

    /* Initial scan of files with HTTP filtering */
    tail_http_filter_scan(tail_config->path_list, ctx);

    /* Set read_from_head for newly discovered files after initial scan */
    if (tail_config->read_newly_discovered_files_from_head)
    {
        tail_config->read_from_head = FLB_TRUE;
    }

    /* Add http_ctx to global list for lookup */
    mk_list_add(&ctx->_head, &http_filter_configs);

    /* Set context to tail_config (required for fs callbacks registered by flb_tail_fs_init) */
    flb_input_set_context(ins, tail_config);

    ret = flb_input_set_collector_event(ins, in_tail_http_filter_collect_static,
                                        tail_config->ch_manager[0], config);
    if (ret == -1)
    {
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
    if (ret == -1)
    {
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
    if (ret == -1)
    {
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
    if (ret == -1)
    {
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
    struct flb_tail_config *ctx = in_context;
    (void)ins;
    (void)config;

    return tail_signal_manager(ctx);
}

int in_tail_http_filter_exit(void *data, struct flb_config *config)
{
    struct flb_tail_config *tail_ctx = data;
    struct flb_tail_http_filter_config *http_ctx;

    if (tail_ctx)
    {
        http_ctx = get_http_ctx_from_tail_config(tail_ctx);
        if (http_ctx)
        {
            /* Remove from global list */
            mk_list_del(&http_ctx->_head);

            if (http_ctx->upstream)
            {
                flb_upstream_destroy(http_ctx->upstream);
            }

            struct pattern_entry *entry;
            struct mk_list *curr, *next;
            mk_list_foreach_safe(curr, next, &http_ctx->allowed_patterns)
            {
                entry = mk_list_entry(curr, struct pattern_entry, _head);
                flb_sds_destroy(entry->pattern);
                mk_list_del(&entry->_head);
                flb_free(entry);
            }

            flb_sds_destroy(http_ctx->http_url);
            flb_sds_destroy(http_ctx->http_key);
            flb_free(http_ctx);
        }

        flb_tail_file_remove_all(tail_ctx);
        flb_tail_fs_exit(tail_ctx);
        flb_tail_config_destroy(tail_ctx);
    }

    return 0;
}

void in_tail_http_filter_pause(void *data, struct flb_config *config)
{
    struct flb_tail_config *ctx = data;
    if (ctx)
    {
        flb_input_collector_pause(ctx->coll_fd_static, ctx->ins);
        flb_input_collector_pause(ctx->coll_fd_pending, ctx->ins);
    }
}

void in_tail_http_filter_resume(void *data, struct flb_config *config)
{
    struct flb_tail_config *ctx = data;
    if (ctx)
    {
        flb_input_collector_resume(ctx->coll_fd_static, ctx->ins);
        flb_input_collector_resume(ctx->coll_fd_pending, ctx->ins);
    }
}

static struct flb_config_map config_map[] = {
    {FLB_CONFIG_MAP_STR, "http_url", "http://localhost:8080",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, http_url),
     "HTTP URL to fetch allowed patterns"},
    {FLB_CONFIG_MAP_STR, "http_key", "allowed_patterns",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, http_key),
     "Key in JSON response that contains allowed patterns array"},
    {FLB_CONFIG_MAP_INT, "http_timeout", "5",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, http_timeout),
     "HTTP request timeout in seconds"},
    {FLB_CONFIG_MAP_INT, "refresh_interval", "60",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, refresh_interval),
     "Interval to refresh allowed patterns from HTTP URL"},

    /* Inherit all in_tail plugin configuration options */
    {
        FLB_CONFIG_MAP_CLIST, "path", NULL,
        0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, path_list),
        "pattern specifying log files or multiple ones through "
        "the use of common wildcards."},
    {FLB_CONFIG_MAP_CLIST, "exclude_path", NULL,
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, exclude_list),
     "Set one or multiple shell patterns separated by commas to exclude "
     "files matching a certain criteria, e.g: 'exclude_path *.gz,*.zip'"},
    {FLB_CONFIG_MAP_STR, "key", "log",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, key),
     "when a message is unstructured (no parser applied), it's appended "
     "as a string under the key name log. This option allows to define an "
     "alternative name for that key."},
    {FLB_CONFIG_MAP_BOOL, "read_from_head", "false",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, read_from_head),
     "For new discovered files on start (without a database offset/position), read the "
     "content from the head of the file, not tail."},
    {FLB_CONFIG_MAP_BOOL, "read_newly_discovered_files_from_head", "true",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, read_newly_discovered_files_from_head),
     "For new discovered files after start (without a database offset/position), read the "
     "content from the head of the file, not tail."},
    {FLB_CONFIG_MAP_STR, "refresh_interval", "60",
     0, FLB_FALSE, 0,
     "interval to refresh the list of watched files expressed in seconds."},
    {FLB_CONFIG_MAP_TIME, "watcher_interval", "2s",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, watcher_interval),
     "Interval to watch for file changes."},
    {FLB_CONFIG_MAP_TIME, "progress_check_interval", "2s",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, progress_check_interval),
     "Interval to check for progress in file processing."},
    {FLB_CONFIG_MAP_INT, "progress_check_interval_nsec", "0",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, progress_check_interval_nsec),
     "Nanoseconds part of progress check interval."},
    {FLB_CONFIG_MAP_TIME, "rotate_wait", "5",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, rotate_wait),
     "specify the number of extra time in seconds to monitor a file once is "
     "rotated in case some pending data is flushed."},
    {FLB_CONFIG_MAP_BOOL, "docker_mode", "false",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, docker_mode),
     "If enabled, the plugin will recombine split Docker log lines before "
     "passing them to any parser as configured above. This mode cannot be "
     "used at the same time as Multiline."},
    {FLB_CONFIG_MAP_INT, "docker_mode_flush", "4",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, docker_mode_flush),
     "wait period time in seconds to flush queued unfinished split lines."},
    {FLB_CONFIG_MAP_STR, "path_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, path_key),
     "set the 'key' name where the name of monitored file will be appended."},
    {FLB_CONFIG_MAP_STR, "offset_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, offset_key),
     "set the 'key' name where the offset of monitored file will be appended."},
    {FLB_CONFIG_MAP_TIME, "ignore_older", "0",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, ignore_older),
     "ignore records older than 'ignore_older'. Supports m,h,d (minutes, "
     "hours, days) syntax. Default behavior is to read all records. Option "
     "only available when a Parser is specified and it can parse the time "
     "of a record."},
    {FLB_CONFIG_MAP_BOOL, "ignore_active_older_files", "false",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, ignore_active_older_files),
     "ignore files that are older than the value set in ignore_older even "
     "if the file is being ingested."},
    {FLB_CONFIG_MAP_SIZE, "buffer_chunk_size", "32k",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, buf_chunk_size),
     "set the initial buffer size to read data from files. This value is "
     "used too to increase buffer size."},
    {FLB_CONFIG_MAP_SIZE, "buffer_max_size", "32k",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, buf_max_size),
     "set the limit of the buffer size per monitored file. When a buffer "
     "needs to be increased (e.g: very long lines), this value is used to "
     "restrict how much the memory buffer can grow. If reading a file exceed "
     "this limit, the file is removed from the monitored file list."},
    {FLB_CONFIG_MAP_SIZE, "static_batch_size", "512k",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, static_batch_size),
     "On start, Fluent Bit might process files which already contains data, "
     "these files are called 'static' files. The configuration property "
     "in question set's the maximum number of bytes to process per iteration "
     "for the static files monitored."},
    {FLB_CONFIG_MAP_SIZE, "event_batch_size", "512k",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, event_batch_size),
     "When Fluent Bit is processing files in event based mode the amount of"
     "data available for consumption could be too much and cause the input plugin "
     "to over extend and smother other plugins"
     "The configuration property sets the maximum number of bytes to process per iteration "
     "for the files monitored (in event mode)."},
    {FLB_CONFIG_MAP_BOOL, "skip_long_lines", "false",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, skip_long_lines),
     "if a monitored file reach it buffer capacity due to a very long line "
     "(buffer_max_size), the default behavior is to stop monitoring that "
     "file. This option alter that behavior and instruct Fluent Bit to skip "
     "long lines and continue processing other lines that fits into the buffer."},
    {FLB_CONFIG_MAP_BOOL, "exit_on_eof", "false",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, exit_on_eof),
     "exit Fluent Bit when reaching EOF on a monitored file."},
    {FLB_CONFIG_MAP_BOOL, "skip_empty_lines", "false",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, skip_empty_lines),
     "Allows to skip empty lines."},
    {FLB_CONFIG_MAP_BOOL, "truncate_long_lines", "false",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, truncate_long_lines),
     "Truncate overlong lines after input encoding to UTF-8"},
#ifdef __linux__
    {FLB_CONFIG_MAP_BOOL, "file_cache_advise", "true",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, file_cache_advise),
     "Use posix_fadvise for file access. Advise not to use kernel file cache."},
#endif
#ifdef FLB_HAVE_INOTIFY
    {FLB_CONFIG_MAP_BOOL, "inotify_watcher", "true",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, inotify_watcher),
     "set to false to use file stat watcher instead of inotify."},
#endif

/* Multiline Options */
#ifdef FLB_HAVE_PARSER
    {FLB_CONFIG_MAP_BOOL, "multiline", "false",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, multiline),
     "if enabled, the plugin will try to discover multiline messages and use "
     "the proper parsers to compose the outgoing messages. Note that when this "
     "option is enabled the Parser option is not used."},
    {FLB_CONFIG_MAP_TIME, "multiline_flush", "4",
     0, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, multiline_flush),
     "wait period time in seconds to process queued multiline messages."},
    {FLB_CONFIG_MAP_STR, "parser_firstline", NULL,
     0, FLB_FALSE, 0,
     "name of the parser that matches the beginning of a multiline message. "
     "Note that the regular expression defined in the parser must include a "
     "group name (named capture)."},
    {FLB_CONFIG_MAP_STR_PREFIX, "parser_", NULL,
     0, FLB_FALSE, 0,
     "optional extra parser to interpret and structure multiline entries. This "
     "option can be used to define multiple parsers, e.g: Parser_1 ab1, "
     "Parser_2 ab2, Parser_N abN."},

    /* Multiline Core Engine based API */
    {
        FLB_CONFIG_MAP_CLIST, "multiline.parser", NULL,
        FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_tail_http_filter_config, tail_config) + offsetof(struct flb_tail_config, multiline_parsers),
        "specify one or multiple multiline parsers: docker, cri, go, java, etc."},
#endif

#ifdef FLB_HAVE_UNICODE_ENCODER
    {
        FLB_CONFIG_MAP_STR,
        "unicode.encoding",
        NULL,
        0,
        FLB_FALSE,
        0,
        "specify the preferred input encoding for converting to UTF-8. "
        "Currently, UTF-16LE, UTF-16BE, auto are supported.",
    },
#endif
    {
        FLB_CONFIG_MAP_STR,
        "generic.encoding",
        NULL,
        0,
        FLB_FALSE,
        0,
        "specify the preferred input encoding for converting to UTF-8. "
        "Currently, the following encodings are supported: "
        "ShiftJIS, UHC, GBK, GB18030, Big5, "
        "Win866, Win874, "
        "Win1250, Win1251, Win1252, Win2513, Win1254, Win1255, WIn1256",
    },

    {0}};

struct flb_input_plugin in_tail_http_filter_plugin = {
    .name = "tail_http_filter",
    .description = "Tail files with HTTP-based filtering",
    .cb_init = in_tail_http_filter_init,
    .cb_pre_run = in_tail_http_filter_pre_run,
    .cb_collect = NULL,
    .cb_flush_buf = NULL,
    .cb_pause = in_tail_http_filter_pause,
    .cb_resume = in_tail_http_filter_resume,
    .cb_exit = in_tail_http_filter_exit,
    .config_map = config_map,
    .flags = 0};
