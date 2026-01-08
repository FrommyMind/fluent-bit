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

#ifndef FLB_TAIL_HTTP_FILTER_H
#define FLB_TAIL_HTTP_FILTER_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_upstream.h>
#include "../in_tail/tail.h"

struct flb_tail_http_filter_config {
    struct flb_tail_config *tail_config;
    flb_sds_t http_url;
    flb_sds_t http_key;
    int http_timeout;
    struct flb_upstream *upstream;
    struct mk_list allowed_patterns;
    time_t last_fetch_time;
    int refresh_interval;
};

int in_tail_http_filter_init(struct flb_input_instance *ins,
                             struct flb_config *config, void *data);

int in_tail_http_filter_pre_run(struct flb_input_instance *ins,
                                struct flb_config *config, void *in_context);

int in_tail_http_filter_exit(void *data, struct flb_config *config);

void in_tail_http_filter_pause(void *data, struct flb_config *config);

void in_tail_http_filter_resume(void *data, struct flb_config *config);

int fetch_http_data(struct flb_tail_http_filter_config *ctx, struct flb_config *config);

int is_file_allowed(const char *file_path, struct flb_tail_http_filter_config *ctx);

#endif