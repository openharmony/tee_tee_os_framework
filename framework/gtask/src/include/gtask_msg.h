/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#ifndef __GTASK_MSG_H_
#define __GTASK_MSG_H_

#include "tee_internal_api.h"
#include "ta_framework.h"
#include "gtask_inner.h"

struct global_to_ta_msg_32 {
    uint32_t session_id;
    uint32_t session_type;
    uint32_t cmd_id;
    uint32_t param_type;
    uint32_t params;          /* TEE_Param *params */
    uint32_t session_context; /* void *session_context */
    uint32_t dev_id;
    char first_session;
    char last_session;
    bool started;
    uint32_t stack_size;
    TEE_Result ret;
};

struct global_to_ta_msg_64 {
    uint32_t session_id;
    uint32_t session_type;
    uint32_t cmd_id;
    uint32_t param_type;
    uint64_t params;          /* TEE_Param *params */
    uint64_t session_context; /* void *session_context */
    uint32_t dev_id;
    char first_session;
    char last_session;
    bool started;
    uint32_t stack_size;
    TEE_Result ret;
};

typedef struct global_to_ta_msg_64 global_to_ta_msg;

struct ta_to_global_msg_32 {
    TEE_Result ret;
    uint32_t agent_id;
    uint32_t session_context; /* void *session_context */
    uint32_t ta2ta_from_taskid;
};

struct ta_to_global_msg_64 {
    TEE_Result ret;
    uint32_t agent_id;
    uint64_t session_context; /* void *session_context */
    uint32_t ta2ta_from_taskid;
};

typedef struct ta_to_global_msg_64 ta_to_global_msg;

typedef struct {
    TEE_UUID uuid;
    uint32_t stack_size;
    uint32_t heap_size;
    bool single_instance;
    bool multi_session;
    bool keep_alive;
    bool ssa_enum_enable;
    uint32_t other_buff; /* char *other_buff; TA's non-std property */
    uint32_t other_len;  /* non-std propery buff len */
} ta_property_t_32;

typedef struct {
    TEE_UUID uuid;
    uint32_t stack_size;
    uint32_t heap_size;
    bool single_instance;
    bool multi_session;
    bool keep_alive;
    bool ssa_enum_enable;
    uint64_t other_buff; /* char *other_buff; TA's non-std property */
    uint32_t other_len;  /* non-std propery buff len */
} ta_property_t_64;

struct ta_init_msg_32 {
    uint32_t fs_mem;       /* void *fs_mem; fs agent share mem */
    uint32_t misc_mem;     /* void *misc_mem; misc agent share mem */
    ta_property_t_32 prop; /* struct ta_property prop */
    uint32_t login_method;
    uint32_t time_data; /* void *time_data; async call notify share data */
    TEE_Time sys_time;
    uint32_t rtc_time;
};

struct ta_init_msg_64 {
    uint64_t fs_mem;       /* void *fs_mem; fs agent share mem */
    uint64_t misc_mem;     /* void *misc_mem; misc agent share mem */
    ta_property_t_64 prop; /* struct ta_property prop */
    uint32_t login_method;
    uint64_t time_data; /* void *time_data; async call notify share data */
    TEE_Time sys_time;
    uint32_t rtc_time;
};

typedef struct ta_init_msg_64 ta_init_msg;
#endif
