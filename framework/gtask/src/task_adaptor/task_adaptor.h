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

#ifndef GTASK_TASK_ADAPTOR_H
#define GTASK_TASK_ADAPTOR_H

#include <dlist.h>
#include "tee_internal_api.h"
#include "tee_internal_task_pub.h"

struct srv_adaptor_config_t {
    uint32_t task_prio;
    uint32_t agent_id;
    bool is_need_release_ta_res;
    bool crash_callback;
    bool is_need_create_msg;
    bool is_need_release_msg;
};

typedef void (*register_ta_to_task_f)(const struct reg_ta_info *reg_msg, uint32_t dest_task_id);
typedef void (*unregister_ta_to_task_f)(const char *cur_task_name,
    const struct reg_ta_info *reg_msg, uint32_t dest_task_id);
typedef void (*task_crash_callback_f)(const TEE_UUID *uuid, const char *task_name,
    const struct srv_adaptor_config_t *config);
typedef void (*register_agent_buffer_to_task_f)(uint32_t agent_id, uint32_t dest_task_id);
typedef void (*send_ta_create_msg_to_task_f)(const char *cur_task_name,
    const struct reg_ta_info *msg, uint32_t dest_task_id);
typedef void (*send_ta_release_msg_to_task_f)(const char *cur_task_name,
    const struct reg_ta_info *msg, uint32_t dest_task_id);

#define INVALID_TASK_ID 0
#define MAX_TASK_NAME_LEN 64
struct task_adaptor_info {
    struct dlist_node task_node;
    char task_name[MAX_TASK_NAME_LEN];
    TEE_UUID uuid;
    uint32_t task_id;
    uint32_t task_prio;
    bool is_agent;
    uint32_t agent_id;
    uint32_t agent_status;
    bool is_need_release_ta_res;
    bool crash_callback;
    bool is_need_create_msg;
    bool is_need_release_msg;
    struct task_caller_info caller_info;
    register_ta_to_task_f register_ta_to_task;
    unregister_ta_to_task_f unregister_ta_to_task;
    task_crash_callback_f task_crash_callback;
    register_agent_buffer_to_task_f register_agent_buffer_to_task;
    send_ta_create_msg_to_task_f send_ta_create_msg_to_task;
    send_ta_release_msg_to_task_f send_ta_release_msg_to_task;
};

typedef void (*task_init_priv_info_f)(struct task_adaptor_info *task);

struct task_adaptor_info *find_task_by_taskid(uint32_t task_id);
void del_task_from_list(const TEE_UUID *uuid);
void send_register_ta_to_task(const struct reg_ta_info *reg_msg, uint32_t dest_task_id);
void send_unregister_ta_to_task(const char *cur_task_name, const struct reg_ta_info *reg_msg,
    uint32_t dest_task_id);
struct task_adaptor_info *find_task_by_uuid(const TEE_UUID *uuid);
struct task_adaptor_info *register_task_proc(const TEE_UUID *uuid, uint16_t task_prio, const char *task_name,
    const task_init_priv_info_f task_init_priv_info, const struct srv_adaptor_config_t *srv_config);
void task_adapt_send_ta_create_msg(const struct reg_ta_info *msg, uint32_t dest_task_id);
void task_adapt_send_ta_release_msg(const struct reg_ta_info *msg, uint32_t dest_task_id);

#if (defined CONFIG_APP_TEE_TEST_SERVICE || defined CONFIG_APP_TEE_TEST_SERVICE_A64)
struct task_adaptor_info *register_task_test_srv(void);
#endif
#endif
