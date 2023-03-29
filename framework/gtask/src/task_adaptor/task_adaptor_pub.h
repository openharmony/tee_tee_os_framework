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

#ifndef GTASK_TASK_ADAPTOR_PUB_H
#define GTASK_TASK_ADAPTOR_PUB_H

#include <stddef.h>

void task_adapt_init(void);
int32_t task_adapt_set_caller_info(uint32_t cmd_id, uint32_t task_id,
    const uint8_t *msg_buf, uint32_t msg_size);
bool is_internal_task_by_task_id(uint32_t task_id);
bool is_internal_task_by_uuid(const TEE_UUID *uuid);
void task_adapt_crash_callback(uint32_t task_id);
void task_adapt_register_ta(uint32_t ta_task_id, uint32_t userid, bool ssa_enum_enable, const TEE_UUID *uuid);
void task_adapt_unregister_ta(const TEE_UUID *ta_uuid, uint32_t ta_task_id);
bool is_service_agent_request(uint32_t agent_task_id, uint32_t *caller_task_id, uint32_t **agent_status);
bool is_agent_response(uint32_t agent_id, uint32_t *agent_task_id, uint32_t *caller_task_id,
                       uint32_t **agent_status);
bool check_system_agent_permission(uint32_t task_id, uint32_t agent_id);
void task_adapt_register_agent(uint32_t agent_id);
void fs_agent_late_init(void);
void task_adapt_ta_create(uint32_t pid, const TEE_UUID *uuid);
void task_adapt_ta_release(const TEE_UUID *uuid);

#endif
