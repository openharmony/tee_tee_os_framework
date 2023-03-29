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
#ifndef GTASK_AGENT_MANAGER_H
#define GTASK_AGENT_MANAGER_H

#include <dlist.h>
#include "gtask_core.h"

TEE_Result register_agent(const smc_cmd_t *cmd);
TEE_Result unregister_agent(const smc_cmd_t *cmd);
TEE_Result agent_late_init(const smc_cmd_t *cmd);
TEE_Result tee_get_agent_buffer(uint32_t agent_id, paddr_t *buffer, uint32_t *length);
void tee_unlock_agents(struct session_struct *session);
void agent_manager_init(void);
void register_agent_buffer_to_task(uint32_t agent_id, uint32_t dest_task_id);
TEE_Result set_service_thread_cmd(const smc_cmd_t *cmd, bool *async);
bool service_thread_request_dequeue(const smc_cmd_t *in, smc_cmd_t *out);

int32_t handle_agent_request(uint32_t cmd_id, uint32_t task_id,
    const uint8_t *msg_buf, uint32_t msg_size);
int32_t handle_service_agent_back_cmd(const smc_cmd_t *cmd);
int32_t handle_ta_agent_back_cmd(smc_cmd_t *cmd);

#endif /* GTASK_AGENT_MANAGER_H */
