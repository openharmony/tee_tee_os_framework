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
#ifndef __SSAGENT_AGENT_H
#define __SSAGENT_AGENT_H

#include <tee_defines.h>
#include "tee_ss_agent_api.h"

bool is_client_register(uint32_t sender);
void ssa_send_agent_cmd(uint32_t id, uint32_t cmd, uint32_t *cmd_buff);
void ssa_obtain_agent_work_lock(uint32_t id);
void ssa_agent_work_unlock(uint32_t id);
TEE_Result ssa_get_msg(uint32_t *cmd, uint8_t *msg, uint32_t size, uint32_t *sender);
void register_uuid(uint32_t sender, TEE_UUID uuid, uint32_t user_id, bool ssa_enum_enable);
char pre_unregister_uuid(const union ssa_agent_msg *msg, uint32_t sender);
void ssa_register_uuid(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
TEE_Result set_caller_info_proc(uint32_t task_id, uint32_t cmd);
#define PERMSRV_SAVE_FILE "permsrv_save_file"
#endif
