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
#ifndef LIBAGENT_BASE_TEE_AGENT_H
#define LIBAGENT_BASE_TEE_AGENT_H

#include <stdint.h>
#include <tee_defines.h>

TEE_Result tee_agent_lock(uint32_t agent_id);
TEE_Result tee_agent_unlock(uint32_t agent_id);
TEE_Result tee_send_agent_cmd(uint32_t agent_id);
TEE_Result tee_get_agent_buffer(uint32_t agent_id, void **buffer, uint32_t *length);

#endif
