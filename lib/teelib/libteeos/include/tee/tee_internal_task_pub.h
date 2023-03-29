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

#ifndef TEE_INTERNAL_TASK_PUB_H
#define TEE_INTERNAL_TASK_PUB_H

#include <stddef.h>
#include "tee_defines.h"
#include "ta_framework.h"
#include "tee_service_public.h"

/*
 * here 10 is based on experience, we need to ensure that
 * the number of clients accessing the service does not exceed this SRV_MAX_CLIENTS
 */
#define SRV_MAX_CLIENTS (10 * TA_SESSION_MAX)

/*
 * these pub cmd should be defined very carefully,
 * cannot conflict with cmd of internal tasks
 */
enum TEE_INTERNAL_TASK_MSG_CMD {
    TEE_TASK_MSG_BASE            = 0x1000,
    TEE_TASK_OPEN_TA_SESSION     = TEE_TASK_MSG_BASE + 1, /* gtask send TA open session msg to internal task */
    TEE_TASK_CLOSE_TA_SESSION    = TEE_TASK_MSG_BASE + 2, /* gtask send TA close session msg to internal task */
    TEE_TASK_REGISTER_AGENT      = TEE_TASK_MSG_BASE + 3, /* only for ssa, gtask -> ssa */
    TEE_TASK_SET_CALLER_INFO     = TEE_TASK_MSG_BASE + 4, /* internal task send caller ta gtask */
    TEE_TASK_SET_CALLER_INFO_ACK = TEE_TASK_MSG_BASE + 5, /* gtask -> internal task */
    TEE_TASK_AGENT_SMC_CMD       = TEE_TASK_MSG_BASE + 6, /* system agent service -> gtask */
    TEE_TASK_AGENT_SMC_ACK       = TEE_TASK_MSG_BASE + 7, /* gtask -> system agent service */
    TEE_TASK_UNRESISTER_SERVICE  = TEE_TASK_MSG_BASE + 8, /* dynamic service to gtask */
    TEE_TASK_CREATE_TA_SERVICE   = TEE_TASK_MSG_BASE + 9, /* gtask send TA create service msg to internal task */
    TEE_TASK_RELEASE_TA_SERVICE  = TEE_TASK_MSG_BASE + 10, /* gtask send TA release service msg to internal task */
    TEE_TASK_MSG_END
};

struct reg_agent_buf {
    uint32_t agentid;
    paddr_t phys_addr;
    uint32_t size;
};

struct task_caller_info {
    uint32_t taskid;
    uint32_t cmd;
};

#endif
