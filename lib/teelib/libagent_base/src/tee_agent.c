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
#include "tee_agent.h"
#include <ipclib.h>
#include <tee_defines.h>
#include <ta_framework.h>
#include <tee_ext_api.h>
#include <tee_log.h>
#include <tee_internal_task_pub.h>
#include <ipclib_hal.h>

TEE_Result tee_send_agent_cmd(uint32_t agent_id)
{
    struct ta_to_global_msg send_msg = {0};
    struct global_to_ta_msg ret_msg = {0};
    uint32_t ret;

    send_msg.ret             = TEE_PENDING2;
    send_msg.agent_id        = agent_id;
    send_msg.session_context = NULL;

    __asm__ volatile("isb");
    __asm__ volatile("dsb sy");

    ret = ipc_msg_snd(TEE_TASK_AGENT_SMC_CMD, GLOBAL_HANDLE, &send_msg, sizeof(send_msg));
    if (ret != SRE_OK) {
        tloge("msg snd error %x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    ret = ipc_msg_rcv_safe(OS_WAIT_FOREVER, NULL, &ret_msg, sizeof(ret_msg),
                           GLOBAL_HANDLE);
    tlogd("send agent cmd receive message from gtask %x\n", ret);
    if (ret != SRE_OK) {
        tloge("msg rcv error %x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    if (ret_msg.cmd_id == TEE_INVALID_AGENT) {
        tloge("send agent cmd to gtask failed, agent id = %u\n", agent_id);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result wait_msg_from_gtask(void)
{
    uint32_t ret;
    uint32_t sndr;
    uint32_t msg;
    uint32_t i;
    uint8_t *ret_data = NULL;
    struct global_to_ta_msg ret_msg = {0};

    do {
        ret = ipc_msg_rcv_a(OS_WAIT_FOREVER, &msg, &ret_msg, sizeof(ret_msg), &sndr);
        if (ret != SRE_OK) {
            if (ret == SRE_IPC_NO_CHANNEL_ERR) {
                tloge("msg rcv fail to get channel\n");
                return TEE_ERROR_GENERIC;
            }
            tloge("msg rcv error %x\n", ret);
            continue;
        }

        if (msg == TEE_TASK_SET_CALLER_INFO_ACK)
            continue;

        if (sndr != GLOBAL_HANDLE || msg != TA_LOCK_ACK) {
            tloge("get agent lock exception:msg %x, cmd 0x%x, sender 0x%x\n", msg, ret_msg.cmd_id, sndr);
            ret_data = (uint8_t *)(&ret_msg);
            for (i = 0; i < sizeof(ret_msg); i++)
                tloge("msg get from gtask is ret_data[%u] = 0x%x\n", i, ret_data[i]);
            continue; /* rcv the ta_lock agent ack msg */
        }

        /* if ta try to lock/unlock an invalid agent, gtask will return TEE_INVALID_AGENT */
        if (ret_msg.cmd_id != TEE_AGENT_LOCK) {
            tloge("agent lock/unlock failed ret cmd is %x\n", ret_msg.cmd_id);
            return TEE_ERROR_GENERIC;
        }
        break;
    } while (1);

    return TEE_SUCCESS;
}

TEE_Result tee_agent_lock(uint32_t agent_id)
{
    struct ta_to_global_msg send_msg = {0};
    uint32_t ret;

    /* Ask global task to lock the agent for us till the next invoke */
    send_msg.ret             = TEE_PENDING2;
    send_msg.agent_id        = agent_id;
    send_msg.session_context = NULL;

    ret = ipc_msg_snd(TA_LOCK_AGENT, GLOBAL_HANDLE, &send_msg, sizeof(send_msg));
    if (ret != SRE_OK) {
        tloge("msg snd to gtask error %x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    return wait_msg_from_gtask();
}

/*
 * In many cases we know when the agent can be unlocked so make sure to allow other tasks
 * to use the agent ASAP
 */
TEE_Result tee_agent_unlock(uint32_t agent_id)
{
    struct ta_to_global_msg send_msg = {0};
    uint32_t ret;

    /* Ask global task to lock the agent for us till the next invoke */
    send_msg.ret             = TEE_PENDING2;
    send_msg.agent_id        = agent_id;
    send_msg.session_context = NULL;

    ret = ipc_msg_snd(TA_UNLOCK_AGENT, GLOBAL_HANDLE, &send_msg, sizeof(send_msg));
    if (ret != SRE_OK) {
        tloge("msg snd to gtask error %x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    return wait_msg_from_gtask();
}

TEE_Result tee_get_agent_buffer(uint32_t agent_id, void **buffer, uint32_t *length)
{
    struct ta_to_global_msg send_msg  = {0};
    struct global_to_ta_msg entry_msg = {0};
    uint32_t ret;

    if (buffer == NULL || length == NULL) {
        tloge("invalid input parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    send_msg.agent_id = agent_id;
    ret = ipc_msg_snd(TA_GET_AGENT_BUFFER, GLOBAL_HANDLE, &send_msg, sizeof(send_msg));
    if (ret != SRE_OK) {
        tloge("msg snd error %x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    ret = ipc_msg_rcv_safe(OS_WAIT_FOREVER, NULL, &entry_msg, sizeof(entry_msg),
                           GLOBAL_HANDLE);
    if (ret != SRE_OK) {
        tloge("receive msg failed in get agent buffer, ret=0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }

    /*
     * we reused the members(cmd_id and session_context) of entry_msg,
     * which is not a good practice.
     * since those member used internally, without inducing problem.
     */
    if (entry_msg.cmd_id == TEE_RETURN_AGENT_BUFFER) {
        *buffer = entry_msg.session_context;
        *length = entry_msg.param_type;
    } else {
        tloge("Failed to get buffer of agent %u\n", agent_id);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

/* we keep the old interface to compat with old TA */
void obtain_agent_work_lock(uint32_t agent_id)
{
    TEE_Result ret = tee_agent_lock(agent_id);
    if (ret != TEE_SUCCESS)
        tloge("failed to lock agent 0x%x\n", agent_id);
}

void agent_work_unlock(uint32_t agent_id)
{
    TEE_Result ret = tee_agent_unlock(agent_id);
    if (ret != TEE_SUCCESS)
        tloge("failed to unlock agent 0x%x\n", agent_id);
}
