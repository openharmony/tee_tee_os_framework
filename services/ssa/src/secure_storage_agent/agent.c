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
#include "ta_framework.h"
#include "tee_log.h"
#include "tee_init.h"
#include "tee_ext_api.h"
#include "tee_ss_agent_api.h"
#include "sfs_internal.h"
#include "agent.h"
#include "securec.h"
#include "tee_internal_task_pub.h"
#include <ipclib_hal.h>

static void ssa_msgqueue_add(uint32_t cmd, const union ssa_agent_msg *msg, uint32_t sndr)
{
    errno_t rc;
    ssa_cmd_t *cmd_oper = NULL;
    struct ssa_agent_rsp rsp   = {0};

    uint32_t in = g_ssa_msg_queue.in;
    tlogd("put msg %x to SSqueue[%u]\n", cmd, in);

    if (in >= SS_AGENT_MSG_QUEUE_SIZE) {
        tloge("invalid ssa msg queue in : [%u]\n", in);
        goto send_msg_to_ta;
    }

    if (g_ssa_msg_queue.msg[in].msg_id == 0xFFFFFFFF) {
        g_ssa_msg_queue.msg[in].msg_id = cmd;
        g_ssa_msg_queue.msg[in].sender = sndr;
        rc = memmove_s(&g_ssa_msg_queue.msg[in].msg, sizeof(g_ssa_msg_queue.msg[in].msg), msg,
            sizeof(union ssa_agent_msg));
        if (rc != EOK) {
            g_ssa_msg_queue.msg[in].msg_id = 0xFFFFFFFF;

            tloge("memmove ssa msg queue error %x\n", rc);
        } else {
            if (++in >= SS_AGENT_MSG_QUEUE_SIZE)
                in = 0;

            g_ssa_msg_queue.in = in;
        }
    } else {
        tloge("SSqueue overflow\n");
        for (uint32_t i = 0; i < SS_AGENT_MSG_QUEUE_SIZE; i++)
            tloge("ssa queue:%u, cmd:0x%x, taskid:0x%x", i,
                g_ssa_msg_queue.msg[i].msg_id, g_ssa_msg_queue.msg[i].sender);

        goto send_msg_to_ta;
    }

    return;

send_msg_to_ta:
        /* when set caller info failed, a message should be sent to TA
         * to prevent TA from being suspended */
        cmd_oper = ssa_find_cmd(cmd);
        if (cmd_oper != NULL && cmd_oper->need_ack == 1) {
            rsp.ret = TEE_ERROR_MSG_QUEUE_OVERFLOW;
            TEE_Result ret_ack = (uint32_t)ipc_msg_snd(cmd, sndr, (void *)&rsp, sizeof(rsp));
            if (ret_ack != SRE_OK)
                tloge("msg snd error %x\n", ret_ack);
        }
}
static TEE_Result ssa_not_file_operate(uint32_t cmd, uint8_t *msg, uint32_t sndr)
{
    uint32_t need_ack;
    uint32_t res_code;
    ssa_cmd_t *cmd_oper = NULL;
    struct ssa_agent_rsp rsp   = { 0 };

    tlogd("ssa_not_file_operate, cmd=%x", cmd);

    cmd_oper = ssa_find_cmd(cmd);
    if (cmd_oper == NULL) {
        tloge("ssa_find_cmd failed : %x , from %x\n", cmd, sndr);
        return TEE_ERROR_GENERIC;
    }

    if (cmd_oper->is_file_oper != NOT_FILE_OPERATION) {
        tlogd("cmd is file operate: %x , from %x\n", cmd, sndr);
        return TEE_ERROR_GENERIC;
    }

    rsp.ret  = TEE_ERROR_GENERIC;
    need_ack = cmd_oper->need_ack;
    if (cmd_oper->fn != NULL) {
        cmd_oper->fn((union ssa_agent_msg *)msg, sndr, &rsp);
    } else {
        tlogw("no process func for cmd %x, from %x", cmd, sndr);
    }

    if (need_ack) {
        tlogd("send msg to %x\n", sndr);
        res_code = (uint32_t)ipc_msg_snd(cmd, sndr, (void *)&rsp, sizeof(struct ssa_agent_rsp));
        if (res_code != SRE_OK)
            tlogw("msg snd error %x\n", res_code);
    }

    return TEE_SUCCESS;
}
static void ssa_deal_msg(uint32_t cmd, uint8_t *ret_msg, size_t msg_len, uint32_t sdr)
{
    union ssa_agent_msg tmp_msg;
    errno_t rc;

    (void)memset_s(&tmp_msg, sizeof(tmp_msg), 0, sizeof(tmp_msg));
    if (cmd == TEE_TASK_OPEN_TA_SESSION) {
        rc = memcpy_s(&tmp_msg, sizeof(tmp_msg), ret_msg, msg_len);
        if (rc != EOK) {
            tloge("memcpy_s ssa msg failed, ret 0x%x\n", rc);
            return;
        }

        tlogd("register task: %x-%x\n", tmp_msg.reg.taskid, tmp_msg.reg.uuid.timeLow);
        ssa_register_uuid(&tmp_msg, sdr, NULL);

        return;
    } else if (cmd == TEE_TASK_CLOSE_TA_SESSION) {
        rc = memcpy_s(&tmp_msg, sizeof(tmp_msg), ret_msg, msg_len);
        if (rc != EOK) {
            tloge("memcpy_s ssa msg failed, ret 0x%x\n", rc);
            return;
        }
        if (pre_unregister_uuid(&tmp_msg, sdr) == 0) {
            return; /* not mark as dead, has been remove the client directly. */
        } else {
            /* mark as dead, so need add msg to the queue */
        }
    } else {
        if (ssa_not_file_operate(cmd, ret_msg, sdr) == TEE_SUCCESS)
            return;
    }

    if (!is_client_register(sdr)) {
        tloge("client is not registered, taskid:0x%x", sdr);
        return;
    }

    ssa_msgqueue_add(cmd, (const union ssa_agent_msg *)ret_msg, sdr);
}

static uint32_t ssa_receive_msg(uint32_t uw_timeout, uint32_t *puw_msg_id, void *msgp,
                                uint16_t size, uint32_t *puw_sender_pid)
{
    return (uint32_t)ipc_msg_rcv_a(uw_timeout, puw_msg_id, msgp, size, puw_sender_pid);
}

/* globaltask and TA's msgs will go here when SSA wait REE agent.
 * 1. globaltask's msg which can goes here are either null msg, or send with struct union ssa_agent_msg.
 * 2. TA's msgs are all use union ssa_agent_msg.
 * 3. globaltask's msgs which use struct global_to_ta_msg are processed in ssa_obtain_agent_work_lock
 *    and ssa_agent_work_unlock, that means 'struct global_to_ta_msg' will never be used in this function.
 */
static void ssa_wait_msg(uint32_t want_cmd, uint8_t *msg, uint32_t size, uint32_t want_sdr)
{
    uint32_t cmd;
    uint32_t sdr;
    uint32_t ret;
    uint32_t cp_size;
    uint8_t ret_msg[sizeof(union ssa_agent_msg)];
    errno_t rc;

    while (1) {
        cmd = 0;
        sdr = 0;
        rc  = memset_s((void *)ret_msg, sizeof(union ssa_agent_msg), 0, sizeof(union ssa_agent_msg));
        if (rc != EOK)
            tloge("memset ret_msg failed %x\n", rc);

        ret = ssa_receive_msg(OS_WAIT_FOREVER, (UINT32 *)(&cmd), (void *)ret_msg, sizeof(union ssa_agent_msg), &sdr);
        if (ret != SRE_OK) {
            tloge("ssa msg rcv error %x\n", ret);
            continue;
        }

        tlogd("got msg %x from %x\n", cmd, sdr);

        if (want_cmd == cmd && want_sdr == sdr) {
            if (msg == NULL)
                break;

            cp_size = (size < sizeof(union ssa_agent_msg)) ? size : sizeof(union ssa_agent_msg);
            rc      = memmove_s(msg, size, ret_msg, cp_size);
            if (rc != EOK)
                tloge("memmove ssa msg, size %u error, ret %x\n", cp_size, rc);

            break;
        }

        ssa_deal_msg(cmd, ret_msg, sizeof(union ssa_agent_msg), sdr);
    }

    return;
}

void ssa_send_agent_cmd(uint32_t id, uint32_t cmd, uint32_t *cmd_buff)
{
    struct ta_to_global_msg send_msg;
    errno_t rc;
    uint32_t ret;

    if (cmd_buff != NULL)
        *cmd_buff = cmd;

    rc = memset_s((void *)&send_msg, sizeof(send_msg), 0, sizeof(send_msg));
    if (rc != EOK) {
        tloge("memset send_msg failed %x\n", rc);
        return;
    }

    send_msg.ret             = TEE_PENDING2;
    send_msg.agent_id        = id;
    send_msg.session_context = (void *)NULL;

    __asm__ volatile("isb");
    __asm__ volatile("dsb sy");

    ret = ipc_msg_snd(TEE_TASK_AGENT_SMC_CMD, get_global_handle(), &send_msg, sizeof(send_msg));
    if (ret != SRE_OK) {
        tloge("msg snd error %x\n", ret);
        return;
    }

    tlogd("ready to wait for rsp from nwd\n");

    /* no need to verify return value here */
    ssa_wait_msg(TEE_TASK_AGENT_SMC_ACK, NULL, 0, get_global_handle());
}

static void ssa_agent_lock_handler(uint32_t id, uint32_t lock_type)
{
    struct ta_to_global_msg send_msg;
    struct global_to_ta_msg ret_msg;
    errno_t rc;
    uint32_t i, ret;
    uint8_t *ret_data = NULL;

    rc = memset_s((void *)&send_msg, sizeof(send_msg), 0, sizeof(send_msg));
    if (rc != EOK) {
        tloge("memset failed %x\n", rc);
        return;
    }

    send_msg.ret             = TEE_PENDING2;
    send_msg.agent_id        = id;
    send_msg.session_context = NULL;
    /* Ask global task to lock the agent for us till the next invoke */
    ret = (uint32_t)ipc_msg_snd(lock_type, get_global_handle(), &send_msg, sizeof(send_msg));
    if (ret != SRE_OK) {
        tloge("msg snd error %x\n", ret);
        return;
    }
    /* Some form of error .... */
    tlogd("ready to wait for locking agent\n");

    do {
        rc = memset_s((void *)&ret_msg, sizeof(ret_msg), 0, sizeof(ret_msg));
        if (rc != EOK)
            tlogw("memset fail");

        ssa_wait_msg(TA_LOCK_ACK, (uint8_t *)&ret_msg, sizeof(ret_msg), get_global_handle());
        /* Couldn't get lock... */
        if (ret_msg.cmd_id != TEE_AGENT_LOCK) {
            tloge("ssa get agent lock exception:msg %x, cmd 0x%x, sender 0x%x\n", TA_LOCK_ACK, ret_msg.cmd_id,
                  get_global_handle());

            ret_data = (uint8_t *)(&ret_msg);
            for (i = 0; i < sizeof(ret_msg); i++)
                tloge("msg get from gtask is ret_data[%u] = 0x%x\n", i, ret_data[i]);

            continue; /* rcv the ta_lock agent ack msg */
        }

        break;
    } while (1);

    return;
}

void ssa_obtain_agent_work_lock(uint32_t id)
{
    ssa_agent_lock_handler(id, TA_LOCK_AGENT);
}

/* In many cases we know when the agent can be unlocked so make sure to allow other tasks
 * to use the agent ASAP */
void ssa_agent_work_unlock(uint32_t id)
{
    ssa_agent_lock_handler(id, TA_UNLOCK_AGENT);
}

TEE_Result ssa_get_msg(uint32_t *cmd, uint8_t *msg, uint32_t size, uint32_t *sender)
{
    uint32_t cp_size;
    uint8_t buf[sizeof(union ssa_agent_msg)];
    errno_t rc;
    uint32_t out = g_ssa_msg_queue.out;

    tlogd("start to get msg  %u %u\n", g_ssa_msg_queue.in, g_ssa_msg_queue.out);

    if (sender == NULL || cmd == NULL || msg == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    /* check if there are queued messages */
    if (g_ssa_msg_queue.msg[out].msg_id != 0xFFFFFFFF) {
        /* if there are, read them first */
        tlogd("get msg %x from SSqueue[%u]\n", g_ssa_msg_queue.msg[out].msg_id, out);
        *cmd    = g_ssa_msg_queue.msg[out].msg_id;
        *sender = g_ssa_msg_queue.msg[out].sender;

        cp_size = (size < sizeof(union ssa_agent_msg)) ? size : sizeof(union ssa_agent_msg);

        rc = memmove_s((void *)msg, size, (void *)(&g_ssa_msg_queue.msg[out].msg), cp_size);
        if (rc != EOK)
            return TEE_ERROR_SECURITY;

        g_ssa_msg_queue.msg[out].msg_id = (uint32_t)0xFFFFFFFF;
        if (++out >= SS_AGENT_MSG_QUEUE_SIZE)
            out = 0;

        g_ssa_msg_queue.out = out;
        return TEE_SUCCESS;
    }

    do {
        rc = memset_s((void *)buf, sizeof(union ssa_agent_msg), 0, sizeof(union ssa_agent_msg));
        if (rc != EOK)
            tlogw("memset failed %x\n", rc);

        uint32_t ret =
            (uint32_t)ipc_msg_rcv_a(OS_WAIT_FOREVER, (UINT32 *)(cmd), (void *)buf, sizeof(union ssa_agent_msg), sender);
        if (ret != SRE_OK) {
            tloge("ssa msg rcv error %x\n", ret);
            continue;
        }
        tlogd("got msg %x from %x\n", *cmd, *sender);

        cp_size = (size < sizeof(buf)) ? size : sizeof(buf);
        rc      = memmove_s(msg, size, buf, cp_size);
        if (rc != EOK)
            continue;

        break;
    } while (1);

    return TEE_SUCCESS;
}

TEE_Result set_caller_info_proc(uint32_t task_id, uint32_t cmd)
{
    uint32_t ret;
    struct task_caller_info caller_proc_info;
    ssa_cmd_t *cmd_oper = NULL;
    uint8_t ret_msg[sizeof(union ssa_agent_msg)];
    struct ssa_agent_rsp rsp;

    caller_proc_info.taskid = task_id;
    caller_proc_info.cmd = cmd;
    ret = ipc_msg_snd(TEE_TASK_SET_CALLER_INFO, get_global_handle(), &caller_proc_info, sizeof(caller_proc_info));
    if (ret != SRE_OK) {
        tloge("ssa send caller info failed 0x%x\n", ret);
        goto send_msg_to_ta;
    } else {
        (void)ssa_wait_msg(TEE_TASK_SET_CALLER_INFO_ACK, ret_msg, sizeof(ret_msg), get_global_handle());
        if (((union ssa_agent_msg *)ret_msg)->ret != TEE_SUCCESS) {
            tloge("set callerinfo fail, recv_ret:0x%x", ((union ssa_agent_msg *)ret_msg)->ret);
            goto send_msg_to_ta;
        }
    }

    return TEE_SUCCESS;

send_msg_to_ta:
    /* when set caller info failed, a message should be sent to TA
     * to prevent TA from being suspended */
    cmd_oper = ssa_find_cmd(cmd);
    if (cmd_oper != NULL && cmd_oper->need_ack == 1) {
        rsp.ret = TEE_ERROR_GENERIC;
        ret = (uint32_t)ipc_msg_snd(cmd, task_id, (void *)&rsp, sizeof(rsp));
        if (ret != SRE_OK)
            tloge("msg snd error %x\n", ret);
    }
    return TEE_ERROR_COMMUNICATION;
}

