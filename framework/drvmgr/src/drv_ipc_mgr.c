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
#include "drv_ipc_mgr.h"
#include <securec.h>
#include <tee_log.h>
#include <drv.h>
#include <tee_drv_internal.h>
#include "task_mgr.h"
#include <ipclib.h>

static int32_t get_drv_param(const struct tee_drv_param *params, char **param, uint32_t *len)
{
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    char *indata = (char *)(uintptr_t)(params->data);
    uint64_t param_len = args[DRV_PARAM_LEN_INDEX];
    uint64_t param_offset = args[DRV_PARAM_INDEX];

    if (param_len == 0) {
        tlogd("input null param\n");
        *param = NULL;
        *len = 0;
        return 0;
    }

    if (param_len > (SYSCAL_MSG_BUFFER_SIZE - sizeof(struct drv_req_msg_t))) {
        tloge("param_len:0x%llx is invalid\n", param_len);
        return -1;
    }

    if (param_offset != 0) {
        tloge("invalid param_offset:0x%llx\n", param_offset);
        return -1;
    }

    if (indata == NULL) {
        tloge("invalid param_indata\n");
        return -1;
    }

    *param = indata;
    *len = param_len;

    return 0;
}

static void trans_uuid_to_ul(const struct tee_uuid *uuid, uint64_t *uuid_time, uint64_t *uuid_clock)
{
    uint64_t uuid_c = 0;

    uint64_t uuid_t = uuid->timeLow;
    uuid_t = (uuid_t << UUID_TIME_LOW_OFFSET) |
        ((uint64_t)uuid->timeMid << UUID_TIME_MID_OFFSET) |
        ((uint64_t)uuid->timeHiAndVersion);

    uint32_t i;
    for (i = 0; i < NODE_LEN; i++)
        uuid_c = (uuid_c << BITS_NUM_PER_BYTE) | uuid->clockSeqAndNode[i];

    *uuid_time = uuid_t;
    *uuid_clock = uuid_c;

    tlogd("tran uuid:0x%x uuid_time:0x%llx uuid_clock:0x%llx\n", uuid->timeLow, *uuid_time, *uuid_clock);
}

static int64_t call_drv_open(const struct tee_drv_param *params, cref_t channel, uint64_t perm)
{
    char buf[SYSCAL_MSG_BUFFER_SIZE] = { 0 };
    struct drv_req_msg_t *msg    = (struct drv_req_msg_t *)buf;
    struct drv_reply_msg_t *rmsg = (struct drv_reply_msg_t *)buf;

    uint32_t ext_data = SYSCAL_MSG_BUFFER_SIZE - sizeof(struct drv_req_msg_t);
    char *param = NULL;
    uint32_t param_len;

    int32_t ret = get_drv_param(params, &param, &param_len);
    if (ret != 0)
        return -1;

    msg->args[DRV_FRAM_CMD_INDEX] = CALL_DRV_OPEN;
    msg->args[DRV_PARAM_INDEX] = 0; /* offset */
    msg->args[DRV_PARAM_LEN_INDEX] = param_len; /* buffer len */
    msg->args[DRV_PERM_INDEX] = perm;
    msg->args[DRV_CALLER_PID_INDEX] = params->caller_pid;
    trans_uuid_to_ul(&params->uuid, &msg->args[DRV_UUID_TIME_INDEX], &msg->args[DRV_UUID_CLOCK_INDEX]);

    if (param != NULL && param_len != 0 && memcpy_s(msg->data, ext_data, param, param_len) != 0) {
        tloge("copy param to data failed\n");
        return -1;
    }

    msg->header.send.msg_id = 0;
    msg->header.send.msg_size = sizeof(struct drv_req_msg_t) + param_len;

    ret = ipc_msg_call(channel, msg, msg->header.send.msg_size, rmsg, SYSCAL_MSG_BUFFER_SIZE, DRV_IPC_MAX_TIMEOUT);
    if (ret == E_EX_TIMER_TIMEOUT) {
        tloge("open msg call open timeout:%u\n", DRV_IPC_MAX_TIMEOUT);
        return -1;
    }

    if (ret != 0) {
        tloge("open msg call fail ret:0x%x\n", ret);
        return -1;
    }

    return rmsg->header.reply.ret_val;
}

int64_t drv_open_handle(const struct tee_drv_param *params, const struct task_node *node, uint64_t perm)
{
    if (params == NULL || params->args == 0 || node == NULL) {
        tloge("open invalid param\n");
        return -1;
    }

    int64_t ret = call_drv_open(params, node->drv_task.channel, perm);
    if (ret <= 0 || ret > FD_COUNT_MAX) {
        tloge("call drv open fail ret:0x%llx\n", ret);
        return -1;
    }

    return (int64_t)(((uint64_t)node->drv_task.drv_index << DRV_INDEX_OFFSET) | (uint64_t)ret);
}

int64_t call_drv_close(uint32_t taskid, const struct tee_uuid *caller_uuid, int64_t fd, cref_t channel)
{
    if (caller_uuid == NULL) {
        tloge("invalid close uuid\n");
        return -1;
    }

    if (fd < 0) {
        tloge("close invalid fd\n");
        return -1;
    }

    char buf[SYSCAL_MSG_BUFFER_SIZE] = { 0 };
    struct drv_req_msg_t *msg    = (struct drv_req_msg_t *)buf;
    struct drv_reply_msg_t *rmsg = (struct drv_reply_msg_t *)buf;

    msg->args[DRV_FRAM_CMD_INDEX] = CALL_DRV_CLOSE;
    msg->args[DRV_CLOSE_FD_INDEX] = (uint64_t)fd;
    msg->args[DRV_CALLER_PID_INDEX] = taskid;
    trans_uuid_to_ul(caller_uuid, &msg->args[DRV_UUID_TIME_INDEX], &msg->args[DRV_UUID_CLOCK_INDEX]);

    msg->header.send.msg_id = 0;
    msg->header.send.msg_size = sizeof(struct drv_req_msg_t);

    int32_t ret = ipc_msg_call(channel, msg, msg->header.send.msg_size, rmsg,
        SYSCAL_MSG_BUFFER_SIZE, DRV_IPC_MAX_TIMEOUT);
    if (ret == E_EX_TIMER_TIMEOUT) {
        tloge("close msg call close timeout:%u\n", DRV_IPC_MAX_TIMEOUT);
        return -1;
    }

    if (ret != 0) {
        tloge("close msg call fail ret:0x%x\n", ret);
        return -1;
    }

    return rmsg->header.reply.ret_val;
}

#ifdef TEE_SUPPORT_DRV_FD_DUMP
void call_drv_dump(cref_t channel)
{
    char buf[SYSCAL_MSG_BUFFER_SIZE] = { 0 };
    struct drv_req_msg_t *msg    = (struct drv_req_msg_t *)buf;
    struct drv_reply_msg_t *rmsg = (struct drv_reply_msg_t *)buf;

    msg->header.send.msg_id = DRV_DUMP_CMD_ID;
    msg->header.send.msg_size = sizeof(struct drv_req_msg_t);

    int32_t ret = ipc_msg_call(channel, msg, msg->header.send.msg_size, rmsg,
        SYSCAL_MSG_BUFFER_SIZE, -1);
    if (ret != 0)
        tloge("dump msg call fail ret:0x%x\n", ret);
}
#endif
