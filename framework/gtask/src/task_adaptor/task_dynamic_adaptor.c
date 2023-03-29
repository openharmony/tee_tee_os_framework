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

#include "task_dynamic_adaptor.h"
#include <securec.h>
#include <ipclib.h>
#include <tee_service_public.h>
#include "task_adaptor.h"
#include "gtask_inner.h"
#include "agent_manager.h"

static void task_crash_callback(const TEE_UUID *uuid, const char *task_name,
    const struct srv_adaptor_config_t *srv_config)
{
    if (uuid == NULL || task_name == NULL || srv_config == NULL)
        return;
    register_dynamic_task(uuid, task_name, srv_config);
}

static void send_msg_to_srv(const char *cur_task_name, const struct reg_ta_info *ta_info, uint32_t msg_id)
{
    int32_t ret;
    cref_t ch = 0;
    struct tee_service_ipc_msg_req req_msg = {0};

    if (ta_info == NULL) {
        tloge("msg is null, send ta reg msg to srv failed\n");
        return;
    }

    req_msg.cmd = msg_id;
    errno_t rc = memcpy_s(&req_msg.msg, sizeof(req_msg.msg), ta_info, sizeof(*ta_info));
    if (rc != 0) {
        tloge("msg cpy failed, ret=0x%x\n", rc);
        return;
    }

    ret = ipc_get_ch_from_path(cur_task_name, &ch);
    if (ret != 0) {
        tloge("get %s ch from pathmgr failed, ret=0x%x\n", cur_task_name, ret);
        return;
    }

    ret = ipc_msg_notification(ch, &req_msg, sizeof(req_msg));
    (void)ipc_release_from_path(cur_task_name, ch);
    if (ret != 0)
        tloge("msg send to 0x%llx failed: 0x%x\n", ch, ret);
}

static void task_send_ta_unregister_msg(const char *cur_task_name,
    const struct reg_ta_info *reg_msg, uint32_t dest_task_id)
{
    (void)dest_task_id;
    send_msg_to_srv(cur_task_name, reg_msg, TEE_TASK_CLOSE_TA_SESSION);
}

static void task_send_ta_create_msg(const char *cur_task_name,
    const struct reg_ta_info *reg_msg, uint32_t dest_task_id)
{
    (void)dest_task_id;
    send_msg_to_srv(cur_task_name, reg_msg, TEE_TASK_CREATE_TA_SERVICE);
}

static void task_send_ta_release_msg(const char *cur_task_name,
    const struct reg_ta_info *reg_msg, uint32_t dest_task_id)
{
    (void)dest_task_id;
    send_msg_to_srv(cur_task_name, reg_msg, TEE_TASK_RELEASE_TA_SERVICE);
}

static void task_init_priv_info(struct task_adaptor_info *task)
{
    if (task->agent_id != 0)
        task->register_agent_buffer_to_task = register_agent_buffer_to_task;
    if (task->crash_callback)
        task->task_crash_callback           = task_crash_callback;
    if (task->is_need_release_ta_res)
        task->unregister_ta_to_task         = task_send_ta_unregister_msg;
    if (task->is_need_create_msg)
        task->send_ta_create_msg_to_task    = task_send_ta_create_msg;
    if (task->is_need_release_msg)
        task->send_ta_release_msg_to_task   = task_send_ta_release_msg;
}

#define TASK_PRIO_DEMO (DEFAULT_TASK_PRIO - 1)
void register_dynamic_task(const TEE_UUID *uuid, const char *task_name,
    const struct srv_adaptor_config_t *srv_config)
{
    if (uuid == NULL || task_name == NULL || srv_config == NULL)
        return;

    struct task_adaptor_info *task = NULL;
    task = find_task_by_uuid(uuid);
    if (task != NULL && task->task_id != INVALID_TASK_ID)
        return;

    task = register_task_proc(uuid, srv_config->task_prio,
        task_name, task_init_priv_info, srv_config);
    if (task == NULL)
        tlogd("jump to reg task %s\n", task_name);
}
