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
#include "task_se_service_adaptor.h"
#include <securec.h>
#include "se_service.h"
#include "tee_task_config.h"
#include "ta_framework.h"
#include "gtask_inner.h"
#include "ipclib.h"
#include "task_adaptor.h"
#include <ipclib_hal.h>

#define TASK_PRIO_SE_SERVICE (DEFAULT_TASK_PRIO - 2)
struct task_adaptor_info *register_task_se_srv(void);

static void send_response_to_pending_ta(const struct task_caller_info *caller_info)
{
    if (caller_info->taskid != INVALID_TASK_ID) {
        struct se_srv_rsp_t rsp;

        (void)memset_s(&rsp, sizeof(rsp), 0, sizeof(rsp));

        rsp.data.ret = TEE_ERROR_SESRV_NOT_AVAILABLE;
        uint32_t ret = ipc_msg_snd(caller_info->cmd, caller_info->taskid, &rsp, sizeof(rsp));
        if (ret != SRE_OK)
            tloge("send msg to se service failed:%u\n", ret);
    }
}

static void send_unregister_ta_to_sesrv(const char *cur_task_name, const struct reg_ta_info *reg_msg,
    uint32_t dest_task_id)
{
    (void)cur_task_name;
    struct se_srv_msg_t msg;
    errno_t rc;
    cref_t rslot = 0;

    (void)memset_s(&msg, sizeof(msg), 0, sizeof(msg));
    (void)dest_task_id;

    if (reg_msg == NULL) {
        tloge("msg is null, send unreg ta failed\n");
        return;
    }

    msg.header.send.msg_id = CMD_SESRV_UNREGISTER_TA;
    msg.data.reg_ta_info_msg.taskid = reg_msg->taskid;

    rc = ipc_get_ch_from_path(SE_PATH, &rslot);
    if (rc == -1) {
        tloge("sesrv: get channel from pathmgr failed\n");
        return;
    }

    rc = ipc_msg_notification(rslot, &msg, sizeof(msg));
    if (rc < 0)
        tloge("msg send 0x%llx failed: 0x%x\n", rslot, rc);

    (void)ipc_release_from_path(SE_PATH, rslot);
}

static void task_se_serv_crash_callback(const TEE_UUID *uuid, const char *task_name,
    const struct srv_adaptor_config_t *config)
{
    (void)uuid;
    (void)task_name;
    (void)config;
    struct task_adaptor_info *task = register_task_se_srv();
    if (task != NULL)
        send_response_to_pending_ta(&task->caller_info);
}

static void task_se_serv_init_priv_info(struct task_adaptor_info *task)
{
    task->task_crash_callback = task_se_serv_crash_callback;
    task->unregister_ta_to_task = send_unregister_ta_to_sesrv;
}

struct task_adaptor_info *register_task_se_srv(void)
{
    if (is_se_service_enable()) {
        TEE_UUID uuid = TEE_SERVICE_SE;
        struct task_adaptor_info *task = register_task_proc(&uuid, TASK_PRIO_SE_SERVICE,
            SE_TASK_NAME, task_se_serv_init_priv_info, NULL);
        if (task == NULL)
            tlogd("jump to reg task se service\n");
        return task;
    }
    return NULL;
}
