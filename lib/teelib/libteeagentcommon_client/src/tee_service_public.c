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
#include "tee_service_public.h"
#include <securec.h>
#include "ta_framework.h"
#include "tee_log.h"
#include "ipclib.h"

void tee_common_ipc_proc_cmd(const char *task_name,
                             uint32_t snd_cmd, const tee_service_ipc_msg *snd_msg,
                             uint32_t ack_cmd, tee_service_ipc_msg_rsp *rsp_msg)
{
    int32_t ret;
    cref_t ch = 0;
    struct tee_service_ipc_msg_req req_msg = {0};

    if (task_name == NULL || snd_msg == NULL || rsp_msg == NULL)
        return;

    (void)ack_cmd;
    req_msg.cmd = snd_cmd;
    errno_t rc = memcpy_s(&req_msg.msg, sizeof(req_msg.msg), snd_msg, sizeof(*snd_msg));
    if (rc != EOK) {
        tloge("msg cpy failed, task=%s, rc=%d\n", task_name, rc);
        return;
    }

    ret = ipc_get_ch_from_path(task_name, &ch);
    if (ret != 0) {
        tloge("get ch from pathmgr failed, task=%s, ret=0x%x\n", task_name, ret);
        return;
    }

    ret = ipc_msg_call(ch, &req_msg, sizeof(req_msg), rsp_msg, sizeof(*rsp_msg), OS_WAIT_FOREVER);
    if (ret != 0)
        tloge("msg send to 0x%llx failed: 0x%x\n", ch, ret);

    ret = (int32_t)ipc_release_from_path(task_name, ch);
    if (ret != 0) {
        tloge("release path failed, task=%s, ret=0x%x\n", task_name, ret);
        return;
    }
}
