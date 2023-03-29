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
#include "ssa_snd_msg.h"
#include <ipclib.h>
#include <tee_log.h>
#include <securec.h>

uint32_t send_msg_to_ssa(uint32_t cmd_id, const void *msg, uint32_t msg_size)
{
    struct msg_st msg_info = { 0 };
    cref_t rslot = 0;
    uint32_t ret;

    ret = (uint32_t)ipc_get_ch_from_path(SSA_SERVICE_PATH, &rslot);
    if (ret != 0) {
        tloge("get channel from pathmgr failed\n");
        return ret;
    }

    msg_info.msg_id = cmd_id;
    if (memcpy_s(msg_info.payload, sizeof(msg_info.payload), msg, msg_size) != 0) {
        (void)ipc_release_from_path(SSA_SERVICE_PATH, rslot);
        return -1;
    }

    ret = (uint32_t)ipc_msg_notification(rslot, &msg_info, sizeof(msg_info));
    if (ret != 0)
        tloge("msg snd error %x\n", ret);

    (void)ipc_release_from_path(SSA_SERVICE_PATH, rslot);
    return ret;
}
