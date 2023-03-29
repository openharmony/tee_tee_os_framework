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
#include <securec.h>
#include <sys/mman.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <tee_defines.h>
#include <ipclib.h>
#include <stdlib.h>
#include <ta_framework.h>
#include <chip_info.h>
#include <tee_ext_api.h>
#include <tee_config.h>
#include <tee_ss_agent_api.h>
#include "huk_derive_takey.h"
#include "huk_get_deviceid.h"
#include "huk_service_msg.h"
#include <ipclib_hal.h>
#include <spawn_ext.h>

#define MAGIC_STR_LEN               20

#define WEAK __attribute__((weak))

#define BSS_START_MAGIC 0x12345678
#define BSS_END_MAGIX   0x87654321

typedef TEE_Result (*cmd_func)(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
    uint32_t sndr_pid, const TEE_UUID *uuid);

struct cmd_operate_config_s {
    uint32_t cmd_id;
    cmd_func operate_func;
};

static const struct cmd_operate_config_s g_cmd_operate_config[] = {
    { CMD_HUK_DERIVE_TAKEY,         huk_task_derive_takey },
    { CMD_HUK_GET_DEVICEID,         huk_task_get_deviceid },
};
#define CMD_COUNT (sizeof(g_cmd_operate_config) / sizeof(g_cmd_operate_config[0]))

static void handle_cmd(const struct huk_srv_msg *msg, cref_t msghdl, uint32_t sndr_pid,
                       uint16_t msg_type, const TEE_UUID *uuid)
{
    uint32_t cmd_id;
    uint32_t self_pid;
    int32_t rc;
    struct huk_srv_rsp rsp;
    uint32_t i;

    (void)memset_s(&rsp, sizeof(rsp), 0, sizeof(rsp));
    rsp.data.ret = TEE_ERROR_GENERIC;
    cmd_id = msg->header.send.msg_id;
    self_pid = get_self_taskid();
    if (self_pid == SRE_PID_ERR) {
        tloge("huk service get self pid error\n");
        rsp.data.ret = TEE_ERROR_GENERIC;
        goto ret_flow;
    }

    for (i = 0; i < CMD_COUNT; i++) {
        if ((cmd_id != g_cmd_operate_config[i].cmd_id) || (g_cmd_operate_config[i].operate_func == NULL))
            continue;
        rsp.data.ret = g_cmd_operate_config[i].operate_func(msg, &rsp, sndr_pid, uuid);
        if (rsp.data.ret != TEE_SUCCESS && rsp.data.ret != TEE_ERROR_NOT_SUPPORTED)
            tloge("cmd 0x%x error, ret = 0x%x\n", cmd_id, rsp.data.ret);
        break;
    }
    if (i == CMD_COUNT)
        tloge("the cmd id 0x%x is not supported\n", cmd_id);

ret_flow:
    if (msg_type == MSG_TYPE_CALL) {
        rc = ipc_msg_reply(msghdl, &rsp, sizeof(rsp));
        if (rc != 0)
            tloge("reply error 0x%x\n", rc);
    }
}

__attribute__((visibility ("default"))) void tee_task_entry(int init_build)
{
    (void)init_build;
    struct huk_srv_msg msg;
    spawn_uuid_t uuid;
    cref_t ch = 0;
    struct src_msginfo info = {0};
    int32_t ret;

    (void)memset_s(&msg, sizeof(msg), 0, sizeof(msg));
    cref_t msghdl = ipc_get_my_msghdl();
    if (!check_ref_valid(msghdl)) {
        tloge("Cannot create msg hdl, %x\n", (int)msghdl);
        exit((int)msghdl);
    }

    if (ipc_create_channel_native(HUK_PATH, &ch) != 0) {
        tloge("create main thread native channel failed!\n");
        exit(-1);
    }

    while (1) {
        ret = ipc_msg_receive(ch, &msg, sizeof(msg), msghdl, &info, -1);
        if (ret < 0) {
            tloge("huk service: message receive failed, %llx\n", ret);
            continue;
        }

        if (getuuid((pid_t)info.src_pid, &uuid) != 0)
            tloge("huk service get uuid failed\n");

        if (info.src_pid == 0)
            handle_cmd(&msg, msghdl, GLOBAL_HANDLE, info.msg_type, &(uuid.uuid));
        else
            handle_cmd(&msg, msghdl, (uint32_t)pid_to_taskid(info.src_tid, info.src_pid),
                       info.msg_type, &(uuid.uuid));
    }

    tloge("huk service abort!\n");
}
