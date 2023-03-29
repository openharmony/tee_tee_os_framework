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

#include <stddef.h>
#include <teecall.h>
#include <mem_ops.h>
#include <tee_sharemem.h>
#include <dyn_conf_dispatch_inf.h>
#include "tee_log.h"
#include "ta_framework.h"
#include "gtask_inner.h"
#include "ext_interface.h"
#include "mem_manager.h"
#include "service_manager.h"
#include "tee_ext_api.h"
#include "tee_config.h"
#include "securec.h"
#include "gtask_core.h" /* for find_task */
#include <ipclib_hal.h>

static bool g_rdr_mem_registered = false;

#define KERNEL_IMG_IS_ENG 1

TEE_Result map_rdr_mem(const smc_cmd_t *cmd)
{
    TEE_Param *tee_param = NULL;
    uint64_t rdr_mem_addr;
    uint32_t rdr_mem_size;
    uint32_t param_types  = 0;
    uint64_t map_mem_addr = 0;
    bool is_cache_mem = false;

    if (cmd == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (g_rdr_mem_registered) {
        tloge("rdr mem already registered\n");
        return TEE_ERROR_GENERIC;
    }

    if (cmd_global_ns_get_params(cmd, &param_types, &tee_param) != TEE_SUCCESS) {
        tloge("failed to map operation!\n");
        return TEE_ERROR_GENERIC;
    }

    /* check params types */
    if ((TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        (TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        (TEE_PARAM_TYPE_GET(param_types, 2) != TEE_PARAM_TYPE_VALUE_INPUT)) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* this condition should never happen here */
    if (tee_param == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    tlogd("cmd id=0x%x\n", cmd->cmd_id);

    /* this will only be called once when booting up, the addr is trusted */
    rdr_mem_addr = tee_param[0].value.a | (((uint64_t)tee_param[0].value.b) << SHIFT_OFFSET);
    rdr_mem_size = tee_param[1].value.a;
    is_cache_mem = tee_param[2].value.a;

    // check rdr memory address.
    if (task_map_ns_phy_mem(0, rdr_mem_addr, rdr_mem_size, &map_mem_addr) != 0) {
        tloge("map rdr mem addr failed\n");
        return TEE_ERROR_GENERIC;
    }

    char chip_type[CHIP_TYPE_LEN_MAX] = {0};
    if (tee_get_chip_type(chip_type, CHIP_TYPE_LEN_MAX) != 0) {
        tee_push_rdr_update_addr(rdr_mem_addr, (uint32_t)rdr_mem_size,
            is_cache_mem, "chip type not set", (uint32_t)strlen("chip type not set") + 1);
    } else {
        tee_push_rdr_update_addr(rdr_mem_addr, (uint32_t)rdr_mem_size, is_cache_mem, chip_type, CHIP_TYPE_LEN_MAX);
    }

    (void)task_unmap(0, map_mem_addr, rdr_mem_size);

    g_rdr_mem_registered = true;
    return TEE_SUCCESS;
}

static TEE_Result process_get_reeinfo(uint32_t task_id, struct session_struct *session)
{
    struct global_to_ta_for_uid buffer_msg = {0};

    /* uid is equal to userId*100000 + appId%100000 */
    if (session->cmd_type == CMD_TYPE_NS_TO_SECURE) {
        buffer_msg.userid = session->cmd_in.uid / PER_USER_RANGE;
        buffer_msg.appid  = session->cmd_in.uid % PER_USER_RANGE;
    } else {
        buffer_msg.userid = 0;
        buffer_msg.appid  = 0;
    }
    buffer_msg.cmd_id = TEE_GET_REEINFO_SUCCESS;

    uint32_t ret = ipc_msg_snd(0x0, task_id, &buffer_msg, sizeof(buffer_msg));
    if (ret != 0) {
        tloge("get reeinof msg send to ta failed:0x%x\n", ret);
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

int32_t handle_info_query(uint32_t cmd_id, uint32_t task_id, const uint8_t *msg_buf, uint32_t msg_size)
{
    TEE_Result ret;
    struct service_struct *service = NULL;
    struct session_struct *session = NULL;

    (void)msg_buf;
    (void)msg_size;

    if (find_task(task_id, &service, &session) == false) {
        tloge("find task 0x%x failed, query info %u failed\n", task_id, cmd_id);
        return GT_ERR_END_CMD;
    }

    switch (cmd_id) {
    case TA_GET_REEINFO:
        ret = process_get_reeinfo(task_id, session);
        break;
    default:
        ret = TEE_ERROR_BAD_PARAMETERS;
        tloge("invalid info query cmd %u\n", cmd_id);
        break;
    }
    if (ret != TEE_SUCCESS)
        return GT_ERR_END_CMD;

    return GT_ERR_OK;
}
