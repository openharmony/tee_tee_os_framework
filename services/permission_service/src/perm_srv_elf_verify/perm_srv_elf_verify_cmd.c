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
#include "perm_srv_elf_verify_cmd.h"
#include <securec.h>
#include <tee_log.h>
#include <ta_framework.h>
#include "tee_elf_verify.h"
#include "permission_service.h"
#include "handle_anti_rollback.h"
#include "perm_srv_ta_ctrl.h"
#include "perm_srv_ta_config.h"
#include <ipclib_hal.h>

static TEE_Result perm_srv_ta_run_authorization_check(const TEE_UUID *uuid, const ta_property_t *manifest,
                                      uint16_t target_version, bool mem_page_align)
{
    TEE_Result ret;
    struct config_info config;

    (void)memset_s(&config, sizeof(config), 0, sizeof(config));
    bool is_invalid = (uuid == NULL || manifest == NULL);
    bool is_valid_device = true;
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = perm_srv_check_ta_deactivated(uuid, target_version);
    if (ret != TEE_SUCCESS) {
        tloge("The TA version %u is not allowed\n", target_version);
        return TEE_ERROR_GENERIC;
    }

    if (perm_srv_get_config_by_uuid(uuid, &config) != TEE_SUCCESS) {
        tloge("Failed to get config by uuid\n");
        return TEE_ERROR_GENERIC;
    }

    is_valid_device = config.control_info.debug_info.valid_device;

    is_invalid = ((manifest->heap_size <= config.manifest_info.heap_size) &&
                  (manifest->stack_size <= config.manifest_info.stack_size) &&
                  (bool)manifest->instance_keep_alive == config.manifest_info.instance_keep_alive &&
                  (bool)manifest->multi_command == config.manifest_info.multi_command &&
                  (bool)manifest->multi_session == config.manifest_info.multi_session &&
                  (bool)manifest->single_instance == config.manifest_info.single_instance &&
                  is_valid_device && mem_page_align == config.manifest_info.mem_page_align);
    if (is_invalid) {
        return TEE_SUCCESS;
    } else {
        tloge("heap size 0x%x : 0x%x\n", manifest->heap_size, config.manifest_info.heap_size);
        tloge("stack size 0x%x : 0x%x\n", manifest->stack_size, config.manifest_info.stack_size);
        tloge("keep alive 0x%x : 0x%x\n", manifest->instance_keep_alive, config.manifest_info.instance_keep_alive);
        tloge("multi command 0x%x : 0x%x\n", manifest->multi_command, config.manifest_info.multi_command);
        tloge("multi session 0x%x : 0x%x\n", manifest->multi_session, config.manifest_info.multi_session);
        tloge("single instance 0x%x : 0x%x\n", manifest->single_instance, config.manifest_info.single_instance);
        tloge("is valid device 0x%x\n", is_valid_device);
        tloge("mem page align 0x%x : 0x%x\n", mem_page_align, config.manifest_info.mem_page_align);
    }

    tloge("ta run authorization check manifest compare error\n");

    return TEE_ERROR_GENERIC;
}

static TEE_Result check_perm_srv_elf_verify(const perm_srv_req_msg_t *msg, uint32_t sndr_taskid)
{
    if (msg == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (sndr_taskid != GLOBAL_HANDLE) {
        tloge("taload permission denied\n");
        return TEE_ERROR_ACCESS_DENIED;
    }

    if (msg->header.send.msg_size != sizeof(elf_verify_req)) {
        tloge("elf verify req msg size %u invalid\n", msg->header.send.msg_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

TEE_Result perm_srv_elf_verify(const perm_srv_req_msg_t *msg, uint32_t sndr_taskid,
                               const TEE_UUID *sndr_uuid, perm_srv_reply_msg_t *rsp)
{
    elf_verify_req req;
    elf_verify_reply reply;

    (void)sndr_uuid;
    (void)rsp;

    if (check_perm_srv_elf_verify(msg, sndr_taskid) != TEE_SUCCESS)
        return TEE_ERROR_BAD_PARAMETERS;

    if (memcpy_s(&req, sizeof(req), &(msg->req_msg.verify_req),
                 msg->header.send.msg_size) != EOK) {
        tloge("copy elf verify req failed\n");
        return TEE_ERROR_GENERIC;
    }

    (void)memset_s(&reply, sizeof(reply), 0, sizeof(reply));

    TEE_Result ret = secure_elf_verify(&req, &reply);
    if (ret != TEE_SUCCESS) {
        tloge("secure elf verify failed, ret=0x%x\n", ret);
    } else {
        if (reply.payload_hdr.ta_conf_size > 0)
            ret = perm_srv_ta_run_authorization_check(&(reply.srv_uuid),
                &(reply.ta_property), reply.mani_ext.target_version,
                reply.mani_ext.mem_page_align);
        if (ret == TEE_SUCCESS)
            ret = anti_version_rollback(&reply);
    }

    reply.verify_result = ret;

    uint32_t result = ipc_msg_snd(REGISTER_ELF_REQ, sndr_taskid, &reply, sizeof(reply));
    if (result != SRE_OK) {
        tloge("send reg elf req msg to failed, ret=0x%x\n", result);
        return TEE_ERROR_COMMUNICATION;
    }
    return TEE_SUCCESS;
}
