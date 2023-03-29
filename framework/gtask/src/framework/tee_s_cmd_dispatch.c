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
#include "tee_s_cmd_dispatch.h"
#include <securec.h>
#include "tee_common.h"
#include "global_task.h"
#include "gtask_inner.h"
#include "gtask_msg.h"
#include "gtask_adapt.h"
#include "tee_task_exception.h"
#include "tee_internal_task_pub.h"
#include "tee_app_load_srv.h"
#include "task_adaptor_pub.h"
#include "session_manager.h"
#include "mem_manager.h"
#include "agent_manager.h"
#include "ext_interface.h"
#include "tee_load_lib.h"
#include <ipclib_hal.h>

static void s_cmd_response(smc_cmd_t *cmd, uint32_t ret_task_id)
{
    struct ta2ta_ret_msg ret_msg = {0};

    ret_msg.ret = cmd->ret_val;

    TEE_Result ret = copy_pam_to_src(cmd->cmd_id, true);
    if (ret != TEE_SUCCESS)
        ret_msg.ret = ret;

    if (memcpy_s(&ret_msg.cmd, sizeof(ret_msg.cmd), cmd, sizeof(*cmd)) != EOK) {
        tloge("memcpy ta2ta back cmd failed\n");
        ret_msg.ret = TEE_ERROR_GENERIC;
    }

    (void)unmap_secure_operation(cmd);

    (void)ipc_msg_snd(TA2TA_CALL, ret_task_id, &ret_msg, sizeof(ret_msg));
}

static void gt_cmd_response(smc_cmd_t *cmd, uint32_t cmd_type, uint32_t ret_task_id)
{
    /* Dispatch CA answer or agent request */
    if (cmd_type == CMD_TYPE_NS_TO_SECURE)
        ns_cmd_response(cmd);
    else if (cmd_type == CMD_TYPE_SECURE_TO_SECURE)
        s_cmd_response(cmd, ret_task_id);
}

static void process_ta2ta_cmd(smc_cmd_t *cmd, uint32_t task_id, const struct ta2ta_info_t *ta2ta_info)
{
    bool async = false;
    TEE_Result ret;

    if (cmd->cmd_type == CMD_TYPE_GLOBAL) {
        ret = process_ta_common_cmd(cmd, CMD_TYPE_SECURE_TO_SECURE, task_id, &async, ta2ta_info);
    } else {
        /* resume app task that pending on message */
        ret = start_ta_task(cmd, CMD_TYPE_SECURE_TO_SECURE);
        if (ret == TEE_SUCCESS)
            async = true;
    }

    /* In case of error we should send the error right now */
    if (!async)
        goto response;

    return;
response:
    set_tee_return_origin(cmd, TEE_ORIGIN_TEE);
    set_tee_return(cmd, ret);
    s_cmd_response(cmd, task_id);
}

static int32_t handle_ta2ta_cmd(uint32_t cmd_id, uint32_t task_id, const uint8_t *msg_buf, uint32_t msg_size)
{
    TEE_Result ret;
    errno_t rc;
    smc_cmd_t cmd;
    struct ta2ta_msg msg;
    struct ta2ta_info_t ta2ta_info = {0};

    (void)cmd_id;
    if (msg_size < sizeof(msg)) {
        tloge("invalid msg param, msg size %u\n", msg_size);
        return GT_ERR_END_CMD;
    }

    (void)memset_s(&cmd, sizeof(cmd), 0, sizeof(cmd));
    rc = memcpy_s(&msg, sizeof(msg), msg_buf, sizeof(msg));
    if (rc != EOK) {
        tloge("memcpy ta2ta msg failed, rc=%d, line:%d\n", rc, __LINE__);
        return GT_ERR_END_CMD;
    }

    /* init this secure call's context */
    ret = init_ta2ta_context(&cmd, msg.cmd, task_id);
    if (ret != TEE_SUCCESS) {
        tloge("init ta2ta context failed, ret = 0x%x, id=0x%x\n", ret, task_id);
        set_tee_return_origin(&cmd, TEE_ORIGIN_TEE);
        set_tee_return(&cmd, ret);
        s_cmd_response(&cmd, task_id);
        return GT_ERR_END_CMD;
    }
    ta2ta_info.handle         = (int)msg.handle;
    ta2ta_info.is_load_worked = msg.is_load_worked;
    process_ta2ta_cmd(&cmd, task_id, &ta2ta_info);
    return GT_ERR_OK;
}

static int32_t call_ta_open_session_init(const ta_to_global_msg *ret_msg, bool *need_response)
{
    tlogd("TA open session step 1 done\n");
    if (ret_msg->ret != TEE_SUCCESS) {
        tloge("open session init return fail, ret = 0x%x\n", ret_msg->ret);
        process_open_session_error();
        /* First step failed, send answer to NWD */
        *need_response = true;
        return GT_ERR_END_CMD;
    }
    /*
     * If nothing to process anymore, then send answer back to nwd,
     * otherwise continue with next step
     */
    if (process_init_session()) {
        tlogd("TA open session going for step 2\n");
        return GT_ERR_END_CMD;
    }

    return GT_ERR_OK;
}

static void call_ta_open_session_prop(ta_to_global_msg *ret_msg, const smc_cmd_t *cmd,
    uint32_t cmd_type, bool *need_response)
{
    tlogd("TA open session step 2 done\n");
    if (ret_msg->ret != TEE_SUCCESS) {
        tloge("init no-standard property fail, ret = 0x%x\n", ret_msg->ret);
        process_open_session_error();
        /* Second step failed, send answer to NWD */
        *need_response = true;
    } else {
        if (process_open_session(cmd, cmd_type) != TEE_SUCCESS) {
            tloge("init no-standard property2 failed\n");
            ret_msg->ret = TEE_ERROR_GENERIC;
            *need_response = true;
        }
    }
}

static void call_ta_open_session(ta_to_global_msg *ret_msg, struct session_struct *session,
    struct service_struct *service, bool *need_response)
{
    if (ret_msg->ret == TEE_SUCCESS && check_short_buffer())
        ret_msg->ret = TEE_ERROR_SHORT_BUFFER;

    if (ret_msg->ret == TEE_SUCCESS) {
        tlogd("Open session success!\n");
        service->first_open = false;
        session->session_context = ret_msg->session_context;
    } else {
        tloge("Open session failed, ret = 0x%x\n", ret_msg->ret);
        process_open_session_error();
    }

    *need_response = true;
}

static int32_t handle_ta_back_msg(smc_cmd_t *cmd, uint32_t back_cmd, struct session_struct *session,
    struct service_struct *service, ta_to_global_msg *ret_msg)
{
    bool need_response = false;

    /* if ta send duplicate msg to gtask, gtask will ignore */
    if (session->wait_ta_back_msg == false) {
        tloge("this msg from ta is invalid, 0x%x", back_cmd);
        return GT_ERR_END_CMD;
    }

    session->wait_ta_back_msg = false;
    int32_t sess_status = session->session_status;

    set_tee_return_origin(cmd, TEE_ORIGIN_TRUSTED_APP);

    switch (back_cmd) {
    case CALL_TA_INVOKE_CMD:
        tlogd("TA answered for invoke\n");
        need_response = true;
        break;
    case CALL_TA_CLOSE_SESSION:
        tlogd("TA answered for close session\n");
        process_close_session();
        need_response = true;
        break;
    case CALL_TA_OPEN_SESSION_INIT:
        /* Answer from TA open session after init msg has been processed */
        if (call_ta_open_session_init(ret_msg, &need_response) != GT_ERR_OK)
            break;
        /* fall-through */
    case CALL_TA_OPEN_SESSION_PROP:
        /*
         * NOTE: Missing break above intentional!!!!
         * Answer from TA open session after prop buffer has been processed,
         * here the task will block waiting for open session message to call
         * the open session hook
         */
        call_ta_open_session_prop(ret_msg, cmd, session->cmd_type, &need_response);
        break;
    case CALL_TA_OPEN_SESSION:
        /* Answer from TA after open session has finished running */
        call_ta_open_session(ret_msg, session, service, &need_response);
        break;
    default:
        /* in this scene, wait_ta_back_msg status should not be changed */
        tloge("Unknown cmd from S world!%x\n", back_cmd);
        session->wait_ta_back_msg = true;
        return GT_ERR_END_CMD;
    }

    /* ANSWER TIME!!!!! */
    if (need_response == true) {
        if (sess_status == TA_STATUS_NORMAL) {
            set_tee_return(cmd, ret_msg->ret);
            gt_cmd_response(cmd, session->cmd_type, session->ta2ta_from_taskid);
        } else {
            ta_exception_handle_ack(sess_status, session->task_id, session->ta2ta_from_taskid);
        }
    }
    return GT_ERR_OK;
}

int32_t handle_tee_wait_pending_msg(smc_cmd_t *cmd, uint32_t task_id)
{
    TEE_Result ret;
    global_to_ta_msg entry_msg = {0};

    if (cmd == NULL)
        return GT_ERR_END_CMD;

    if (is_opensession_cmd(cmd)) {
        tloge("tee wait is not allowed when open session\n");
        entry_msg.ret = TEE_ERROR_GENERIC;
        goto error_ack;
    }

    /* we clear oper here to avoid check error when pending back */
    cmd->operation_phys = 0;
    cmd->operation_h_phys = 0;

    tlogd("Sending back pending command to NWD!\n");
    set_tee_return(cmd, TEE_PENDING);
    ns_cmd_response(cmd);
    return GT_ERR_OK;

error_ack:
    ret = send_global2ta_msg(&entry_msg, 0x0, task_id, NULL);
    if (ret != TEE_SUCCESS)
        tloge("msg send to ta failed:0x%x\n", ret);
    return GT_ERR_OK;
}

static int32_t handle_msg_from_ta(uint32_t back_cmd, uint32_t task_id, const uint8_t *msg_buf,
                              uint32_t msg_size)
{
    smc_cmd_t cmd;
    TEE_Result ret;
    ta_to_global_msg ret_msg = {0};
    struct session_struct *session = NULL;
    struct service_struct *service = NULL;

    (void)memset_s(&cmd, sizeof(cmd), 0, sizeof(cmd));

    if (convert_ta2gtask_msg(msg_buf, msg_size, task_id, &ret_msg) != 0) {
        tloge("convert ta to gtask msg failed\n");
        return GT_ERR_END_CMD;
    }

    ret = init_session_context(task_id, &service, &session);
    if (ret != TEE_SUCCESS) {
        tloge("init session context failed, ret = 0x%x, task_id = 0x%x\n", ret, task_id);
        return GT_ERR_END_CMD;
    }

    if (memcpy_s(&cmd, sizeof(cmd), &session->cmd_in, sizeof(session->cmd_in)) != EOK)
        return GT_ERR_END_CMD;

    /* in order to adapt to FACE TA, because FACE TA send agent request with cmd 0 but not TEE_TASK_AGENT_SMC_CMD */
    if (ret_msg.ret == TEE_PENDING2)
        return handle_agent_request(TEE_TASK_AGENT_SMC_CMD, task_id, msg_buf, msg_size);

    tee_unlock_agents(session);

    if (ret_msg.ret == TEE_PENDING) {
        session_set_cancelable(true);
        return handle_tee_wait_pending_msg(&cmd, task_id);
    }
    session_set_cancelable(false);
    return handle_ta_back_msg(&cmd, back_cmd, session, service, &ret_msg);
}

static const struct s_cmd_proc_t g_s_cmd_table[] = {
    { TA2TA_CALL,                    handle_ta2ta_cmd },

    { TA_LOCK_AGENT,                 handle_agent_request },
    { TA_UNLOCK_AGENT,               handle_agent_request },
    { TA_GET_AGENT_BUFFER,           handle_agent_request },
    { TEE_TASK_AGENT_SMC_CMD,        handle_agent_request },

    { TEE_UNLINK_DYNAMIC_DRV,        handle_unlink_dynamic_drv },
    { REGISTER_ELF_REQ,              process_register_elf_req },
    { TEE_TASK_SET_CALLER_INFO,      task_adapt_set_caller_info },

    { MSG_ABORT_VALUE,               process_task_crash },
    { TEE_PANIC_VALUE,               process_task_crash },

    { TA_GET_REEINFO,                handle_info_query },
    { TA_GET_CALLERINFO,             handle_info_query },
};

static const uint32_t g_s_cmd_num =
    sizeof(g_s_cmd_table) / sizeof(g_s_cmd_table[0]);

int32_t handle_s_cmd(uint32_t cmd_id, uint32_t task_id, const uint8_t *msg_buf, uint32_t msg_size)
{
    if (msg_buf == NULL || msg_size == 0) {
        tloge("invalid msg param, msg size %u\n", msg_size);
        return GT_ERR_END_CMD;
    }

    for (uint32_t i = 0; i < g_s_cmd_num; i++) {
        if ((cmd_id == g_s_cmd_table[i].cmd_id) && (g_s_cmd_table[i].func != NULL))
            return g_s_cmd_table[i].func(cmd_id, task_id, msg_buf, msg_size);
    }

    /* handle ta cmd of middle process */
    return handle_msg_from_ta(cmd_id, task_id, msg_buf, msg_size);
}
