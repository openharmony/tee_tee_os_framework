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
#include "tee_task_exception.h"
#include <stddef.h>
#include <dlist.h>
#include "securec.h"
#include "tee_log.h"
#include "ta_framework.h"
#include "init.h"
#include "initlib.h"
#include "gtask_config_hal.h"
#include "tee_config.h"
#include "task_adaptor_pub.h"
#include "gtask_core.h"
#include "gtask_inner.h"
#include "service_manager.h"
#include "session_manager.h"
#include "global_task.h"
#include "tee_drv_internal.h"
#include "tee_task_config.h"
#include "tee_task.h"
#include "timer.h"
#include <ipclib_hal.h>

static void response_to_ca(const smc_cmd_t *cmd)
{
    if (put_last_out_cmd(cmd) != GT_ERR_OK)
        tloge("put ns cmd fail\n");
}

static void response_to_ta(const smc_cmd_t *cmd, uint32_t father_task_id)
{
    struct ta2ta_ret_msg ret_msg = { 0 };

    ret_msg.ret = cmd->ret_val;
    if (memcpy_s(&ret_msg.cmd, sizeof(ret_msg.cmd), cmd, sizeof(*cmd)) != EOK) {
        tloge("memcpy ta2ta back cmd failed\n");
        ret_msg.ret = TEE_ERROR_GENERIC;
    }

    (void)ipc_msg_snd(TA2TA_CALL, father_task_id, &ret_msg, sizeof(ret_msg));
}

static void ta_exception_response(smc_cmd_t *cmd, uint32_t cmd_type, uint32_t father_task_id)
{
    cmd->err_origin = TEE_ORIGIN_TRUSTED_APP;
    cmd->ret_val = TEE_ERROR_TARGET_DEAD;

    if (cmd_type == CMD_TYPE_NS_TO_SECURE)
        response_to_ca(cmd);
    else if (cmd_type == CMD_TYPE_SECURE_TO_SECURE)
        response_to_ta(cmd, father_task_id);
    else
        tloge("unknown cmd type %u\n", cmd_type);
}

static void try_release_dead_father(uint32_t task_id);
static TEE_Result release_cur_session(struct service_struct *crash_srv, struct session_struct *sess)
{
    uint32_t father_task_id = sess->ta2ta_from_taskid;

    tlogi("release session 0x%x, service name is %s\n", sess->session_id, crash_srv->name);
    if (sess->wait_ta_back_msg) {
        /* if session is killed when running, we should send response to CA or Father TA */
        tlogi("session 0x%x need response, cmd type=%u, father_task_id=0x%x\n", sess->session_id, sess->cmd_type,
            sess->ta2ta_from_taskid);
        ta_exception_response(&sess->cmd_in, sess->cmd_type, sess->ta2ta_from_taskid);
    }
    int32_t ret = release_session(crash_srv, sess);
    if (ret != 0) {
        tloge("release session failed\n");
        return TEE_ERROR_GENERIC;
    }

    /* in case of more than one TA has exception, we check father session here to clear dead father */
    if (father_task_id != SMCMGR_PID)
        try_release_dead_father(father_task_id);
    return TEE_SUCCESS;
}

/* we only close child TA here, if child TA has child, like TA1->TA2->TA3, TA2 should close TA3 itself */
static TEE_Result close_child_session(const struct session_struct *sess)
{
    TEE_Result ret = TEE_SUCCESS;
    struct session_struct *sess_context = NULL;

    dlist_for_each_entry(sess_context, &(sess->child_ta_sess_head), struct session_struct, child_ta_sess_list)
    {
        sess_context->session_status = TA_STATUS_FATHER_DEAD;
        /* session is running, we will wait ack */
        if (sess_context->wait_ta_back_msg) {
            tlogi("child session 0x%x is running, will wait ack\n", sess_context->session_id);
            continue;
        }
        if (close_session_async(sess_context) != TEE_SUCCESS) {
            ret = TEE_ERROR_GENERIC;
            tloge("close session 0x%x async failed\n", sess_context->session_id);
        }
    }
    return ret;
}

static TEE_Result try_release_session(struct service_struct *crash_srv, struct session_struct *sess)
{
    sess->session_status = TA_STATUS_SELF_DEAD;
    if (sess->agent_pending) {
        /* we should wait agent response */
        tlogi("service %s, session 0x%x is waiting for agent response, will release later\n", crash_srv->name,
            sess->session_id);
        return TEE_SUCCESS;
    }
    if (dlist_empty(&sess->child_ta_sess_head)) {
        /* if session has no child, just release itself */
        return release_cur_session(crash_srv, sess);
    } else {
        /* if session has child sess, release child sess first */
        tlogi("service %s, session 0x%x has child session, will close child session first\n", crash_srv->name,
            sess->session_id);
        return close_child_session(sess);
    }
}

static void release_service(struct service_struct *dead_srv)
{
    TEE_UUID uuid = { 0 };
    struct service_struct dyn_srv;

    tlogi("start release service %s img_type:%u\n", dead_srv->name, dead_srv->img_type);
    if (is_build_in_service(&dead_srv->property.uuid) || dead_srv->img_type == IMG_TYPE_DYNAMIC_SRV) {
        (void)memcpy_s(&uuid, sizeof(TEE_UUID), &dead_srv->property.uuid, sizeof(TEE_UUID));
        (void)memcpy_s(&dyn_srv, sizeof(struct service_struct), dead_srv, sizeof(struct service_struct));
        process_release_service(dead_srv, TA_REGION_FOR_REUSE);
        if (dead_srv->img_type == IMG_TYPE_DYNAMIC_SRV)
            load_dynamic_service(&dyn_srv);
        else
            load_internal_task(&uuid);
    } else {
        process_release_service(dead_srv, TA_REGION_RELEASE);
    }
}

static void try_release_exception_srv(struct service_struct *srv)
{
    struct session_struct *sess_context = NULL;
    struct session_struct *sess_tmp = NULL;

    recycle_srvc_thread(srv);
    srv->is_service_dead = true;
    dlist_for_each_entry_safe(sess_context, sess_tmp, &(srv->session_head), struct session_struct, session_list)
    {
        TEE_Result ret = try_release_session(srv, sess_context);
        if (ret != TEE_SUCCESS)
            tloge("try release session failed, ret=0x%x\n", ret);
    }

    /* session_count 0 means all sessions have beed released */
    if (srv->session_count == 0) {
        release_service(srv);
    } else {
        tlogi("will release service %s later, still have %d session to release\n", srv->name, srv->session_count);
    }
}

static void try_release_dead_father(uint32_t task_id)
{
    struct service_struct *service = NULL;
    struct session_struct *session = NULL;

    if (!find_task_dead(task_id, &service, &session)) {
        tloge("find father ta 0x%x failed\n", task_id);
        return;
    }

    if (session->session_status != TA_STATUS_SELF_DEAD) {
        tloge("something wrong, father ta 0x%x is not dead\n", task_id);
        return;
    }

    if (!dlist_empty(&session->child_ta_sess_head)) {
        tloge("father ta 0x%x still have child session, will release later\n", task_id);
        return;
    }

    TEE_Result ret = release_cur_session(service, session);
    if (ret != TEE_SUCCESS) {
        tloge("release dead father failed, task id is 0x%x\n", task_id);
        return;
    }

    if (service->session_count == 0)
        release_service(service);
}

void ta_exception_handle_ack(int32_t sess_status, uint32_t task_id, uint32_t father_task_id)
{
    struct service_struct *service = NULL;
    struct session_struct *session = NULL;

    if (sess_status == TA_STATUS_NORMAL)
        return;

    if (sess_status == TA_STATUS_SELF_DEAD) {
        tloge("something wrong, dead ta 0x%x can not send ack\n", task_id);
        return;
    }

    /* handle TA_STATUS_FATHER_DEAD */
    if (find_task(task_id, &service, &session)) {
        /* because its father is dead, we will close this session async */
        if (close_session_async(session) != TEE_SUCCESS)
            tloge("close session 0x%x async failed\n", session->session_id);
    } else {
        /* cur session has been closed, we will try release its dead father */
        try_release_dead_father(father_task_id);
    }
}

static void process_ta_agent_ack(struct service_struct *srv, struct session_struct *sess)
{
    if (sess->session_status != TA_STATUS_SELF_DEAD) {
        tloge("something wrong, task 0x%x is not dead\n", sess->task_id);
        return;
    }

    sess->agent_pending = false;
    TEE_Result ret = try_release_session(srv, sess);
    if (ret != TEE_SUCCESS)
        tloge("try release session failed, ret=0x%x\n", ret);

    if (srv->session_count == 0)
        release_service(srv);
}

void ta_exception_handle_buildin_agent_ack(uint32_t task_id)
{
    struct service_struct *srv = NULL;
    struct session_struct *sess = NULL;

    if (!find_task_dead(task_id, &srv, &sess)) {
        tloge("find dead task 0x%x failed\n", task_id);
        return;
    }
    process_ta_agent_ack(srv, sess);
}

TEE_Result ta_exception_handle_agent_ack(const smc_cmd_t *cmd)
{
    const TEE_UUID *uuid = NULL;
    struct service_struct *srv = NULL;
    struct session_struct *sess = NULL;

    if (cmd == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    uuid = (const TEE_UUID *)(uintptr_t)cmd->uuid;
    srv = find_service_dead(uuid, service_index_of_context(cmd->context));
    if (srv == NULL) {
        tloge("dead service not found uuid = %x-%x\n", uuid->timeLow, uuid->timeMid);
        return TEE_ERROR_SERVICE_NOT_EXIST;
    }

    sess = find_session_with_dev_file_id(session_id_of_context(cmd->context), cmd->dev_file_id, srv);
    if (sess == NULL) {
        tloge("session[%u] not exist in service[%s]\n", session_id_of_context(cmd->context), srv->name);
        return TEE_ERROR_SESSION_NOT_EXIST;
    }

    process_ta_agent_ack(srv, sess);
    return TEE_SUCCESS;
}

static struct session_struct *find_block_child_session(const struct session_struct *father_sess)
{
    struct session_struct *child_sess = NULL;
    struct session_struct *grandson_sess = NULL;

    dlist_for_each_entry(child_sess, &(father_sess->child_ta_sess_head), struct session_struct, child_ta_sess_list)
    {
        /* find a block child */
        if (child_sess->wait_ta_back_msg) {
            grandson_sess = find_block_child_session(child_sess);
            if (grandson_sess != NULL)
                return grandson_sess;
            else
                return child_sess;
        }
    }
    return NULL;
}

static bool check_core_service(const TEE_UUID *uuid)
{
    return is_gtask_by_uuid(uuid) || is_internal_task_by_uuid(uuid);
}

static TEE_Result process_kill_task(struct service_struct *srv, const struct session_struct *sess)
{
    struct session_struct *child_sess = NULL;
    struct service_struct *block_srv = NULL;

    if (srv == NULL || sess == NULL) {
        tloge("process kill task error, invalid param\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (check_core_service(&srv->property.uuid)) {
        tloge("process kill task error, can not kill a core service\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tlogi("start process kill task, block task name=%s, session id=0x%x, ca pid=%u\n", srv->name, sess->session_id,
        sess->cmd_in.ca_pid);

    if (sess->agent_pending) {
        tloge("killing a agent pending ta or dyn svc, delay it, cmd id = 0x%x\n", sess->cmd_in.cmd_id);
        return TEE_ERROR_BUSY;
    }

    if (!sess->wait_ta_back_msg) {
        tloge("unexpected status:sess is not running\n");
        return TEE_ERROR_BAD_STATE;
    }

    child_sess = find_block_child_session(sess);
    if (child_sess != NULL) {
        /* if child_sess block, we kill child TA */
        block_srv = find_service_by_task_id(child_sess->task_id);
        if (block_srv == NULL) {
            tloge("find child block srv failed, task id 0x%x\n", child_sess->task_id);
            return TEE_ERROR_SERVICE_NOT_EXIST;
        }
        tlogi("find child TA block, start kill task %s\n", block_srv->name);
    } else {
        /* if no child_sess block, that means cur TA block, we kill cur TA */
        block_srv = srv;
    }
    try_release_exception_srv(block_srv);
    return TEE_SUCCESS;
}

int32_t handle_kill_task(const smc_cmd_t *cmd)
{
    struct service_struct *srv = NULL;
    struct session_struct *sess = NULL;

    if (cmd == NULL) {
        tloge("handle kill task error, invalid param\n");
        return GT_ERR_END_CMD;
    }

    tlogi("receive kill task msg\n");

    const TEE_UUID *uuid = (const TEE_UUID *)(uintptr_t)cmd->uuid;
    if (find_service(uuid, service_index_of_context(cmd->context), &srv) == -1) {
        tloge("find normal service failed, try to find dead service, uuid = %x-%x\n", uuid->timeLow, uuid->timeMid);
        /* in case of multi ta have exception at the same time */
        srv = find_service_dead(uuid, service_index_of_context(cmd->context));
        if (srv == NULL) {
            tloge("find dead service failed, return error\n");
            return GT_ERR_END_CMD;
        }
    }

    sess = find_session_with_dev_file_id(session_id_of_context(cmd->context), cmd->dev_file_id, srv);
    if (sess == NULL) {
        tloge("find session %u failed in service %s\n", session_id_of_context(cmd->context), srv->name);
        return GT_ERR_END_CMD;
    }
    if (process_kill_task(srv, sess) != TEE_SUCCESS)
        return GT_ERR_END_CMD;

    return GT_ERR_OK;
}

int32_t process_task_crash(uint32_t cmd_id, uint32_t task_id, const uint8_t *msg_buf,
                           uint32_t msg_size)
{
    uint32_t crash_task_id;

    (void)cmd_id;
    /* check msg sender */
    if (!is_sys_task(task_id)) {
        tloge("recv task crash msg from wrong sender 0x%x\n", task_id);
        return GT_ERR_END_CMD;
    }

    if (msg_buf == NULL || msg_size < sizeof(crash_task_id)) {
        tloge("recv task crash msg error, msg size is %u\n", msg_size);
        return GT_ERR_END_CMD;
    }

    crash_task_id = *(const uint32_t *)(uintptr_t)msg_buf;

    /* check service exist & valid */
    struct service_struct *crash_srv = find_service_by_task_id(crash_task_id);
    if (crash_srv == NULL || is_gtask_by_uuid(&(crash_srv->property.uuid))) {
        tloge("process task crash failed: invalid task id 0x%x\n", crash_task_id);
        tee_drv_task_exit(crash_task_id);
        return GT_ERR_END_CMD;
    }

    tlogi("recv task crash msg, task_name=%s, task_id=0x%x\n", crash_srv->name, crash_task_id);

    try_release_exception_srv(crash_srv);

    /* if internal task crash, we should call callback */
    if (is_internal_task_by_task_id(crash_task_id)) {
        tloge("internal task crash\n");
        task_adapt_crash_callback(crash_task_id);
    }
    return GT_ERR_OK;
}
