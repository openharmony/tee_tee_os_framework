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
#include <dlist.h>
#include "tee_log.h"
#include "tee_mem_mgmt_api.h"
#include "ta_framework.h"
#include "gtask_inner.h"
#include "session_manager.h"
#include "service_manager.h"
#include "agent_manager.h"
#include "mem_manager.h"
#include "tee_ext_api.h"
#include "tee_config.h"
#include "gtask_config_hal.h"
#include "securec.h"

#include "gtask_adapt.h"
#include "dynload.h"
#include "task_adaptor_pub.h"
#include "tee_task.h"
#include "tee_task_exception.h"
#include <ipclib_hal.h>

#define DEFAULT_EVENT_NR 0xffffffff

struct service_struct *g_cur_service = (struct service_struct *)NULL;
struct session_struct *g_cur_session = (struct session_struct *)NULL;

/* static funs declare */
int32_t find_service(const TEE_UUID *uuid, uint32_t service_index, struct service_struct **entry);
void set_session_context(smc_cmd_t *cmd, uint32_t service_index, uint32_t session_id);
TEE_Result process_close_session_entry(struct service_struct **service, struct session_struct **session);
void process_close_ta2ta_target_sessions(uint32_t from_taskid, uint32_t level);

struct session_struct *get_cur_session(void)
{
    return g_cur_session;
}

struct service_struct *get_cur_service(void)
{
    return g_cur_service;
}

static TEE_Result __attribute__((noinline)) call_ta_invoke_close_session(const smc_cmd_t *cmd, uint32_t cmd_type, uint32_t cmd_id,
                                               global_to_ta_msg *entry_msg)
{
    TEE_Result ret;

    if (cmd->ret_val == TEE_PENDING2 || cmd->ret_val == TEE_PENDING)
        return TEE_SUCCESS;

    entry_msg->session_id      = set_session_context_bit(g_cur_service->index, g_cur_session->session_id);
    entry_msg->session_context = g_cur_session->session_context;
    entry_msg->cmd_id          = cmd->cmd_id;
    entry_msg->dev_id          = cmd->dev_file_id;
    entry_msg->started         = cmd->started;

    if (cmd_id == CALL_TA_CLOSE_SESSION) {
        if (g_cur_service->session_count == 1 && g_cur_service->property.keep_alive == false)
            entry_msg->last_session = 1;
    }
    if (cmd_type == CMD_TYPE_NS_TO_SECURE) {
        ret = cmd_ns_get_params(g_cur_session->task_id, cmd, &entry_msg->param_type, &entry_msg->params);
        if (ret != TEE_SUCCESS) {
            tloge("map ns params error\n");
            return ret;
        }
        entry_msg->session_type = SESSION_FROM_CA;
    } else {
        ret = cmd_secure_get_params(g_cur_session->task_id, cmd, &entry_msg->param_type, &entry_msg->params);
        if (ret != TEE_SUCCESS) {
            tloge("map secure params error\n");
            return ret;
        }
        entry_msg->session_type = SESSION_FROM_TA;
    }

    return ret;
}

static void set_init_msg_prop(const struct ta_property *in, ta_property_t_64 *out)
{
    out->uuid            = in->uuid;
    out->stack_size      = in->stack_size;
    out->heap_size       = in->heap_size;
    out->single_instance = in->single_instance;
    out->multi_session   = in->multi_session;
    out->keep_alive      = in->keep_alive;
    out->ssa_enum_enable = in->ssa_enum_enable;
    out->other_buff      = (uintptr_t)in->other_buff;
    out->other_len       = in->other_len;
}

static TEE_Result check_and_process_init_build(ta_init_msg *init_msg,
                                               global_to_ta_msg *entry_msg, bool *flag)
{
    TEE_Result ret;

    if (g_cur_service->init_build == 0) {
        tlogd("Do service initial build!\n");
        *flag = true;
        /*
         * Once the first msg CALL_TA_OPEN_SESSION_INIT send
         * to TA, TA will do init work like clear bss etc,
         * So we need make sure the other session of the TA will
         * not send msg with init_build=0 again.
         */
        g_cur_service->init_build = 1;

        set_init_msg_prop(&g_cur_service->property, &(init_msg->prop));
        init_msg->login_method = g_cur_session->login_method;

        ret = send_ta_init_msg(init_msg, g_cur_service->ta_64bit, CALL_TA_OPEN_SESSION_INIT,
                               g_cur_session->task_id);
        if (ret != TEE_SUCCESS) {
            tloge("send open session init msg to session[%s] failed:0x%x\n", g_cur_session->name, ret);
            return ret;
        }
        g_cur_session->wait_ta_back_msg = true;

        return TEE_SUCCESS;
    }

    if (g_cur_service->session_count == 1)
        entry_msg->first_session = 1;

    return TEE_SUCCESS;
}

TEE_Result async_call_ta_entry(const smc_cmd_t *cmd, uint32_t cmd_type, uint32_t cmd_id)
{
    global_to_ta_msg entry_msg = { 0 };
    ta_init_msg init_msg       = { 0 };
    TEE_Result ret;
    bool flag = false;

    if (cmd == NULL || g_cur_session == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    /*
     * If the TA has agent pending command but the incomming command
     * does not come from the agent then we cannot forward the command
     * because the TA is single threaded!
     */
    if (g_cur_session->agent_pending) {
        tloge("session %s is busy, command %u rejected\n", g_cur_session->name, cmd_id);
        return TEE_ERROR_BUSY;
    }

    g_cur_session->login_method = cmd->login_method;

    switch (cmd_id) {
    case CALL_TA_OPEN_SESSION:
        ret = check_and_process_init_build(&init_msg, &entry_msg, &flag);
        if (flag)
            return ret;
        /* fall-through */
    case CALL_TA_INVOKE_CMD:
    case CALL_TA_CLOSE_SESSION:
        ret = call_ta_invoke_close_session(cmd, cmd_type, cmd_id, &entry_msg);
        if (ret) {
            tloge("call ta invoke_cmd or close_session error\n");
            return ret;
        }
        break;
    default:
        tloge("invalid asyn cmd id %u\n", cmd_id);
        return TEE_ERROR_GENERIC;
    }

    tlogd("send to TA(0x%x): cmd=0x%x, session_id=0x%x\n", g_cur_session->task_id, cmd_id, entry_msg.session_id);
    ret = send_global2ta_msg(&entry_msg, cmd_id, g_cur_session->task_id, NULL);
    if (ret != TEE_SUCCESS) {
        tloge("msg send to ta failed:0x%x\n", ret);
        return ret;
    }

    g_cur_session->wait_ta_back_msg = true;
    return TEE_SUCCESS;
}

void session_set_cancelable(bool cancelable)
{
    if (g_cur_session != NULL)
        g_cur_session->cancelable = cancelable;
}

struct session_struct *find_session_with_dev_file_id(uint32_t session_id, uint32_t dev_file_id,
    const struct service_struct *srv)
{
    struct session_struct *sess_context = NULL;

    if (srv == NULL)
        return NULL;

    dlist_for_each_entry (sess_context, &srv->session_head, struct session_struct, session_list) {
        if ((sess_context->session_id == session_id) && (sess_context->cmd_in.dev_file_id == dev_file_id))
            return sess_context;
    }
    return NULL;
}

void reset_ta_context(void)
{
    g_cur_service = (struct service_struct *)NULL;
    g_cur_session = (struct session_struct *)NULL;
}

void set_tee_return_origin(smc_cmd_t *cmd, TEE_Result ret_origin)
{
    if (cmd == NULL)
        return;

    cmd->err_origin = ret_origin;
}

void set_tee_return(smc_cmd_t *cmd, TEE_Result ret_val)
{
    if (cmd == NULL)
        return;

    cmd->ret_val = ret_val;
}

static TEE_Result init_ta_service_session(const smc_cmd_t *cmd)
{
    const TEE_UUID *uuid = NULL;
    int32_t service_index;

    uuid = (const TEE_UUID *)(uintptr_t)cmd->uuid;

    if ((service_index = find_service(uuid, service_index_of_context(cmd->context), &g_cur_service)) == -1) {
        tloge("service not found uuid = %x-%x\n", uuid->timeLow, uuid->timeMid);
        return TEE_ERROR_SERVICE_NOT_EXIST;
    }

    g_cur_session = find_session_with_dev_file_id(session_id_of_context(cmd->context), cmd->dev_file_id, g_cur_service);
    if ((g_cur_session == NULL) && (cmd->cmd_type != CMD_TYPE_GLOBAL)) {
        tloge("session[%u] not exist in service[%s]\n", session_id_of_context(cmd->context), g_cur_service->name);
        return TEE_ERROR_SESSION_NOT_EXIST;
    }

    return TEE_SUCCESS;
}

TEE_Result init_ta_context(const smc_cmd_t *cmd)
{
    if (cmd == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    TEE_Result ret = init_ta_service_session(cmd);
    if (ret != 0) {
        tloge("init ta service session error:%x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result init_ta2ta_session(const smc_cmd_t *cmd)
{
    g_cur_session = find_session_with_dev_file_id(session_id_of_context(cmd->context), cmd->dev_file_id, g_cur_service);
    if ((g_cur_session == NULL) && (cmd->cmd_type != CMD_TYPE_GLOBAL))
        return TEE_ERROR_SESSION_NOT_EXIST;

    return TEE_SUCCESS;
}

static int ta2ta_call_back(uint32_t task_id)
{
    struct service_struct *serv = NULL;
    struct session_struct *sess = NULL;
    uint32_t pre_task           = task_id;
    uint32_t level;

    do {
        if (!find_task(pre_task, &serv, &sess)) {
            tloge("find service fail taskid:%u\n", pre_task);
            return -1;
        }

        if (serv == g_cur_service) {
            tloge("WRONG! ta2ta cannot call back\n");
            return -1;
        }
        tlogd("sess level:%d\n", sess->ta2ta_level);

        pre_task = sess->ta2ta_from_taskid;
        level    = sess->ta2ta_level;
    } while (level > 0);

    return 0;
}


static TEE_Result check_ta2ta_context(uint32_t task_id)
{
    /* check if there is a loop call */
    if (ta2ta_call_back(task_id) != 0) {
        tloge("ta2ta call in wrong state\n");
        return TEE_ERROR_GENERIC;
    }

    /* We don't allow TA2TA session calls from TAs that did not initiate the session */
    if (g_cur_session != NULL) {
        if (g_cur_session->ta2ta_from_taskid != task_id) {
            tloge("receive invalid ta2ta call from task 0x%x\n", task_id);
            return TEE_ERROR_SESSION_NOT_EXIST;
        }
    }
    return TEE_SUCCESS;
}

static TEE_Result init_ta2ta_service(const smc_cmd_t *cmd)
{
    const TEE_UUID *uuid = NULL;

    uuid = (const TEE_UUID *)(uintptr_t)cmd->uuid;
    if (find_service(uuid, service_index_of_context(cmd->context), &g_cur_service) == -1) {
        tloge("find second service fail\n");
        return TEE_ERROR_SERVICE_NOT_EXIST;
    }

    return TEE_SUCCESS;
}

static TEE_Result init_ta2ta_service_session(const smc_cmd_t *cmd)
{
    TEE_Result ret;
    ret = init_ta2ta_service(cmd);
    if (ret != TEE_SUCCESS) {
        tloge("init ta2ta service error:%x\n", ret);
        return ret;
    }

    ret = init_ta2ta_session(cmd);
    if (ret != TEE_SUCCESS) {
        tloge("init ta2ta session error:%x\n", ret);
        return ret;
    }

    return ret;
}

TEE_Result init_ta2ta_agent_context(smc_cmd_t *cmd)
{
    uint32_t ret_val;
    TEE_Result ret;
    struct service_struct *service = NULL;
    struct session_struct *session = NULL;

    if (cmd == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    ret_val = cmd->ret_val;

    ret = init_ta2ta_service_session(cmd);
    if (ret != TEE_SUCCESS)
        return ret;

    if ((g_cur_session != NULL) && (g_cur_session->cmd != NULL)) {
        /* agent response will use a new cmd index, updata the event_nr in original cmd */
        if (g_cur_session->cmd->event_nr != cmd->event_nr) {
            /*
             * The ta2ta cmd was already initialized so we need to change out cmd to point to the
             * mapped pointer instead of the current cmd
             */
            if (!find_task(g_cur_session->ta2ta_from_taskid, &service, &session)) {
                tloge("can't find session for ta2ta_from_taskid taskid=0x%x\n", g_cur_session->ta2ta_from_taskid);
                return TEE_ERROR_GENERIC;
            }

            session->cmd_in.event_nr     = cmd->event_nr;
            session->cmd_in.ca_pid       = cmd->ca_pid;
            g_cur_session->cmd->event_nr = cmd->event_nr;
            g_cur_session->cmd->ca_pid   = cmd->ca_pid;
        }
        cmd = g_cur_session->cmd;
        if (cmd != NULL) {
            cmd->ret_val = ret_val;
        } else {
            /* this never happen */
            tloge("out cmd is null\n");
            return TEE_ERROR_GENERIC;
        }
    }

    return TEE_SUCCESS;
}

TEE_Result init_ta2ta_context(smc_cmd_t *cmd, uint64_t ta_cmd, uint32_t task_id)
{
    TEE_Result ret;
    struct service_struct *service = NULL;
    struct session_struct *session = NULL;

    if (cmd == NULL || ta_cmd == 0)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Need to remap the command id incomming from the secure ta2ta call */
    if (map_secure_operation(ta_cmd, cmd, task_id) != TEE_SUCCESS)
        return TEE_ERROR_OUT_OF_MEMORY;

    if (!find_task(task_id, &service, &session)) {
        tloge("can't find session for ta2ta call taskid=%u\n", task_id);
        return TEE_ERROR_GENERIC;
    }
    /* TA2TA call will reuse the src TA's CA's cmd_index */
    cmd->ca_pid   = session->cmd_in.ca_pid;
    cmd->event_nr = session->cmd_in.event_nr;
    cmd->dev_file_id = session->cmd_in.dev_file_id;
    tlogd("ta2ta call update, service_id=%u, session_id=%u, ca_pid=%u, event_nr=%u, dev_file_id=%u\n",
        service->index, session->session_id, cmd->ca_pid, cmd->event_nr, cmd->dev_file_id);

    ret = init_ta2ta_service_session(cmd);
    if (ret != TEE_SUCCESS)
        return ret;
    ret = check_ta2ta_context(task_id);
    if (ret != TEE_SUCCESS)
        return ret;

    /*
     * If it's the first time we map the ta2ta command then set the internals of the session
     * to point to it
     */
    if (g_cur_session != NULL) {
        g_cur_session->cmd = &g_cur_session->cmd_in;
        if (memcpy_s(&g_cur_session->cmd_in, sizeof(g_cur_session->cmd_in), cmd, sizeof(*cmd)) != TEE_SUCCESS) {
            tloge("memcpy cmd_in failed\n");
            return TEE_ERROR_GENERIC;
        }
    }

    return TEE_SUCCESS;
}

TEE_Result init_session_context(uint32_t task_id,
    struct service_struct **service, struct session_struct **session)
{
    if (!find_task(task_id, &g_cur_service, &g_cur_session))
        return TEE_ERROR_SESSION_NOT_EXIST;

    if (service != NULL)
        *service = g_cur_service;
    if (session != NULL)
        *session = g_cur_session;

    return TEE_SUCCESS;
}

void set_session_context(smc_cmd_t *cmd, uint32_t service_index, uint32_t session_id)
{
    if (cmd == NULL)
        return;
    cmd->context = set_session_context_bit(service_index, session_id);

    tlogd("set session id = 0x%x\n", cmd->context);
}

int32_t get_session_id(void)
{
    int32_t id = ERROR_SESSION_ID;
    uint32_t i;

    for (i = 0; i < MAX_SESSION_ID; i++) {
        if ((g_cur_service->session_bitmap[get_index_by_uint32(i)] & (uint32_t)(0x1 << get_bit_by_uint32(i))) == 0) {
            id = (int32_t)(i + 1);
            break;
        }
    }

    return id;
}

int join_session_task_name(const char *service_name, struct session_struct *session)
{
    if (service_name == NULL || session == NULL)
        return -1;

    if (snprintf_s(session->name, SERVICE_NAME_MAX + SESSION_ID_LEN,
        SERVICE_NAME_MAX + SESSION_ID_LEN - 1, "%u%s", session->session_id,
        service_name) < 0) {
        tloge("snprintf_s session name failed\n");
        return -1;
    }

    return 0;
}

TEE_Result start_ta_task(const smc_cmd_t *cmd, uint32_t cmd_type)
{
    TEE_Result ret;

    if (cmd == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (g_cur_session != NULL &&
        memcpy_s(&g_cur_session->cmd_in, sizeof(smc_cmd_t), cmd, sizeof(smc_cmd_t))) {
        tloge("memcpy_s cmd_in failed\n");
        return TEE_ERROR_GENERIC;
    }

    ret = async_call_ta_entry(cmd, cmd_type, CALL_TA_INVOKE_CMD);
    return ret;
}

static void ta_task_init(struct tsk_init_param *task_param)
{
    if (task_param == NULL)
        return;

    task_param->task_prior = DEFAULT_TASK_PRIO;
    task_param->task_name  = g_cur_session->name;
    task_param->que_num    = DEFAULT_MSG_QUEUE_NUM;

    task_param->uuid.timeLow          = g_cur_service->property.uuid.timeLow;
    task_param->uuid.timeMid          = g_cur_service->property.uuid.timeMid;
    task_param->uuid.timeHiAndVersion = g_cur_service->property.uuid.timeHiAndVersion;
    int i;
    for (i = 0; i < NODE_LEN; i++)
        task_param->uuid.clockSeqAndNode[i] = g_cur_service->property.uuid.clockSeqAndNode[i];
}

static int get_ta2ta_level(uint32_t cmd_type, uint32_t task_id, uint32_t *level)
{
    struct service_struct *serv = NULL;
    struct session_struct *sess = NULL;

    if (level == NULL) {
        tloge("get ta2ta level invalid param\n");
        return -1;
    }

    if (cmd_type == CMD_TYPE_NS_TO_SECURE) {
        tlogd("type is ns to secure\n");
        *level = 0;
        return 0;
    }

    if (find_task(task_id, &serv, &sess) == 0) {
        tloge("cannot find caller ta. something wrong\n");
        return -1;
    }

    if (sess->ta2ta_level >= MAX_TA2TA_LEVEL) {
        tloge("get caller ta2ta_level:%u, cannot open other ta\n", sess->ta2ta_level);
        return -1;
    }

    *level = sess->ta2ta_level + 1;

    return 0;
}

static void add_session_to_ta2ta_list(uint32_t cmd_type, uint32_t caller_task_id, struct session_struct *cur_sess)
{
    struct service_struct *caller_serv = NULL;
    struct session_struct *caller_sess = NULL;

    if (cmd_type == CMD_TYPE_NS_TO_SECURE)
        return;

    if (find_task(caller_task_id, &caller_serv, &caller_sess) == 0) {
        tloge("find caller task 0x%x failed\n", caller_task_id);
        return;
    }
    dlist_insert_tail(&(cur_sess->child_ta_sess_list), &caller_sess->child_ta_sess_head);
}

static void release_srvc_gc(bool handle_ref_cnt, int sre_ret)
{
    /*
     * for built-in service, we only need to care about session node,
     * don't need to care about service node
     */
    if (is_build_in_service(&(g_cur_service->property.uuid)))
        return;

    if (handle_ref_cnt)
        decr_ref_cnt(g_cur_service);

    /* when service thread is blocked and session count is 0, we release service thread */
    if (sre_ret == TIMEOUT_FAIL_RET) {
        tloge("%s is blocked and session count is %u\n",
            g_cur_service->name, g_cur_service->session_count);
        if (g_cur_service->session_count == 0) {
            process_release_service(g_cur_service, TA_REGION_RELEASE);
            g_cur_service = NULL;
        }
        return;
    }

    /*
     * for non built-in TA, in following case, we release service node and service thread
     * 1. keepalive is false;
     * 2. keepalive is true, first open session;
     */
    if (g_cur_service->session_count == 0 && g_cur_service->ref_cnt == 0) {
        bool need_release_service =
            (!g_cur_service->property.keep_alive ||
            (g_cur_service->property.keep_alive && g_cur_service->first_open));
        if (need_release_service) {
            process_release_service(g_cur_service, TA_REGION_RELEASE);
            g_cur_service = NULL;
        }
    }
}

/* for normal TA and built-in TA, we need to release session node and service node. */
static void create_task_fail_gc(bool handle_ref_cnt, int sre_ret)
{
    if (g_cur_session != NULL) {
        CLR_BIT(g_cur_service->session_bitmap[get_index_by_uint32(g_cur_session->session_id - 1)],
                get_bit_by_uint32(g_cur_session->session_id - 1));
        release_pam_node(g_cur_session->pam_node);
        dlist_delete(&g_cur_session->session_list);
        dlist_delete(&g_cur_session->child_ta_sess_list);
        TEE_Free(g_cur_session);
        g_cur_session = NULL;
    }
    release_srvc_gc(handle_ref_cnt, sre_ret);
}

static int open_session_fail_gc(void)
{
    if (g_cur_service->session_count > 0) {
        g_cur_service->session_count--;
        uint32_t session_id = set_session_context_bit(g_cur_service->index, g_cur_session->session_id);
        int32_t ret = sre_task_delete_ex(g_cur_session->task_id, false, session_id);
        if (ret != SUCC_RET)
            tloge("task del fail errorno =%d\n", ret);
        return ret;
    }
    tloge("here session count never be 0, some bad things must happen\n");
    return SUCC_RET;
}

TEE_Result add_new_session_into_list(struct session_struct **session, uint32_t *session_id,
                                     uint32_t ta2ta_level)
{
    if (session == NULL || session_id == NULL || g_cur_service == NULL)
        return TEE_ERROR_GENERIC;

    /* session id will never be bigger than SESSION_MAX=8 */
    int32_t tmp_id = get_session_id();
    if (tmp_id == ERROR_SESSION_ID) {
        tloge("failed to get session id, return TEE_ERROR_SESSION_MAXIMUM\n");
        return TEE_ERROR_SESSION_MAXIMUM;
    }
    *session_id = (uint32_t)tmp_id;

    *session = TEE_Malloc(sizeof(struct session_struct), 0);
    if (*session == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    (*session)->agent_pending = false;
    (*session)->ta2ta_level   = ta2ta_level;
    (*session)->session_id    = *session_id;

    if (join_session_task_name(g_cur_service->name, *session) != 0) {
        tloge("join session task name failed\n");
        if (*session != NULL) {
            TEE_Free(*session);
            *session = NULL;
        }
        return TEE_ERROR_GENERIC;
    }

    dlist_init(&(*session)->session_list);
    SET_BIT(g_cur_service->session_bitmap[get_index_by_uint32(*session_id - 1)],
            get_bit_by_uint32(*session_id - 1));
    dlist_insert_tail(&(*session)->session_list, &g_cur_service->session_head);
    g_cur_session = *session;

    /* Init list of locked agents */
    dlist_init(&(*session)->locked_agents);
    dlist_init(&(*session)->map_mem);

    (*session)->session_status = TA_STATUS_NORMAL;
    dlist_init(&(*session)->child_ta_sess_head);
    dlist_init(&(*session)->child_ta_sess_list);

    return TEE_SUCCESS;
}

static TEE_Result create_session(smc_cmd_t *cmd, uint32_t cmd_type, uint32_t caller_id, bool handle_ref_cnt)
{
    TEE_Result ret = TEE_ERROR_GENERIC;
    uint32_t task_id;
    uint32_t session_id;
    uint32_t level;
    struct tsk_init_param task_init_param;
    struct session_struct *session = NULL;

    if (get_ta2ta_level(cmd_type, caller_id, &level) != 0)
        goto generic_fail;

    ret = add_new_session_into_list(&session, &session_id, level);
    if (ret != TEE_SUCCESS)
        goto generic_fail;

    ta_task_init(&task_init_param);
    int32_t sre_ret = sre_task_create(&task_init_param, &task_id);
    if (sre_ret != 0) {
        tloge("create task %s fail : errorno = 0x%x\n", g_cur_service->name, sre_ret);
        ret = TEE_ERROR_GENERIC;
        goto create_task_fail;
    }
    session->task_id            = task_id;
    session->ta2ta_from_taskid  = caller_id;
    add_session_to_ta2ta_list(cmd_type, caller_id, session);
    session->wait_ta_back_msg = false;
    set_session_context(cmd, g_cur_service->index, session_id);
    g_cur_service->session_count++;
    tlogd("create session-%d: %s: 0x%x\n", session_id, g_cur_service->name, task_id);
    return ret;

create_task_fail:
    create_task_fail_gc(handle_ref_cnt, sre_ret);
    return ret;
generic_fail:
    release_srvc_gc(handle_ref_cnt, SUCC_RET);
    return ret;
}

static TEE_Result check_session_accessible()
{
    if (is_system_service(g_cur_service)) {
        tloge("session is denied\n");
        return TEE_ERROR_ACCESS_DENIED;
    }

    if (g_cur_service->property.multi_session == false && g_cur_service->session_count > 0) {
        struct session_struct *tmp_session =
            dlist_entry(&(g_cur_service->session_head.next), struct session_struct, session_list);

        if (true == tmp_session->cancelable) {
            tloge("session[%s] is busy\n", tmp_session->name);
            return TEE_ERROR_BUSY;
        } else {
            tloge("service[%s] only 1 session can be opened\n", g_cur_service->name);
            return TEE_ERROR_ACCESS_CONFLICT;
        }
    }

    return TEE_SUCCESS;
}

static TEE_Result is_session_valid(const smc_cmd_t *cmd, uint32_t cmd_type)
{
    (void)cmd;
    (void)cmd_type;

    return check_session_accessible();
}

static void check_and_release_ta_elf(void)
{
    if (!is_build_in_service(&(g_cur_service->property.uuid)) && g_cur_service->elf_state == ELF_EXIST) {
        if (sre_release_dynamic_region(&g_cur_service->property.uuid, TA_REGION_RELEASE) != 0)
            tloge("release elf failed\n");
    }
}

static void do_resc_release_work(bool handle_ref_cnt)
{
    /* after session is created, elf and ref_cnt can be released. */
    if (handle_ref_cnt) {
        decr_ref_cnt(g_cur_service);
        tlogd("service: %s, session count is %d ref_cnt-- is %d\n", g_cur_service->name, g_cur_service->session_count,
              g_cur_service->ref_cnt);
    }
    check_and_release_ta_elf();
}

static bool check_handle_ref_cnt(uint32_t cmd_type, const struct ta2ta_info_t *ta2ta_info)
{
    /*
     * 1.ta2ta and ta elf is not loaded by secfile load agent
     * 2.built-in service;
     * don't need to handle ref_cnt
     */
    bool check_value = (cmd_type == CMD_TYPE_SECURE_TO_SECURE && ta2ta_info->is_load_worked == false) ||
                        is_build_in_service(&((g_cur_service->property).uuid));
    if (check_value)
        return false;
    return true;
}

TEE_Result open_session(smc_cmd_t *cmd, uint32_t cmd_type, uint32_t caller_id,
                        const struct ta2ta_info_t *ta2ta_info)
{
    TEE_Result ret;
    int sre_ret;

    bool check_value = (g_cur_service == NULL || cmd == NULL);
    if (check_value)
        return TEE_ERROR_BAD_PARAMETERS;

    check_value = (cmd_type == CMD_TYPE_SECURE_TO_SECURE && ta2ta_info == NULL);
    if (check_value) {
        tloge("ta2ta info is null, something bad must happened\n");
        return TEE_ERROR_GENERIC;
    }

    bool handle_ref_cnt = check_handle_ref_cnt(cmd_type, ta2ta_info);

    ret = is_session_valid(cmd, cmd_type);
    if (ret != TEE_SUCCESS) {
        create_task_fail_gc(handle_ref_cnt, SUCC_RET);
        return ret;
    }
    ret = create_session(cmd, cmd_type, caller_id, handle_ref_cnt);
    if (ret != TEE_SUCCESS) {
        tloge("create session of service failed:0x%x\n", ret);
        return ret;
    }

    g_cur_session->cmd_type = cmd_type;
    if (memcpy_s(&g_cur_session->cmd_in, sizeof(g_cur_session->cmd_in), cmd, sizeof(*cmd)) != EOK) {
        ret = TEE_ERROR_GENERIC;
        goto open_fail;
    }
    ret = async_call_ta_entry(cmd, cmd_type, CALL_TA_OPEN_SESSION);
    if (is_err_ret(ret)) {
        tloge("Call TA Entry of service failed: 0x%x\n", ret);
        goto open_fail;
    }
    g_cur_session->ta2ta_handle =
        ((cmd_type != CMD_TYPE_SECURE_TO_SECURE) ? (INVALID_SESSION_HANDLE) : (ta2ta_info->handle));
    do_resc_release_work(handle_ref_cnt);
    return ret;
open_fail:
    sre_ret = open_session_fail_gc();
    create_task_fail_gc(handle_ref_cnt, sre_ret);
    return ret;
}

int32_t release_session(struct service_struct *service, struct session_struct *session)
{
    int32_t sre_ret;
    uint32_t session_id;
    struct service_struct *backup_service = NULL;
    struct session_struct *backup_session = NULL;

    if (service == NULL || session == NULL)
        return (int32_t)TEE_ERROR_BAD_PARAMETERS;

    task_adapt_unregister_ta(&service->property.uuid, session->task_id);
    service->session_count--;

    backup_service = g_cur_service;
    backup_session = g_cur_session;
    g_cur_service  = service;
    g_cur_session  = session;
    session_id     = set_session_context_bit(service->index, session->session_id);
    sre_ret = sre_task_delete_ex(session->task_id, service->is_service_dead, session_id);
    if (sre_ret != SUCC_RET)
        tloge("task del error fail 1\n");

    release_pam_node(session->pam_node);
    task_del_mem_region(&(session->map_mem), service->is_service_dead);

    CLR_BIT(service->session_bitmap[get_index_by_uint32(session->session_id - 1)],
            get_bit_by_uint32(session->session_id - 1));
    dlist_delete(&session->session_list);
    dlist_delete(&session->child_ta_sess_list);

    /* Lose the locks held on agents */
    tee_unlock_agents(session);

    g_cur_service = backup_service;
    g_cur_session = backup_session;
    /* If we are on a waiting list remove it */
    if (session->waiting_agent.next != NULL)
        dlist_delete(&session->waiting_agent);

    /*
     * We are the last one to go, next
     * open session will need to reinit
     */
    TEE_Free(session);

    return sre_ret;
}

TEE_Result process_close_session_entry(struct service_struct **service_in, struct session_struct **session_in)
{
    struct service_struct *service = NULL;
    struct session_struct *session = NULL;
    bool check_status              = ((service_in == NULL) || (session_in == NULL));
    int32_t sre_ret;

    if (check_status)
        return TEE_ERROR_BAD_PARAMETERS;

    service = *service_in;
    session = *session_in;

    check_status = ((service == NULL) || (session == NULL));
    if (check_status)
        return TEE_ERROR_BAD_PARAMETERS;

    sre_ret = release_session(service, session);
    session     = NULL;
    *session_in = NULL;

    /* when service thread is blocked and session count is 0, we release service thread */
    if (sre_ret == TIMEOUT_FAIL_RET) {
        tloge("%s is blocked and session count is %u\n", service->name,
            service->session_count);
        if (service->session_count == 0) {
            if (!is_build_in_service(&(service->property.uuid))) {
                    process_release_service(service, TA_REGION_RELEASE);
                    service     = NULL;
                    *service_in = NULL;
            } else {
                    service->init_build = 0;
                    recycle_srvc_thread(service);
            }
        }
        return TEE_SUCCESS;
    }

    if (service->session_count == 0 && service->ref_cnt == 0) {
        if (!is_build_in_service(&(service->property.uuid))) {
            /* for non-keepalive TA, we release service node and service thread */
            if (!service->property.keep_alive) {
                process_release_service(service, TA_REGION_RELEASE);
                service     = NULL;
                *service_in = NULL;
            }
        } else {
            /*
             * for non-keepalive TA, we need to recycle service thread
             * and set init_build to 0 for restarting process.
             */
            if (!service->property.keep_alive) {
                service->init_build = 0;
                recycle_srvc_thread(service);
            }
        }
    }
    return TEE_SUCCESS;
}

static bool do_target_session_close(struct session_struct *sess_context, struct service_struct *service_entry,
                                    uint32_t from_taskid, uint32_t level)
{
    TEE_Result ret;
    struct session_struct *sess = sess_context;
    struct service_struct *srvc = service_entry;

    if (sess->ta2ta_from_taskid == from_taskid) {
        tlogd("ta2ta targert call session : %u\n", sess->session_id);

        /* if level == MAX_TA2TA_LEVEL, it is the last level session */
        if (level < MAX_TA2TA_LEVEL) {
            tlogi("close next TA session level:%u\n", level);
            process_close_ta2ta_target_sessions(sess->task_id, (level + 1));
        }

        ret = process_close_session_entry(&srvc, &sess);
        if (ret != TEE_SUCCESS)
            tloge("close ta2ta object session failed: errorno =0x%x\n", ret);
        /*
         * once service or session is released,
         * we need to reiterate service list, otherwise,
         * service_tmp or sess_tmp point to mem which has been released.
         */
        if (srvc == NULL || sess == NULL) {
            tlogd("goto retry service list\n");
            return true;
        }
    }
    return false;
}

void process_close_ta2ta_target_sessions(uint32_t from_taskid, uint32_t level)
{
    bool need_reiterate                  = false;
    struct session_struct *sess_context  = NULL;
    struct session_struct *sess_tmp      = NULL;
    struct service_struct *service_entry = NULL;
    struct service_struct *service_tmp   = NULL;

    /* Go through all the services and all sessions */
    do {
        dlist_for_each_entry_safe (service_entry, service_tmp, get_service_head_ptr(),
                                   struct service_struct, service_list) {
            if (service_entry->is_service_dead)
                continue;
            need_reiterate = false;
            tlogd("iterate service %s \n", service_entry->name);
            dlist_for_each_entry_safe (sess_context, sess_tmp, &service_entry->session_head, struct session_struct,
                                session_list) {
                tlogd("iterate session %u \n", sess_context->session_id);
                need_reiterate = do_target_session_close(sess_context, service_entry, from_taskid, level);
                if (need_reiterate)
                    break;
            }
            if (need_reiterate)
                break;
        }
    } while (need_reiterate);
}

TEE_Result process_close_session(void)
{
    TEE_Result ret;

    if (g_cur_session == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    process_close_ta2ta_target_sessions(g_cur_session->task_id, g_cur_session->ta2ta_level);

    /* close current session itself */
    ret = process_close_session_entry(&g_cur_service, &g_cur_session);
    return ret;
}

TEE_Result process_open_session(const smc_cmd_t *cmd, uint32_t cmd_type)
{
    global_to_ta_msg entry_msg = { 0 };
    uint32_t ret;

    if (cmd == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    bool check_stat = (g_cur_service == NULL || g_cur_session == NULL);
    if (check_stat)
        return TEE_ERROR_SESSION_NOT_EXIST;

    if (g_cur_service->session_count == 1)
        entry_msg.first_session = 1;

    entry_msg.session_id      = set_session_context_bit(g_cur_service->index, g_cur_session->session_id);
    entry_msg.session_context = g_cur_session->session_context;
    entry_msg.cmd_id          = cmd->cmd_id;
    entry_msg.dev_id          = cmd->dev_file_id;
    entry_msg.started         = cmd->started;

    if (cmd_type == CMD_TYPE_NS_TO_SECURE) {
        if (cmd_ns_get_params(g_cur_session->task_id, cmd, &entry_msg.param_type, &entry_msg.params) != TEE_SUCCESS) {
            tloge("cmd_ns_get_params failed\n");
            goto map_error;
        }
        entry_msg.session_type = SESSION_FROM_CA;
    } else {
        if (TEE_SUCCESS !=
            cmd_secure_get_params(g_cur_session->task_id, cmd, &entry_msg.param_type, &entry_msg.params)) {
            tloge("cmd_secure_get_params failed\n");
            goto map_error;
        }
        entry_msg.session_type = SESSION_FROM_TA;
    }

    ret = send_global2ta_msg(&entry_msg, CALL_TA_OPEN_SESSION, g_cur_session->task_id, NULL);
    if (ret != 0) {
        tloge("CALL_TA_OPEN_SESSION msg send to ta failed:0x%x\n", ret);
        return (TEE_Result)ret;
    }
    g_cur_session->wait_ta_back_msg = true;
    return TEE_SUCCESS;
map_error:
    process_open_session_error();
    return TEE_ERROR_GENERIC;
}

void process_open_session_error(void)
{
    int sre_ret;
    uint32_t session_id;

    task_adapt_unregister_ta(&g_cur_service->property.uuid, g_cur_session->task_id);
    release_pam_node(g_cur_session->pam_node);
    task_del_mem_region(&(g_cur_session->map_mem), false);

    g_cur_service->session_count--;

    session_id = set_session_context_bit(g_cur_service->index, g_cur_session->session_id);
    sre_ret    = sre_task_delete_ex(g_cur_session->task_id, false, session_id);
    /* no return here, there's other clean work to do. */
    if (sre_ret != SUCC_RET)
        tloge("task del error fail 2: errorno =%d\n", sre_ret);

    CLR_BIT(g_cur_service->session_bitmap[get_index_by_uint32(g_cur_session->session_id - 1)],
            get_bit_by_uint32(g_cur_session->session_id - 1));
    dlist_delete(&g_cur_session->session_list);
    dlist_delete(&g_cur_session->child_ta_sess_list);
    TEE_Free(g_cur_session);
    g_cur_session = (struct session_struct *)NULL;

    /* when service thread is blocked and session count is 0, we release service thread */
    if (sre_ret == TIMEOUT_FAIL_RET) {
        tloge("%s is blocked and session count is %u\n", g_cur_service->name,
            g_cur_service->session_count);
        if (g_cur_service->session_count == 0) {
            if (!is_build_in_service(&(g_cur_service->property.uuid))) {
                    process_release_service(g_cur_service, TA_REGION_RELEASE);
                    g_cur_service = NULL;
            } else {
                    g_cur_service->init_build = 0;
                    recycle_srvc_thread(g_cur_service);
            }
        }
        return;
    }

    /* release dynamic loaded TA's resource */
    if (g_cur_service->session_count == 0 && g_cur_service->ref_cnt == 0) {
        /* for non-keepalive TA, we release service node and service thread; */
        if (!is_build_in_service(&(g_cur_service->property.uuid))) {
            bool need_release_service = (!g_cur_service->property.keep_alive ||
                                         (g_cur_service->property.keep_alive && g_cur_service->first_open));
            if (need_release_service) {
                process_release_service(g_cur_service, TA_REGION_RELEASE);
                g_cur_service = NULL;
            }
        } else {
            /*
             * for  non-keepalive TA, we release service thread
             * and set init_build to 0 for restarting process.
             */
            if (!g_cur_service->property.keep_alive) {
                g_cur_service->init_build = 0;
                recycle_srvc_thread(g_cur_service);
            }
        }
    }
}

bool process_init_session(void)
{
    if (g_cur_service == NULL || g_cur_session == NULL)
        return false;

    /* send non-standard property */
    if (g_cur_service->property.other_buff != NULL && g_cur_service->property.other_len != 0) {
        tlogd("Have non-standard property!");
        uint32_t ret = ipc_msg_snd(CALL_TA_OPEN_SESSION_PROP, g_cur_session->task_id,
                                   g_cur_service->property.other_buff, (uint16_t)g_cur_service->property.other_len);
        if (ret != 0) {
            tloge("CALL_TA_OPEN_SESSION_PROP msg send to ta failed:0x%x\n", ret);
            return false;
        }
        g_cur_session->wait_ta_back_msg = true;
        return true;
    }
    return false;
}

TEE_Result close_session(const smc_cmd_t *cmd, uint32_t cmd_type, bool *sync)
{
    TEE_Result ret;

    if (cmd == NULL || sync == NULL || g_cur_service == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    *sync = false;

    if (is_gtask_by_uuid(&g_cur_service->property.uuid)) {
        /* Send the answer to caller right away since the command was already processed */
        *sync = true;
        return TEE_SUCCESS;
    }

    bool check_stat = (g_cur_session == NULL || g_cur_session->session_id == 0 ||
                       g_cur_session->session_id > MAX_SESSION_ID);
    if (check_stat) {
        tloge("close session not exist\n");
        return TEE_ERROR_SESSION_NOT_EXIST;
    }

    if (memcpy_s(&g_cur_session->cmd_in, sizeof(smc_cmd_t), cmd, sizeof(smc_cmd_t)))
        return TEE_ERROR_GENERIC;

    ret = async_call_ta_entry(cmd, cmd_type, CALL_TA_CLOSE_SESSION);

    return ret;
}

TEE_Result close_session_async(struct session_struct *sess)
{
    if (sess == NULL) {
        tloge("invalid params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    struct service_struct *service = find_service_by_task_id(sess->task_id);
    if (service == NULL) {
        tloge("find service by task id 0x%x failed, session id is 0x%x\n", sess->task_id, sess->session_id);
        return TEE_ERROR_SERVICE_NOT_EXIST;
    }

    g_cur_service = service;
    g_cur_session = sess;
    tlogi("begin close service %s, session 0x%x async\n", service->name, sess->session_id);
    /* we reuse sess->cmd_in to do close session, operation_phys is invalid, so we clear it */
    sess->cmd_in.operation_phys = 0;
    sess->cmd_in.operation_h_phys = 0;
    return async_call_ta_entry(&(sess->cmd_in), sess->cmd_type, CALL_TA_CLOSE_SESSION);
}
