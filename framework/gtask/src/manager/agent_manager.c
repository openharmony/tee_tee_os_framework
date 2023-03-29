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
#include <mem_ops.h>
#include <dlist.h>
#include "tee_log.h"
#include "tee_mem_mgmt_api.h"
#include "ta_framework.h"
#include "gtask_inner.h"
#include "agent_manager.h"
#include "service_manager.h"
#include "mem_manager.h"
#include "session_manager.h"
#include "tee_ext_api.h"
#include "tee_config.h"
#include "gtask_config_hal.h"
#include "mem_page_ops.h"
#include "securec.h"
#include "permsrv_api.h"
#include "gtask_adapt.h"
#include "task_adaptor_pub.h"
#include "tee_internal_task_pub.h"
#include "global_task.h"
#include "tee_task_exception.h"
#include <ipclib_hal.h>

#define AGENT_MAX       32
#define BITS_PER_BYTE   8
extern struct session_struct *g_cur_session;

static struct dlist_node g_agent_head;
static uint32_t g_agent_cnt;

/*
 * service thread is a kthread 'CA' in tzdriver, it can be used
 * to handle build-in agent(ssa) request while there's
 * no source CA for agent request.
 * cases as list:
 * 1.TA open file but not close, ssa will do the close work in
 *   unregister work;
 * 2.permission service call ssa;
 * 3.tui service's release work if tui TA not release correctly.
 */
struct service_thread_control {
    smc_cmd_t cmd;
    bool working;
    struct dlist_node pending_head;
};
static struct service_thread_control g_svc_thread_ctrl;

struct service_thread_request {
    struct dlist_node list;
    uint32_t agent_id;
};

static TEE_Result tee_lock_agent(uint32_t agent_id, struct session_struct *session);
static void tee_unblock_agent(const struct session_struct *session, uint32_t cmd_id);
struct agent_control *find_agent(uint32_t agent_id);
static void tee_unlock_agent(struct agent_control *agent, uint32_t task_id);

void agent_manager_init(void)
{
    dlist_init(&g_agent_head);
    g_agent_cnt = 0;

    g_svc_thread_ctrl.working = false;
    dlist_init(&g_svc_thread_ctrl.pending_head);
}

bool is_system_agent(uint32_t agent_id)
{
    if (agent_id == TEE_FS_AGENT_ID || agent_id == TEE_MISC_AGENT_ID ||
        agent_id == TEE_SOCKET_AGENT_ID || agent_id == TEE_SECLOAD_AGENT_ID ||
        agent_id == TEE_VLTMM_AGENT_ID)
        return true;
    else
        return false;
}

static TEE_Result process_lock_agent(uint32_t agent_id, uint32_t task_id,
    struct service_struct *service, struct session_struct *session)
{
    if (is_system_agent(agent_id)) {
        if (!check_system_agent_permission(task_id, agent_id)) {
            tloge("task %s try to lock system agent:0x%x failed, permission denied\n",
                service->name, agent_id);
            tee_unblock_agent(session, TEE_INVALID_AGENT);
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }

    TEE_Result ret = tee_lock_agent(agent_id, session);
    if (ret == TEE_SUCCESS) {
        tlogd("Succeed to get the lock of agent %u\n", agent_id);
        tee_unblock_agent(session, TEE_AGENT_LOCK);
    } else if (ret != TEE_ERROR_BUSY) {
        tloge("Invalid agent %u\n", agent_id);
        tee_unblock_agent(session, TEE_INVALID_AGENT);
    } else {
        tlogd("Agent %d was already locked, will wait\n", agent_id);
    }

    return ret;
}

static TEE_Result process_unlock_agent(uint32_t agent_id, uint32_t task_id,
    struct session_struct *session)
{
    struct agent_control *agent    = NULL;
    struct session_struct *tmp_session = NULL;

    /* 1. Unlock all the agents in the session locked agents list */
    dlist_for_each_entry(agent, &session->locked_agents, struct agent_control, session_list) {
        if (agent->id == agent_id) {
            tlogd("Unlocking locked aggent %u\n", agent->id);
            dlist_delete(&agent->session_list);
            tee_unlock_agent(agent, task_id);
            /* Unblock sending task */
            tee_unblock_agent(session, TEE_AGENT_LOCK);
            return TEE_SUCCESS;
        }
    }
    tloge("Couldn't find agent to unlock!");

    /* 2. delete the node in the waiting list ,  shouldn't come here normally */
    agent = find_agent(agent_id);
    if (agent == NULL) {
        tloge("Failed to find the agent %u\n", agent_id);
        tee_unblock_agent(session, TEE_INVALID_AGENT);
        return TEE_ERROR_GENERIC;
    }

    while (!dlist_empty(&agent->waiting_sessions)) {
        tmp_session = dlist_first_entry(&agent->waiting_sessions, struct session_struct, waiting_agent);
        if (tmp_session == session) {
            tloge("session %x haven't get lock but to unlock agent %x\n", session->task_id, agent->id);
            dlist_delete(&session->waiting_agent);
        }
    }

    tee_unblock_agent(session, TEE_AGENT_LOCK);

    return TEE_ERROR_GENERIC;
}

static TEE_Result process_get_agent_buffer(uint32_t agent_id, uint32_t task_id,
    const struct session_struct *session)
{
    uint64_t buffer;
    global_to_ta_msg buffer_msg   = {0};
    struct agent_control *control = NULL;

    control = find_agent(agent_id);
    if (control == NULL) {
        tloge("Failed to find the agent 0x%x\n", agent_id);
        goto agent_error;
    }

    /* check the agent has been locked by the session */
    bool flag = (control->locked == true) && (control->locking_session == session);
    if (!flag) {
        tloge("this agent not locked by this session:agent=0x%x, task=0x%x\n", agent_id, task_id);
        goto agent_error;
    }

    if (control->buffer == 0) {
        if (task_map_ns_phy_mem(task_id, (uint64_t)control->phys_buffer, control->size, &buffer) != 0) {
            tloge("map smc cmd operation params failed\n");
            goto agent_error;
        }
        control->buffer = buffer;
    }
    buffer_msg.session_context = control->buffer;
    buffer_msg.param_type      = control->size;
    buffer_msg.cmd_id          = TEE_RETURN_AGENT_BUFFER;

    TEE_Result ret = send_global2ta_msg(&buffer_msg, TA_GET_AGENT_BUFFER, task_id, NULL);
    if (ret != TEE_SUCCESS)
        tloge("get agent buffer msg send to ta failed:0x%x\n", ret);
    return ret;

agent_error:
    tloge("Failed to get the buffer of agent %u\n", agent_id);
    buffer_msg.cmd_id          = TEE_INVALID_AGENT;
    buffer_msg.session_context = 0;
    if (send_global2ta_msg(&buffer_msg, 0x0, task_id, NULL) != TEE_SUCCESS)
        tloge("send agent msg to ta failed\n");
    return TEE_ERROR_GENERIC;
}

static TEE_Result set_agent_status(uint32_t agent_id, struct session_struct *session)
{
    struct agent_control *control = NULL;

    control = find_agent(agent_id);
    if (control != NULL) {
        if (!control->locked || control->locking_session != session) {
            tloge("control->locked=%d\n", control->locked);
            return TEE_ERROR_GENERIC;
        }
        session->agent_pending = true;
        return TEE_SUCCESS;
    } else {
        tloge("Failed to find the agent 0x%x\n", agent_id);
        return TEE_ERROR_GENERIC;
    }
}

struct agent_control *find_agent(uint32_t agent_id)
{
    struct agent_control *tmp_control = NULL;
    uint32_t find_flag                = 0;

    dlist_for_each_entry(tmp_control, &g_agent_head, struct agent_control, list) {
        if (tmp_control->id == agent_id) {
            find_flag = 1;
            break;
        }
    }
    if (find_flag == 0) {
        tlogd("Failed to find the agent 0x%x\n", agent_id);
        return NULL;
    }
    tlogd("Found agent 0x%x \n", agent_id);
    return tmp_control;
}

static TEE_Result add_agent_control(uint32_t agent_id, paddr_t agent_buf_phys_addr, uint32_t agent_buf_size)
{
    struct agent_control *tmp_control = TEE_Malloc(sizeof(struct agent_control), 0);
    if (tmp_control == NULL) {
        tloge("malloc for agent_control failed!\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    dlist_insert_tail(&tmp_control->list, &g_agent_head);
    dlist_init(&tmp_control->waiting_sessions);

    tmp_control->id              = agent_id;
    tmp_control->locking_session = NULL;
    tmp_control->locked          = false;
    tmp_control->buffer          = 0;
    tmp_control->phys_buffer     = agent_buf_phys_addr;
    tmp_control->size            = agent_buf_size;

    ++g_agent_cnt;

    return TEE_SUCCESS;
}

static TEE_Result check_agent_param(const smc_cmd_t *cmd, TEE_Param **param, uint32_t *param_type)
{
    if (cmd == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (cmd_global_ns_get_params(cmd, param_type, param) != TEE_SUCCESS) {
        tloge("Failed to get param\n");
        return TEE_ERROR_GENERIC;
    }

    /* check params types */
    if ((TEE_PARAM_TYPE_GET(*param_type, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        (TEE_PARAM_TYPE_GET(*param_type, 1) != TEE_PARAM_TYPE_VALUE_INPUT)) {
        tloge("Bad expected parameter types.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* this condition should never happen here */
    if (*param == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}

TEE_Result register_agent(const smc_cmd_t *cmd)
{
    uint32_t agent_id;
    uint32_t param_type = 0;
    TEE_Param *param = NULL;
    paddr_t agent_buf_phys_addr;
    uint32_t agent_buf_size;

    if (g_agent_cnt >= AGENT_MAX) {
        tloge("Failed to register agent, exceeds the max agents");
        return TEE_ERROR_GENERIC;
    }

    TEE_Result ret = check_agent_param(cmd, &param, &param_type);
    if (ret != TEE_SUCCESS)
        return ret;

    agent_buf_phys_addr = (paddr_t)(param[0].value.a | ((paddr_t)param[0].value.b << SHIFT_OFFSET));
    agent_buf_size      = param[1].value.a;
    if (!in_mailbox_range(agent_buf_phys_addr, agent_buf_size)) {
        tloge("agent buf is not in mailbox range!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    agent_id = cmd->agent_id;
    tlogd("register agent id = 0x%x, size=%u\n", agent_id, agent_buf_size);
#ifndef CONFIG_REGISTER_OTHER_AGENT
    if (!is_system_agent(agent_id)) {
        tloge("not system agent!\n");
        return TEE_ERROR_GENERIC;
    }
#endif
    if ((agent_buf_size < AGENT_BUFF_SIZE) || (agent_buf_size > BITS_PER_BYTE * AGENT_BUFF_SIZE))
        return TEE_ERROR_GENERIC;

    // judge agent is exist
    if (find_agent(agent_id)) {
        tloge("agent whose id = 0x%x has been registered\n", agent_id);
        goto fail0;
    }

    if (add_agent_control(agent_id, agent_buf_phys_addr, agent_buf_size) != TEE_SUCCESS)
        goto fail0;

    task_adapt_register_agent(agent_id);
    return TEE_SUCCESS;

fail0:
    return TEE_ERROR_GENERIC;
}

TEE_Result unregister_agent(const smc_cmd_t *cmd)
{
    struct agent_control *control  = NULL;
    struct session_struct *session = NULL;
    uint32_t agent_id;
    uint32_t param_type = 0;
    TEE_Param *param    = NULL;

    if (g_agent_cnt == 0) {
        tloge("Failed to unregister agent, no more agent exists!\n");
        return TEE_ERROR_GENERIC;
    }

    TEE_Result ret = check_agent_param(cmd, &param, &param_type);
    if (ret != TEE_SUCCESS)
        return ret;

    agent_id = cmd->agent_id;
    tlogd("unregister agent id = 0x%x\n", agent_id);

    if (is_system_agent(agent_id)) {
        tloge("system agents not allowed to unregister\n");
        return TEE_ERROR_GENERIC;
    }
    control = find_agent(agent_id);
    if (control != NULL) {
        if (control->locked) {
            tloge("agent already had lock set, cannot be unregistered!\n");
            return TEE_ERROR_GENERIC;
        }
        /* If we have waiting sessions then unlock them */
        while (!dlist_empty(&control->waiting_sessions)) {
            tlogd("Agent %u has blocked sessions\n", control->id);
            session = dlist_first_entry(&control->waiting_sessions, struct session_struct, waiting_agent);
            tee_unblock_agent(session, TEE_INVALID_AGENT);
            tlogd("Agent %u unblock session task\n", session->task_id);
            dlist_delete(&session->waiting_agent);
        }

        dlist_delete(&control->list);
        TEE_Free(control);
        control = NULL;
        --g_agent_cnt;
    }
    return TEE_SUCCESS;
}

TEE_Result tee_get_agent_buffer(uint32_t agent_id, paddr_t *buffer, uint32_t *length)
{
    struct agent_control *control = NULL;

    if (buffer == NULL || length == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    control = find_agent(agent_id);
    if (control == NULL) {
        tloge("Failed to find the agent %u\n", agent_id);
        return TEE_ERROR_GENERIC;
    }
    tlogd("Found agent %u \n", agent_id);
    *buffer = control->phys_buffer;
    *length = control->size;
    return TEE_SUCCESS;
}

static void tee_unblock_agent(const struct session_struct *session, uint32_t cmd_id)
{
    global_to_ta_msg buffer_msg = { 0 };

    if (session == NULL)
        return;

    buffer_msg.cmd_id = cmd_id;
    if (send_global2ta_msg(&buffer_msg, TA_LOCK_ACK, session->task_id, NULL) != TEE_SUCCESS)
        tloge("send msg failed\n");
}

static void add_waiting_session(struct session_struct *session, const struct agent_control *control)
{
    struct session_struct *sess_context = NULL;

    if (session == NULL || control == NULL) {
        tloge("session or control is null\n");
        return;
    }

    dlist_for_each_entry(sess_context, &control->waiting_sessions, struct session_struct, waiting_agent) {
        if (sess_context == session && sess_context->session_id == session->session_id) {
            tloge("session already add into agent waiting_sessions list\n");
            return;
        }
    }

    dlist_insert_tail(&session->waiting_agent, &control->waiting_sessions);

    return;
}

static TEE_Result tee_lock_agent(uint32_t agent_id, struct session_struct *session)
{
    struct agent_control *control = NULL;

    if (session == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    control = find_agent(agent_id);
    if (control == NULL) {
        tloge("Failed to find the agent %u\n", agent_id);
        return TEE_ERROR_GENERIC;
    }

    if (control->locking_session == session)
        return TEE_SUCCESS;

    if (control->locked) {
        /* Add the session in the agent's waiting list */
        add_waiting_session(session, control);
        return TEE_ERROR_BUSY;
    }
    control->locking_session = session;
    control->locked          = true;
    dlist_insert_tail(&control->session_list, &session->locked_agents);
    tlogd("Locked agent %u\n", agent_id);
    return TEE_SUCCESS;
}

static void tee_unlock_agent(struct agent_control *agent, uint32_t task_id)
{
    struct session_struct *session = NULL;

    if (agent == NULL)
        return;

    agent->locked          = false;
    agent->locking_session = NULL;

    if (agent->buffer != 0) {
        if (task_unmap(task_id, agent->buffer, agent->size) != 0)
            tloge("unmap agent buffer error\n");

        agent->buffer = 0;
    }

    /* If we have waiting sessions then unlock them */
    if (!dlist_empty(&agent->waiting_sessions)) {
        tlogd("Agent %d has blocked session\n", agent->id);
        session = dlist_entry(agent->waiting_sessions.next, struct session_struct, waiting_agent);
        tlogd("Agent %d unblock session task\n", session->task_id);

        dlist_delete(&session->waiting_agent);
        /* Need to lock the agent on the new session */
        if (tee_lock_agent(agent->id, session) != TEE_SUCCESS) {
            tloge("Failed to add new lock on agent!");
            tee_unblock_agent(session, TEE_INVALID_AGENT);
        } else {
            tee_unblock_agent(session, TEE_AGENT_LOCK);
        }
    }
}

void tee_unlock_agents(struct session_struct *session)
{
    struct agent_control *agent = NULL;
    struct agent_control *tmp   = NULL;

    if (session == NULL)
        return;

    /* Unlock all the agents in the session locked agents list */
    dlist_for_each_entry_safe(agent, tmp, &session->locked_agents, struct agent_control, session_list) {
        agent = dlist_first_entry(&session->locked_agents, struct agent_control, session_list);
        tlogd("Unlocking locked aggent %u\n", agent->id);
        dlist_delete(&agent->session_list);
        tee_unlock_agent(agent, session->task_id);
    }
}

/* caller needs to ensure dest_task_id is valid */
void register_agent_buffer_to_task(uint32_t agent_id, uint32_t dest_task_id)
{
    struct reg_agent_buf reg_msg;
    struct agent_control *control = NULL;

    control = find_agent(agent_id);
    if (control != NULL) {
        reg_msg.agentid  = agent_id;
        reg_msg.phys_addr = control->phys_buffer;
        reg_msg.size     = control->size;
        uint32_t ret     = ipc_msg_snd((uint32_t)TEE_TASK_REGISTER_AGENT, dest_task_id, &reg_msg, sizeof(reg_msg));
        if (ret != 0)
            tloge("send reg agent msg to 0x%x failed, err=0x%x\n", dest_task_id, ret);
    } else {
        tloge("agent %u is not ready\n", agent_id);
    }
}

enum LATE_INIT_INDEX {
    FS_LATE_INIT = 0x1,
};
TEE_Result agent_late_init(const smc_cmd_t *cmd)
{
    uint32_t param_type = 0;
    TEE_Param *param    = NULL;
    uint32_t index;

    if (cmd == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (cmd_global_ns_get_params(cmd, &param_type, &param) != 0)
        return TEE_ERROR_GENERIC;

    /* check params types */
    if (TEE_PARAM_TYPE_GET(param_type, 0) != TEE_PARAM_TYPE_VALUE_INPUT) {
        tloge("Bad expected parameter types.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* this condition should never happen here */
    if (param == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    index = param[0].value.a;
    if (index == FS_LATE_INIT)
        fs_agent_late_init();

    return TEE_SUCCESS;
}

TEE_Result set_service_thread_cmd(const smc_cmd_t *cmd, bool *async)
{
    if (cmd == NULL || async == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (memcpy_s(&g_svc_thread_ctrl.cmd, sizeof(smc_cmd_t), cmd, sizeof(smc_cmd_t)) != EOK) {
        tloge("memcpy cmd failed\n");
        return TEE_ERROR_GENERIC;
    }

    *async = true;
    return TEE_SUCCESS;
}

static smc_cmd_t *get_service_thread_cmd(void)
{
    if (g_svc_thread_ctrl.working == true) {
        tloge("agent svc thread is working, wait until last request done\n");
        return NULL;
    }
    g_svc_thread_ctrl.working = true;

    return &g_svc_thread_ctrl.cmd;
}

static TEE_Result service_thread_request_enqueue(uint32_t agent_id)
{
    struct service_thread_request *request = NULL;

    request = TEE_Malloc(sizeof(struct service_thread_request), ZERO);
    if (request == NULL) {
        tloge("alloc request failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    request->agent_id     = agent_id;
    dlist_insert_tail(&request->list, &g_svc_thread_ctrl.pending_head);

    return TEE_SUCCESS;
}

bool service_thread_request_dequeue(const smc_cmd_t *in, smc_cmd_t *out)
{
    struct service_thread_request *request = NULL;
    bool check_stat                        = (in == NULL || out == NULL);

    if (check_stat)
        return false;

    /* if it's a agent response from svc thread */
    if (in->event_nr != g_svc_thread_ctrl.cmd.event_nr)
        return false;

    if (dlist_empty(&g_svc_thread_ctrl.pending_head)) {
        g_svc_thread_ctrl.working = false;
        return false;
    }

    if (memcpy_s(out, sizeof(smc_cmd_t), &g_svc_thread_ctrl.cmd, sizeof(smc_cmd_t)) != EOK) {
        tloge("memcpy_s failed\n");
        return false;
    }
    request = dlist_first_entry(&g_svc_thread_ctrl.pending_head, struct service_thread_request, list);
    if (request == NULL) {
        tloge("request is null\n");
        return false;
    }
    out->agent_id = request->agent_id;

    dlist_delete(&request->list);
    TEE_Free(request);

    return true;
}

static void put_agent_request_cmd(smc_cmd_t *cmd, uint32_t cmd_type, uint32_t agent_id)
{
    cmd->ret_val  = TEE_PENDING2;
    cmd->agent_id = agent_id;
    cmd->cmd_type  = cmd_type;

    int ret = put_last_out_cmd(cmd);
    if (ret != GT_ERR_OK)
        tloge("put agent req cmd fail:%d, cmd type=%u, agent id=0x%x\n", ret, cmd_type, agent_id);
}

int32_t handle_ta_agent_back_cmd(smc_cmd_t *cmd)
{
    TEE_Result ret;
    uint32_t cmd_type;

    if (cmd == NULL)
        return GT_ERR_END_CMD;

    if (cmd->cmd_type == CMD_TYPE_TA2TA_AGENT) {
        /* hanle TA2TA->AGENT back cmd */
        cmd_type = CMD_TYPE_SECURE_TO_SECURE;
        ret = init_ta2ta_agent_context(cmd);
        if (ret != TEE_SUCCESS) {
            tloge("init TA2TA agent back context failed, ret = 0x%x\n", ret);
            goto ta_dead_chk;
        }

        /*
         * we restore cmd_in here for GLOBAL_CMD_ID_KILL_TASK, because:
         * 1. ca invoke ta1, tzdriver will put smc_cmd_1 in g_cmd_data->in
         * 2. ta1 invoke ta2, using smc_cmd_2
         * 3. when ta2 call agent, gtask will put_last_out_cmd, which will put smc_cmd_2 to g_cmd_data->out
         * 4. tzdriver will copy g_cmd_data->out to g_cmd_data->in when agent back
         * 5. after that, if kill ca, tzdriver will send GLOBAL_CMD_ID_KILL_TASK to gtask, reuse g_cmd_data->in,
         * which is smc_cmd_2, that will cause kill ta1 fail. actually, we need reuse smc_cmd_1
         */
        struct service_struct *service = NULL;
        struct session_struct *session = NULL;
        if (g_cur_session != NULL && find_task(g_cur_session->ta2ta_from_taskid, &service, &session)) {
            if (session != NULL)
                restore_cmd_in(&(session->cmd_in));
        }
    } else {
        /* hanle CA2TA->AGENT back cmd */
        cmd_type = CMD_TYPE_NS_TO_SECURE;
        ret = init_ta_context(cmd);
        if (ret != TEE_SUCCESS) {
            tloge("init TA context failed, ret = 0x%x\n", ret);
            goto ta_dead_chk;
        }
    }

    if (g_cur_session == NULL || !g_cur_session->agent_pending) {
        tloge("session is null or is not in agent pending status, agent id=0x%x\n", cmd->agent_id);
        goto error;
    }

    g_cur_session->agent_pending = false;
    /* reset cmd_type & agent_id for reuse cmd like TEE_PENDING */
    cmd->cmd_type = g_cur_session->cmd_in.cmd_type;
    cmd->agent_id = 0;

    /* resume app task that pending on message */
    ret = start_ta_task(cmd, cmd_type);
    if (ret != TEE_SUCCESS) {
        tloge("resume agent pending error:%x\n", ret);
        goto error;
    }
    return GT_ERR_OK;
ta_dead_chk:
    /* TA may has exception, service is dead */
    if (ret == TEE_ERROR_SERVICE_NOT_EXIST) {
        if (ta_exception_handle_agent_ack(cmd) == TEE_SUCCESS)
            return GT_ERR_OK;
    }
error:
    set_tee_return(cmd, ret);
    ns_cmd_response(cmd);
    return GT_ERR_END_CMD;
}

/* handle service agent(e.g. ssa) back cmd */
int32_t handle_service_agent_back_cmd(const smc_cmd_t *cmd)
{
    uint32_t agent_task_id;
    uint32_t *agent_status = NULL;
    uint32_t caller_task_id;
    uint32_t ret;

    if (cmd == NULL)
        return GT_ERR_END_CMD;

    if (!is_agent_response(cmd->agent_id, &agent_task_id, &caller_task_id, &agent_status)) {
        tloge("unexcepted buildin agent back cmd, agent id=0x%x\n", cmd->agent_id);
        return GT_ERR_END_CMD;
    }

    if ((*agent_status) != TEE_PENDING2) {
        tloge("unexcepted buildint agent status, agent id=0x%x\n", cmd->agent_id);
        return GT_ERR_END_CMD;
    }

    ret = ipc_msg_snd(TEE_TASK_AGENT_SMC_ACK, agent_task_id, NULL, 0);
    if (ret != 0)
        tloge("send msg to agent:%u fail:%u\n", agent_task_id, ret);

    smc_cmd_t cmd_out;
    struct service_struct *service = NULL;
    struct session_struct *session = NULL;

    *agent_status = 0;
    if (find_task(caller_task_id, &service, &session))
        session->agent_pending = false;
    else if (find_service_by_task_id(caller_task_id) == NULL)
        /* TA may be crash, service is dead */
        ta_exception_handle_buildin_agent_ack(caller_task_id);

    if (service_thread_request_dequeue(cmd, &cmd_out)) {
        tlogi("agent svc thread process pending work\n");
        put_agent_request_cmd(&cmd_out, CMD_TYPE_BUILDIN_AGENT, cmd_out.agent_id);
    }
    return GT_ERR_OK;
}

/* handle service agent(e.g. ssa) request */
static TEE_Result handle_service_agent_request(uint32_t caller_task_id,
    uint32_t agent_id, uint32_t *agent_status)
{
    smc_cmd_t cmd;
    smc_cmd_t *cmd_in = NULL;
    struct service_struct *service = NULL;
    struct session_struct *session = NULL;

    if (!find_task(caller_task_id, &service, &session)) {
        tlogd("can't find ta session by task id %u, will use svc thread\n", caller_task_id);
        cmd_in = get_service_thread_cmd();
        if (cmd_in == NULL) {
            if (service_thread_request_enqueue(agent_id) != TEE_SUCCESS) {
                tloge("svc request enqueue failed\n");
                return TEE_ERROR_GENERIC;
            }
            *agent_status = TEE_PENDING2;
            return TEE_SUCCESS;
        }
    } else {
        cmd_in = &session->cmd_in;
        session->agent_pending = true;
    }

    errno_t rc = memcpy_s(&cmd, sizeof(cmd), cmd_in, sizeof(*cmd_in));
    if (rc != EOK) {
        tloge("memcpy cmd failed, rc=%d, line:%d.\n", rc, __LINE__);
        return TEE_ERROR_GENERIC;
    }

    *agent_status = TEE_PENDING2;
    put_agent_request_cmd(&cmd, CMD_TYPE_BUILDIN_AGENT, agent_id);
    return TEE_SUCCESS;
}

static TEE_Result handle_ta_agent_request(uint32_t agent_id, struct session_struct *session)
{
    smc_cmd_t cmd;
    TEE_Result ret;
    uint32_t agent_type;
    global_to_ta_msg entry_msg = {0};

    session_set_cancelable(false);
    /*
     * Need to return to NWD for agent process then we resume,
     * TA is waiting, nwd will send smc back
     */
    if (set_agent_status(agent_id, session) == TEE_SUCCESS) {
        agent_type = (session->cmd_type == CMD_TYPE_SECURE_TO_SECURE) ?
            CMD_TYPE_TA2TA_AGENT : CMD_TYPE_TA_AGENT;

        (void)memcpy_s(&cmd, sizeof(cmd), &session->cmd_in, sizeof(session->cmd_in));
        put_agent_request_cmd(&cmd, agent_type, agent_id);
        return TEE_SUCCESS;
    }

    /* TA tried to call invalid agent */
    entry_msg.cmd_id = TEE_INVALID_AGENT;
    ret = send_global2ta_msg(&entry_msg, 0x0, session->task_id, NULL);
    if (ret != TEE_SUCCESS)
        tloge("msg send to ta failed:0x%x\n", ret);
    return ret;
}

static TEE_Result handle_agent_pending_msg(uint32_t agent_id, uint32_t task_id, struct session_struct *session)
{
    uint32_t caller_task_id;
    uint32_t *agent_status = NULL;

    if (is_service_agent_request(task_id, &caller_task_id, &agent_status))
        return handle_service_agent_request(caller_task_id, agent_id, agent_status);
    else
        return handle_ta_agent_request(agent_id, session);
}

/*
 * this function do not support 32-bit TA or service sends agent request to 64-bit gtask,
 * we should solve this problem later
 */
int32_t handle_agent_request(uint32_t cmd_id, uint32_t task_id, const uint8_t *msg_buf, uint32_t msg_size)
{
    errno_t rc;
    TEE_Result ret;
    uint32_t caller_task_id;
    struct ta_to_global_msg msg;
    struct service_struct *service = NULL;
    struct session_struct *session = NULL;

    if (msg_buf == NULL || msg_size < sizeof(msg)) {
        tloge("invalid msg param, msg size %u\n", msg_size);
        return GT_ERR_END_CMD;
    }

    rc = memcpy_s(&msg, sizeof(msg), msg_buf, sizeof(msg));
    if (rc != EOK) {
        tloge("memcpy agent request msg failed, rc=%d, line:%d\n", rc, __LINE__);
        return GT_ERR_END_CMD;
    }

    caller_task_id = task_id;

    if (find_task(caller_task_id, &service, &session) == false) {
        tloge("find task 0x%x failed, agent request %u failed\n", caller_task_id, cmd_id);
        return GT_ERR_END_CMD;
    }

    switch (cmd_id) {
    case TA_LOCK_AGENT:
        ret = process_lock_agent(msg.agent_id, caller_task_id, service, session);
        break;
    case TA_UNLOCK_AGENT:
        ret = process_unlock_agent(msg.agent_id, caller_task_id, session);
        break;
    case TA_GET_AGENT_BUFFER:
        ret = process_get_agent_buffer(msg.agent_id, caller_task_id, session);
        break;
    case TEE_TASK_AGENT_SMC_CMD:
        ret = handle_agent_pending_msg(msg.agent_id, caller_task_id, session);
        break;
    default:
        ret = TEE_ERROR_BAD_PARAMETERS;
        tloge("invalid agent request cmd %u\n", cmd_id);
        break;
    }
    if (ret != TEE_SUCCESS)
        return GT_ERR_END_CMD;

    return GT_ERR_OK;
}
