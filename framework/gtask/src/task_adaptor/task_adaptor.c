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

#include "task_adaptor.h"
#include <stddef.h>
#include <string.h>
#include <securec.h>
#include <ipclib.h>
#include "gtask_inner.h"
#include "service_manager.h"
#include "task_ssa_adaptor.h"
#include "task_perm_service_adaptor.h"
#include "task_se_service_adaptor.h"
#include "permsrv_api.h"
#include "task_adaptor_pub.h"
#include "task_dynamic_adaptor.h"
#include "task_register.h"
#include <ipclib_hal.h>

#define MAX_TASK_NUM    20
static struct dlist_node g_task_list_head;
static uint32_t g_task_list_num = 0;

struct task_adaptor_info *find_task_by_taskid(uint32_t task_id)
{
    struct dlist_node *pos               = NULL;
    struct task_adaptor_info *task_entry = NULL;

    if (task_id == INVALID_TASK_ID) {
        tloge("task id is invalid\n");
        return NULL;
    }

    dlist_for_each(pos, &g_task_list_head) {
        task_entry = dlist_entry(pos, struct task_adaptor_info, task_node);
        if (taskid_to_pid(task_entry->task_id) == taskid_to_pid(task_id))
            return task_entry;
    }
    return NULL;
}

struct task_adaptor_info *find_task_by_uuid(const TEE_UUID *uuid)
{
    struct dlist_node *pos               = NULL;
    struct task_adaptor_info *task_entry = NULL;

    if (uuid == NULL) {
        tloge("uuid is null\n");
        return NULL;
    }

    dlist_for_each(pos, &g_task_list_head) {
        task_entry = dlist_entry(pos, struct task_adaptor_info, task_node);
        if (memcmp(&task_entry->uuid, uuid, sizeof(task_entry->uuid)) == 0)
            return task_entry;
    }
    return NULL;
}

static struct task_adaptor_info *add_task_to_list(const TEE_UUID *uuid, const char *task_name,
    const struct srv_adaptor_config_t *srv_config)
{
    if (uuid == NULL) {
        tloge("uuid is null\n");
        return NULL;
    }

    /* already exist, return directly */
    struct task_adaptor_info *task = find_task_by_uuid(uuid);
    if (task != NULL)
        return task;

    if (g_task_list_num >= MAX_TASK_NUM)
        return NULL;

    task = TEE_Malloc(sizeof(*task), 0);
    if (task == NULL) {
        tloge("malloc task adaptor info failed\n");
        return NULL;
    }

    errno_t ret = memset_s(task, sizeof(*task), 0, sizeof(*task));
    if (ret != EOK) {
        tloge("memset task adaptor info failed\n");
        TEE_Free(task);
        return NULL;
    }
    ret = memcpy_s(&task->uuid, sizeof(task->uuid), uuid, sizeof(*uuid));
    if (ret != EOK) {
        tloge("memcpy uuid failed\n");
        TEE_Free(task);
        return NULL;
    }

    ret = memcpy_s(&task->task_name, sizeof(task->task_name), task_name, strlen(task_name));
    if (ret != EOK) {
        tloge("memcpy task name failed\n");
        TEE_Free(task);
        return NULL;
    }

    if (srv_config != NULL) {
        task->agent_id = srv_config->agent_id;
        task->is_need_release_ta_res = srv_config->is_need_release_ta_res;
        task->crash_callback = srv_config->crash_callback;
        task->is_need_create_msg = srv_config->is_need_create_msg;
        task->is_need_release_msg = srv_config->is_need_release_msg;
    }

    /* here Initialize the struct member to an illegal value */
    task->task_id  = INVALID_TASK_ID;
    task->is_agent = false;
    dlist_insert_tail(&task->task_node, &g_task_list_head);
    g_task_list_num++;
    return task;
}

void del_task_from_list(const TEE_UUID *uuid)
{
    struct dlist_node *pos               = NULL;
    struct dlist_node *next              = NULL;
    struct task_adaptor_info *task_entry = NULL;

    if (uuid == NULL) {
        tloge("uuid is null\n");
        return;
    }

    dlist_for_each_safe(pos, next, &g_task_list_head) {
        task_entry = dlist_entry(pos, struct task_adaptor_info, task_node);
        if (memcmp(&task_entry->uuid, uuid, sizeof(task_entry->uuid)) == 0) {
            dlist_delete(pos);
            TEE_Free(task_entry);
            if (g_task_list_num > 0)
                g_task_list_num--;
            return;
        }
    }
}

bool is_internal_task_by_task_id(uint32_t task_id)
{
    struct task_adaptor_info *task = find_task_by_taskid(task_id);
    if (task == NULL)
        return false;
    return true;
}

bool is_internal_task_by_uuid(const TEE_UUID *uuid)
{
    struct task_adaptor_info *task = find_task_by_uuid(uuid);
    if (task == NULL)
        return false;
    return true;
}

int32_t task_adapt_set_caller_info(uint32_t cmd_id, uint32_t task_id, const uint8_t *msg_buf, uint32_t msg_size)
{
    TEE_Result ret = TEE_SUCCESS;
    uint32_t sre_ret;

    (void)cmd_id;
    struct task_adaptor_info *task = find_task_by_taskid(task_id);
    if (task == NULL) {
        tloge("unknown task_id, 0x%x", task_id);
        return GT_ERR_END_CMD;
    }

    if (msg_buf == NULL) {
        tloge("set caller info failed, param is null");
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto send_ack;
    }
    if (msg_size < sizeof(struct task_caller_info)) {
        tloge("invalid msg size %u for caller info", msg_size);
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto send_ack;
    }

    errno_t rc = memcpy_s(&task->caller_info, sizeof(task->caller_info), msg_buf, sizeof(task->caller_info));
    if (rc != EOK) {
        tloge("mem copy caller info msg failed, rc=%d\n", rc);
        ret = TEE_ERROR_GENERIC;
        goto send_ack;
    }
send_ack:
    sre_ret = ipc_msg_snd(TEE_TASK_SET_CALLER_INFO_ACK, task_id, (void *)(&ret), sizeof(ret));
    if (sre_ret != SRE_OK || ret != TEE_SUCCESS) {
        tloge("set caller info from task 0x%x failed\n", task_id);
        return GT_ERR_END_CMD;
    }
    return GT_ERR_OK;
}

void task_adapt_crash_callback(uint32_t task_id)
{
    struct task_adaptor_info *task = find_task_by_taskid(task_id);
    if (task == NULL) {
        tloge("unknown task_id, 0x%x", task_id);
        return;
    }

    task->task_id = INVALID_TASK_ID;
    if (task->task_crash_callback == NULL) {
        tloge("failed to find task crash callback func, task_id 0x%x", task_id);
        return;
    }

    struct srv_adaptor_config_t config = {0};
    config.task_prio = task->task_prio;
    config.agent_id = task->agent_id;
    config.is_need_release_ta_res = task->is_need_release_ta_res;
    config.crash_callback = task->crash_callback;
    config.is_need_create_msg = task->is_need_create_msg;
    config.is_need_release_msg = task->is_need_release_msg;

    task->task_crash_callback(&task->uuid, task->task_name, &config);
}

void send_register_ta_to_task(const struct reg_ta_info *reg_msg, uint32_t dest_task_id)
{
    if (reg_msg == NULL) {
        tloge("msg is null, send reg ta failed\n");
        return;
    }

    uint32_t ret = ipc_msg_snd(TEE_TASK_OPEN_TA_SESSION, dest_task_id, reg_msg, sizeof(*reg_msg));
    if (ret != SRE_OK)
        tloge("send reg ta msg to task 0x%x failed\n", dest_task_id);
}

/* param ssa_enum_enable is just for task ssa */
void task_adapt_register_ta(uint32_t ta_task_id, uint32_t userid, bool ssa_enum_enable, const TEE_UUID *uuid)
{
    struct reg_ta_info reg_msg;
    struct dlist_node *pos               = NULL;
    struct task_adaptor_info *task_entry = NULL;

    if (uuid == NULL) {
        tloge("uuid is null, reg ta failed\n");
        return;
    }

    reg_msg.taskid          = ta_task_id;
    reg_msg.userid          = userid;
    reg_msg.ssa_enum_enable = ssa_enum_enable;
    errno_t ret             = memcpy_s(&reg_msg.uuid, sizeof(reg_msg.uuid), uuid, sizeof(*uuid));
    if (ret != EOK) {
        tloge("memcpy uuid failed\n");
        return;
    }

    dlist_for_each(pos, &g_task_list_head) {
        task_entry = dlist_entry(pos, struct task_adaptor_info, task_node);
        if (task_entry->register_ta_to_task != NULL && task_entry->task_id != INVALID_TASK_ID &&
            ta_task_id != task_entry->task_id)
            task_entry->register_ta_to_task(&reg_msg, task_entry->task_id);
    }
}

void send_unregister_ta_to_task(const char *cur_task_name, const struct reg_ta_info *reg_msg,
    uint32_t dest_task_id)
{
    (void)cur_task_name;
    if (reg_msg == NULL) {
        tloge("msg is null, send unreg ta failed\n");
        return;
    }

    uint32_t ret = ipc_msg_snd(TEE_TASK_CLOSE_TA_SESSION, dest_task_id, reg_msg, sizeof(*reg_msg));
    if (ret != SRE_OK)
        tloge("send unreg ta msg to task 0x%x failed\n", dest_task_id);
}

void task_adapt_unregister_ta(const TEE_UUID *ta_uuid, uint32_t ta_task_id)
{
    struct reg_ta_info reg_msg;
    struct dlist_node *pos               = NULL;
    struct task_adaptor_info *task_entry = NULL;

    if (ta_uuid == NULL) {
        tloge("uuid is null, unreg ta failed\n");
        return;
    }

    errno_t ret = memset_s(&reg_msg, sizeof(reg_msg), 0, sizeof(reg_msg));
    if (ret != EOK)
        tloge("memset reg msg failed\n");

    (void)memcpy_s(&reg_msg.uuid, sizeof(TEE_UUID), ta_uuid, sizeof(TEE_UUID));
    reg_msg.taskid = ta_task_id;
    dlist_for_each(pos, &g_task_list_head) {
        task_entry = dlist_entry(pos, struct task_adaptor_info, task_node);
        if (task_entry->unregister_ta_to_task != NULL && task_entry->task_id != INVALID_TASK_ID &&
            ta_task_id != task_entry->task_id)
            task_entry->unregister_ta_to_task(task_entry->task_name, &reg_msg, task_entry->task_id);
    }
}

void task_adapt_send_ta_create_msg(const struct reg_ta_info *msg, uint32_t dest_task_id)
{
    if (msg == NULL) {
        tloge("msg is null, send ta create msg failed\n");
        return;
    }

    uint32_t ret = ipc_msg_snd(TEE_TASK_CREATE_TA_SERVICE, dest_task_id, msg, sizeof(*msg));
    if (ret != SRE_OK)
        tloge("send ta create msg to task 0x%x failed\n", dest_task_id);
}

void task_adapt_ta_create(uint32_t pid, const TEE_UUID *uuid)
{
    struct reg_ta_info msg;
    struct dlist_node *pos               = NULL;
    struct task_adaptor_info *task_entry = NULL;

    if (uuid == NULL) {
        tloge("uuid is null, task adapt proc ta create failed\n");
        return;
    }

    errno_t ret = memset_s(&msg, sizeof(msg), 0, sizeof(msg));
    if (ret != EOK) {
        tloge("memset task reg ta info failed\n");
        return;
    }

    msg.taskid = pid;
    ret = memcpy_s(&msg.uuid, sizeof(msg.uuid), uuid, sizeof(*uuid));
    if (ret != EOK) {
        tloge("memcpy uuid failed\n");
        return;
    }

    dlist_for_each(pos, &g_task_list_head) {
        task_entry = dlist_entry(pos, struct task_adaptor_info, task_node);
        if (task_entry->send_ta_create_msg_to_task != NULL &&
            task_entry->task_id != INVALID_TASK_ID &&
            memcmp(uuid, &(task_entry->uuid), sizeof(*uuid)) != 0)
            task_entry->send_ta_create_msg_to_task(task_entry->task_name, &msg, task_entry->task_id);
    }
}

void task_adapt_send_ta_release_msg(const struct reg_ta_info *msg, uint32_t dest_task_id)
{
    if (msg == NULL) {
        tloge("msg is null, send ta release msg failed\n");
        return;
    }

    uint32_t ret = ipc_msg_snd(TEE_TASK_RELEASE_TA_SERVICE, dest_task_id, msg, sizeof(*msg));
    if (ret != SRE_OK)
        tloge("send ta release msg to task 0x%x failed\n", dest_task_id);
}

void task_adapt_ta_release(const TEE_UUID *uuid)
{
    struct reg_ta_info msg;
    struct dlist_node *pos               = NULL;
    struct task_adaptor_info *task_entry = NULL;

    if (uuid == NULL) {
        tloge("uuid is null, task adapt proc ta release failed\n");
        return;
    }

    errno_t ret = memset_s(&msg, sizeof(msg), 0, sizeof(msg));
    if (ret != EOK) {
        tloge("memset task reg ta info failed\n");
        return;
    }

    ret = memcpy_s(&msg.uuid, sizeof(msg.uuid), uuid, sizeof(*uuid));
    if (ret != EOK) {
        tloge("memcpy uuid failed\n");
        return;
    }

    dlist_for_each(pos, &g_task_list_head) {
        task_entry = dlist_entry(pos, struct task_adaptor_info, task_node);
        if (task_entry->send_ta_release_msg_to_task != NULL &&
            task_entry->task_id != INVALID_TASK_ID &&
            memcmp(uuid, &(task_entry->uuid), sizeof(*uuid)) != 0)
            task_entry->send_ta_release_msg_to_task(task_entry->task_name, &msg, task_entry->task_id);
    }
}

struct task_adaptor_info *register_task_proc(const TEE_UUID *uuid, uint16_t task_prio,
    const char *task_name, const task_init_priv_info_f task_init_priv_info,
    const struct srv_adaptor_config_t *srv_config)
{
    uint32_t task_id;

    if (uuid == NULL || task_name == NULL || task_init_priv_info == NULL) {
        tloge("input param is invalid\n");
        return NULL;
    }

    struct task_adaptor_info *task = add_task_to_list(uuid, task_name, srv_config);
    if (task == NULL) {
        tloge("add task to list failed\n");
        return NULL;
    }

    if (start_internal_task(uuid, task_prio, task_name, &task_id) != TEE_SUCCESS) {
        tloge("Failed to start task\n");
        del_task_from_list(uuid);
        return NULL;
    }

    task->task_id = task_id;
    task_init_priv_info(task);
    return task;
}

void task_adapt_init(void)
{
    dlist_init(&g_task_list_head);

    /* there is no need to process return value here */
    register_multi_task();
    (void)register_task_ssa();
#if defined(CONFIG_APP_TEE_PERM) || defined(CONFIG_APP_TEE_PERM_A32)
    register_task_perm_serv();
#endif
    (void)register_task_se_srv();
#if (defined CONFIG_APP_TEE_TEST_SERVICE || defined CONFIG_APP_TEE_TEST_SERVICE_A64)
    (void)register_task_test_srv();
#endif
}

/* -----------------------------------------for agent task------------------------------------------ */
bool is_service_agent_request(uint32_t agent_task_id, uint32_t *caller_task_id, uint32_t **agent_status)
{
    struct task_adaptor_info *task = NULL;

    if (caller_task_id == NULL || agent_status == NULL) {
        tloge("in param is null, agent request check failed\n");
        return false;
    }

    task = find_task_by_taskid(agent_task_id);
    if (task == NULL)
        return false;

    if (task->is_agent) {
        *caller_task_id = task->caller_info.taskid;
        *agent_status   = &task->agent_status;
        return true;
    }
    return false;
}

bool is_agent_response(uint32_t agent_id, uint32_t *agent_task_id, uint32_t *caller_task_id,
                       uint32_t **agent_status)
{
    struct dlist_node *pos               = NULL;
    struct task_adaptor_info *task_entry = NULL;

    if (agent_task_id == NULL || caller_task_id == NULL || agent_status == NULL) {
        tloge("in param is null, agent response check failed\n");
        return false;
    }

    dlist_for_each(pos, &g_task_list_head) {
        task_entry = dlist_entry(pos, struct task_adaptor_info, task_node);
        if (task_entry->agent_id == agent_id && task_entry->is_agent) {
            *caller_task_id = task_entry->caller_info.taskid;
            *agent_task_id  = task_entry->task_id;
            *agent_status   = &task_entry->agent_status;
            return true;
        }
    }
    return false;
}

/* for system agent buffer, we only allow system agent task to access */
bool check_system_agent_permission(uint32_t task_id, uint32_t agent_id)
{
    struct dlist_node *pos               = NULL;
    struct task_adaptor_info *task_entry = NULL;

    dlist_for_each(pos, &g_task_list_head) {
        task_entry = dlist_entry(pos, struct task_adaptor_info, task_node);
        if (task_entry->is_agent) {
            if ((agent_id == task_entry->agent_id) && (task_id != task_entry->task_id))
                return false;
        }
    }
    return true;
}

/*
 * gtask will send agent buffer to ssa when receive register ssa agent msg.
 * so only ssa need this interface
 */
void task_adapt_register_agent(uint32_t agent_id)
{
    struct dlist_node *pos               = NULL;
    struct task_adaptor_info *task_entry = NULL;

    dlist_for_each(pos, &g_task_list_head) {
        task_entry = dlist_entry(pos, struct task_adaptor_info, task_node);
        if (task_entry->is_agent && task_entry->agent_id == agent_id) {
            if (task_entry->register_agent_buffer_to_task != NULL && task_entry->task_id != INVALID_TASK_ID)
                task_entry->register_agent_buffer_to_task(agent_id, task_entry->task_id);
            return;
        }
    }
}

void fs_agent_late_init(void)
{
    tee_ext_load_file();
    task_ssa_load_manage_info();
}
