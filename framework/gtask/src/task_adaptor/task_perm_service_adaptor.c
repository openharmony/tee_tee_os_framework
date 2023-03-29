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

#include "task_perm_service_adaptor.h"
#include "task_adaptor.h"
#include "permsrv_api.h"
#include "ta_framework.h"
#include "gtask_inner.h"
#include "tee_app_load_srv.h"

#define TASK_PRIO_PERM_SERVICE (DEFAULT_TASK_PRIO - 2)
void register_task_perm_serv(void);

static void register_ta_to_perm_serv(const struct reg_ta_info *reg_msg, uint32_t perm_task_id)
{
    (void)perm_task_id;
    tee_ext_register_ta(&(reg_msg->uuid), reg_msg->taskid, reg_msg->userid);
}

static void unregister_ta_to_perm_serv(const char *cur_task_name, const struct reg_ta_info *reg_msg,
    uint32_t perm_task_id)
{
    (void)perm_task_id;
    (void)cur_task_name;
    tee_ext_unregister_ta(&(reg_msg->uuid), reg_msg->taskid, reg_msg->userid);
}

static void send_ta_release_msg_to_perm_serv(const char *cur_task_name, const struct reg_ta_info *msg,
    uint32_t perm_task_id)
{
    (void)cur_task_name;
    (void)perm_task_id;
    tee_ext_notify_unload_ta(&(msg->uuid));
}

static void task_perm_serv_crash_callback(const TEE_UUID *uuid, const char *task_name,
    const struct srv_adaptor_config_t *config)
{
    (void)uuid;
    (void)task_name;
    (void)config;
    elf_verify_crash_callback();
    register_task_perm_serv();
}

static void task_perm_serv_init_priv_info(struct task_adaptor_info *task)
{
    task->task_crash_callback   = task_perm_serv_crash_callback;
    task->register_ta_to_task   = register_ta_to_perm_serv;
    task->unregister_ta_to_task = unregister_ta_to_perm_serv;
    task->send_ta_release_msg_to_task = send_ta_release_msg_to_perm_serv;
}

/* perm service is enabled by default */
void register_task_perm_serv(void)
{
    TEE_UUID uuid = TEE_SERVICE_PERM;

    struct task_adaptor_info *task =
        register_task_proc(&uuid, TASK_PRIO_PERM_SERVICE, PERM_SERVICE_NAME, task_perm_serv_init_priv_info, NULL);
    if (task == NULL)
        tlogd("jump to reg task perm serv\n");
}
