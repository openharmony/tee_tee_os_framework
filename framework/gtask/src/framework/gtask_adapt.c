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
#include "gtask_adapt.h"
#include <mem_ops.h>
#include <ipclib_hal.h>
#include "securec.h"
#include "init.h"
#include "tee_inner_uuid.h"
#include "service_manager.h"

int get_ta_info(uint32_t task_id, bool *ta_64bit, TEE_UUID *uuid)
{
    struct session_struct *sess = NULL;
    struct service_struct *serv = NULL;
    TEE_UUID gtask_uuid = TEE_SERVICE_GLOBAL;

    if (task_id == 0) {
        /* gtask */
        if (ta_64bit != NULL)
#ifdef __aarch64__
            *ta_64bit = true;
#else
            *ta_64bit = false;
#endif
        if (uuid != NULL)
            *uuid = gtask_uuid;
        return 0;
    }

    if (!find_task(task_id, &serv, &sess)) {
        tloge("cannot find task_id:%u\n", task_id);
        return -1;
    }

    if (uuid != NULL)
        *uuid = serv->property.uuid;

    if (ta_64bit != NULL) {
        if (serv->ta_64bit) {
            *ta_64bit = true; /* TA is 64 bit */
        } else {
            *ta_64bit = false; /* TA is 32 bit */
        }
    }

    if (ta_64bit != NULL)
        tlogd("taskid:%d name:%s 64bit:%d\n", task_id, serv->name, *ta_64bit);

    return 0;
}

static uint32_t ta_to_global_msg_len(bool ta_is_64)
{
    if (ta_is_64) {
        return sizeof(struct ta_to_global_msg_64);
    } else {
        return sizeof(struct ta_to_global_msg_32);
    }
}

static int convert_ta2gtask_msg_handle(const uint8_t *msg_buf, bool ta_is_64, ta_to_global_msg *msg)
{
    const struct ta_to_global_msg_32 *msg_32 = NULL;

    if (!ta_is_64) {
        /* TA is 32 bit */
        msg_32                 = (const struct ta_to_global_msg_32 *)(uintptr_t)msg_buf;
        msg->ret               = msg_32->ret;
        msg->agent_id          = msg_32->agent_id;
        msg->session_context   = (uint64_t)(msg_32->session_context);
        msg->ta2ta_from_taskid = msg_32->ta2ta_from_taskid;
    } else {
        /* TA is 64 bit */
        errno_t rc = memcpy_s(msg, sizeof(*msg), msg_buf, sizeof(struct ta_to_global_msg_64));
        if (rc != EOK) {
            tloge("[error]memcpy_s failed, rc=%d, line:%d.\n", rc, __LINE__);
            return -1;
        }
    }

    return 0;
}

/* struct ta_to_global_msg */
int convert_ta2gtask_msg(const uint8_t *msg_buf, uint32_t msg_size, uint32_t taskid, ta_to_global_msg *msg)
{
    bool ta_is_64 = false;
    uint32_t ta_msg_size;

    if ((msg_buf == NULL) || (msg == NULL)) {
        tloge("msg buf is invalid\n");
        return -1;
    }

    if (get_ta_info(taskid, &ta_is_64, NULL) != 0) {
        tloge("get ta type failed\n");
        return -1;
    }

    ta_msg_size = ta_to_global_msg_len(ta_is_64);
    if (msg_size < ta_msg_size) {
        tloge("invalid msg size.\n");
        return -1;
    }

    return convert_ta2gtask_msg_handle(msg_buf, ta_is_64, msg);
}

/* struct global_to_ta_msg */
static uint32_t send_global2ta_msg_handle(const global_to_ta_msg *msg, bool ta_is_64, uint32_t cmd, uint32_t taskid)
{
    if (!ta_is_64) {
        /* TA is 32 bit */
        struct global_to_ta_msg_32 msg_32 = { 0 };

        msg_32.ret             = msg->ret;
        msg_32.session_id      = msg->session_id;
        msg_32.session_type    = msg->session_type;
        msg_32.cmd_id          = msg->cmd_id;
        msg_32.param_type      = msg->param_type;
        msg_32.params          = (uint32_t)msg->params;
        msg_32.session_context = (uint32_t)msg->session_context;
        msg_32.dev_id          = msg->dev_id;
        msg_32.first_session   = msg->first_session;
        msg_32.last_session    = msg->last_session;
        msg_32.started         = msg->started;
        msg_32.stack_size      = msg->stack_size;
        return ipc_msg_snd(cmd, taskid, &msg_32, sizeof(msg_32));
    }

    /* TA is 64 bit */
    return ipc_msg_snd(cmd, taskid, msg, sizeof(*msg));
}

/* struct global_to_ta_msg */
TEE_Result send_global2ta_msg(const global_to_ta_msg *msg, uint32_t cmd, uint32_t taskid, const bool *ta_64bit)
{
    bool ta_is_64 = false;

    if (msg == NULL) {
        tloge("msg is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (ta_64bit == NULL) {
        if (get_ta_info(taskid, &ta_is_64, NULL) != 0) {
            tloge("get ta type failed\n");
            return TEE_ERROR_GENERIC;
        }
    } else {
        /* send to service_thread which not add to session list */
        ta_is_64 = *ta_64bit;
    }

    uint32_t ret = send_global2ta_msg_handle(msg, ta_is_64, cmd, taskid);
    if (ret != SRE_OK) {
        tloge("send global to ta msg failed, ta taskid is 0x%x\n", taskid);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

TEE_Result send_ta_init_msg(const ta_init_msg *msg, bool ta_is_64, uint32_t cmd, uint32_t taskid)
{
    uint32_t ret;

    if (msg == NULL) {
        tloge("msg is invalid\n");
        return TEE_ERROR_GENERIC;
    }

    if (!ta_is_64) {
        /* TA is 32 bit */
        struct ta_init_msg_32 msg_32 = { 0 };

        msg_32.fs_mem               = (uint32_t)msg->fs_mem;
        msg_32.misc_mem             = (uint32_t)msg->misc_mem;
        msg_32.prop.uuid            = msg->prop.uuid;
        msg_32.prop.stack_size      = msg->prop.stack_size;
        msg_32.prop.heap_size       = msg->prop.heap_size;
        msg_32.prop.single_instance = msg->prop.single_instance;
        msg_32.prop.multi_session   = msg->prop.multi_session;
        msg_32.prop.keep_alive      = msg->prop.keep_alive;
        msg_32.prop.ssa_enum_enable = msg->prop.ssa_enum_enable;
        msg_32.prop.other_buff      = (uint32_t)msg->prop.other_buff;
        msg_32.prop.other_len       = msg->prop.other_len;
        msg_32.login_method         = msg->login_method;
        msg_32.time_data            = (uint32_t)msg->time_data;
        msg_32.sys_time             = msg->sys_time;
        msg_32.rtc_time             = msg->rtc_time;

        ret = ipc_msg_snd(cmd, taskid, &msg_32, sizeof(msg_32));
    } else {
        /* TA is 64 bit */
        ret = ipc_msg_snd(cmd, taskid, msg, sizeof(*msg));
    }
    if (ret != SRE_OK) {
        tloge("send init msg to ta failed, task id is 0x%x\n", taskid);
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

uint32_t get_tee_param_len(bool ta_is_64)
{
    if (ta_is_64) {
        return sizeof(tee_param_64);
    } else {
        return sizeof(tee_param_32);
    }
}

TEE_Result alloc_tee_param_for_ta(uint32_t taskid, struct pam_node *node)
{
    bool ta_is_64 = false;
    TEE_UUID ta_uuid = {0};

    if (node == NULL) {
        tloge("invalid node\n");
        return TEE_ERROR_GENERIC;
    }

    if (get_ta_info(taskid, &ta_is_64, &ta_uuid) != 0) {
        tloge("get ta type failed, taskid:%u\n", taskid);
        return TEE_ERROR_GENERIC;
    }

    /* separate TEE_Param mem for ta */
    void *p_for_ta = (void *)alloc_sharemem_aux(&ta_uuid, (get_tee_param_len(ta_is_64) * TEE_PARAM_NUM));
    if (p_for_ta == NULL) {
        tloge("p_for_ta alloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    node->p_for_ta   = p_for_ta;
    node->param_type = ta_is_64;

    return TEE_SUCCESS;
}
