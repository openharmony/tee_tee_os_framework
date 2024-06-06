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

#include "tee_dynamic_srv.h"
#include <sys/mman.h>
#include <mem_ops.h>
#include <spawn_ext.h>
#include <sys/time.h>
#include "timer_export.h"
#include <pthread.h>
#include "tee_init.h"
#include "tee_mem_mgmt_api.h"
#include "tee_log.h"
#include "securec.h"
#include "ipclib.h"
#include "tee_internal_task_pub.h"
#include "sys_timer.h"
#include "lib_timer.h"
#include <ipclib_hal.h>
#include "tee_msg_type.h"

TEE_Result tee_srv_get_uuid_by_sender(uint32_t sender, TEE_UUID *uuid)
{
#ifdef CONFIG_TEE_DYN_SRV_STUB
    (void)sender;
    (void)uuid;
    return TEE_ERROR_NOT_SUPPORTED;
#else
    spawn_uuid_t sender_uuid;

    if (uuid == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    int32_t ret = getuuid((pid_t)taskid_to_pid(sender), &sender_uuid);
    if (ret != 0) {
        tloge("get uuid failed, sender is 0x%x\n", sender);
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    errno_t rc = memcpy_s(uuid, sizeof(*uuid), &sender_uuid.uuid, sizeof(sender_uuid.uuid));
    if (rc != EOK) {
        tloge("copy uuid to dest failed, rc=%d\n", rc);
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
#endif
}

int tee_srv_map_from_task(uint32_t in_task_id, uint32_t va_addr, uint32_t size, uint32_t *virt_addr)
{
#ifdef CONFIG_TEE_DYN_SRV_STUB
    (void)in_task_id;
    (void)va_addr;
    (void)size;
    (void)virt_addr;
    return TEE_ERROR_NOT_SUPPORTED;
#else
    uint64_t vaddr = 0;
    int ret;

    if (virt_addr == NULL)
        return -1;

    ret = map_sharemem(in_task_id, va_addr, size, &vaddr);
    if (ret == 0)
        *virt_addr = (uint32_t)vaddr;
    else
        *virt_addr = 0;

    return ret;
#endif
}

void tee_srv_unmap_from_task(uint32_t va_addr, uint32_t size)
{
#ifdef CONFIG_TEE_DYN_SRV_STUB
    (void)va_addr;
    (void)size;
#else
    (void)munmap((void *)(uintptr_t)va_addr, size);
#endif
}

#ifndef CONFIG_TEE_DYN_SRV_STUB
/* msg can be null, which means we do not care return msg */
static void tee_task_entry_wait_msg(uint32_t want_cmd, uint8_t *msg, uint32_t size, uint32_t want_sdr)
{
    uint32_t recv_cmd;
    uint32_t sender;
    uint32_t cp_size;
    uint8_t ret_msg[sizeof(tee_service_ipc_msg)];

    while (1) {
        recv_cmd = 0;
        sender = 0;
        (void)memset_s(ret_msg, sizeof(ret_msg), 0, sizeof(ret_msg));

        uint32_t ret = (uint32_t)ipc_msg_rcv_a(OS_WAIT_FOREVER, (uint32_t *)(&recv_cmd),
                                               ret_msg, sizeof(ret_msg), &sender);
        if (ret != SRE_OK) {
            tloge("msg rcv error %x\n", ret);
            continue;
        }

        if (recv_cmd == want_cmd && sender == want_sdr) {
            cp_size = (size < sizeof(ret_msg)) ? size : sizeof(ret_msg);
            errno_t rc = memmove_s(msg, size, ret_msg, cp_size);
            if (rc != EOK)
                tloge("copy msg, size %u error, ret %x\n", cp_size, rc);
            break;
        }
        tloge("receive unexpected msg 0x%x from 0x%x\n", recv_cmd, sender);
    }
}

static TEE_Result set_service_caller_info(uint32_t task_id, uint32_t cmd)
{
    uint32_t ret;
    struct task_caller_info caller_serv_info;

    caller_serv_info.taskid = task_id;
    caller_serv_info.cmd = cmd;
    ret = ipc_msg_snd(TEE_TASK_SET_CALLER_INFO, get_global_handle(), &caller_serv_info, sizeof(caller_serv_info));
    if (ret != SRE_OK) {
        tloge("send caller info failed 0x%x\n", ret);
        return TEE_ERROR_COMMUNICATION;
    }

    tee_task_entry_wait_msg(TEE_TASK_SET_CALLER_INFO_ACK, (uint8_t *)&ret, sizeof(ret), get_global_handle());
    if (ret != TEE_SUCCESS) {
        tloge("set callerinfo fail, recv_ret:0x%x", ret);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static void do_deal_with_msg(const struct srv_dispatch_t *dispatch, uint32_t n_dispatch,
    struct tee_service_ipc_msg_req *req_msg, tee_service_ipc_msg_rsp *rsp_msg, uint32_t task_id)
{
    tlogd("receive cmd:%d, n_dispatch:%d", req_msg->cmd, n_dispatch);

    for (uint32_t i = 0; i < n_dispatch; i++) {
        if (dispatch[i].cmd == req_msg->cmd) {
            dispatch[i].fn(&(req_msg->msg), task_id, rsp_msg);
            return;
        }
    }

    rsp_msg->ret = TEE_ERROR_BAD_PARAMETERS;
}

static void tee_srv_dispatch(const char *task_name, const struct srv_dispatch_t *dispatch, uint32_t n_dispatch)
{
    cref_t msghdl;
    uint32_t task_id;
    cref_t ch;
    struct tee_service_ipc_msg_req req_msg = {0};
    tee_service_ipc_msg_rsp rsp_msg;
    struct src_msginfo info = { 0 };

    msghdl = ipc_msg_create_hdl();
    if (!check_ref_valid(msghdl)) {
        tloge("create msg hdl failed\n");
        return;
    }

    int32_t ret = ipc_create_channel_native(task_name, &ch);
    if (ret != 0) {
        tloge("create ipc channel failed, ret=%d\n", ret);
    }

    while (1) {
        ret = ipc_msg_receive(ch, &req_msg, (unsigned long)sizeof(req_msg), msghdl, &info, -1);
        if (ret < 0) {
            tloge("message receive failed, ret=0x%x\n", ret);
            continue;
        }

        task_id = (uint32_t)pid_to_taskid(info.src_tid, info.src_pid);
        if (info.src_pid != get_global_handle()) {
            if (set_service_caller_info(task_id, req_msg.cmd) != TEE_SUCCESS)
                tloge("failed to set caller info, task id 0x%x, cmd 0x%x\n", task_id, req_msg.cmd);
        }

        do_deal_with_msg(dispatch, n_dispatch, &req_msg, &rsp_msg, task_id);

        if (info.msg_type == MSG_TYPE_CALL) {
            ret = ipc_msg_reply(msghdl, &rsp_msg, sizeof(rsp_msg));
            if (ret != 0) {
                tloge("message reply failed, ret=0x%x\n", ret, ret);
                continue;
            }
        }
    }
}
#endif

void tee_srv_cs_server_loop(const char *task_name, const struct srv_dispatch_t *dispatch, uint32_t n_dispatch,
    struct srv_thread_init_info *cur_thread)
{
    (void)cur_thread;
#ifdef CONFIG_TEE_DYN_SRV_STUB
    (void)task_name;
    (void)dispatch;
    (void)n_dispatch;
    (void)cur_thread;
#else
    if (task_name == NULL || dispatch == NULL || n_dispatch == 0) {
        tloge("param invalid\n");
        return;
    }

    tlogi("------------------enter to %s srv_cs_server_loop------------------\n", task_name);

    tee_srv_dispatch(task_name, dispatch, n_dispatch);
#endif
}
