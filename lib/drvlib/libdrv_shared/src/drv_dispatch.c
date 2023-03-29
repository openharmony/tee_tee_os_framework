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
#include "drv_dispatch.h"
#include <stdint.h>
#include <inttypes.h>
#include <pthread.h>
#include <securec.h>
#include <spawn_ext.h>
#include <ipclib.h>
#include <tee_log.h>
#include <drv.h>
#include <tee_drv_internal.h>
#include "tee_driver_module.h"
#include "drv_thread.h"
#include "drv_operations.h"
#include "tee_drv_entry.h"
#include <unistd.h>

static int32_t get_drv_params(struct tee_drv_param *params, const struct drv_req_msg_t *msg,
                              const struct hmcap_message_info *info)
{
    if (msg == NULL || info == NULL) {
        tloge("invalid parameters\n");
        return -1;
    }

    uint32_t cnode_idx = info->src_cnode_idx;
    if ((cnode_idx == 0) || (info->msg_size < sizeof(struct drv_req_msg_t))) {
        tloge("invalid cnode or invalid msg size\n");
        return -1;
    }

    /* params uuid will set in open/ioctl/close function */
    params->args = (uintptr_t)msg->args;
    params->data = (uintptr_t)msg->data;
    params->caller_pid = pid_to_taskid(TCBCREF2TID(info->src_tcb_cref), info->src_cred.pid);

    return 0;
}

static int64_t driver_open_func(const struct tee_drv_param *params)
{
    char *indata = (char *)(uintptr_t)params->data;
    if (indata == NULL) {
        tloge("invalid input buffer\n");
        return -1;
    }

    taskid_t drv_mgr_pid = get_drv_mgr_pid();
    if (taskid_to_pid(drv_mgr_pid) != (taskid_to_pid(params->caller_pid))) {
        tloge("caller pid:0x%x cannot call open\n", params->caller_pid);
        return -1;
    }

    const struct tee_driver_module *drv_func = get_drv_func();

    /* open fd and call open_fn */
    int64_t fd = driver_open(params, drv_func);
    if (fd <= 0)
        tloge("drv open fd failed ret:0x%llx\n", fd);

    return fd;
}

static int64_t driver_close_func(const struct tee_drv_param *params)
{
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    taskid_t drv_mgr_pid = get_drv_mgr_pid();
    if (taskid_to_pid(drv_mgr_pid) != (taskid_to_pid(params->caller_pid))) {
        tloge("caller pid:0x%x cannot call close\n", params->caller_pid);
        return -1;
    }

    return driver_close(args[DRV_CLOSE_FD_INDEX], params);
}

static int32_t driver_general_handle(struct tee_drv_param *params, int64_t *ret_val)
{
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("args is invalid\n");
        return -1;
    }

    uint64_t drv_cmd = args[DRV_FRAM_CMD_INDEX];
    int64_t ret;
    int64_t fn_ret = 0;

    if (drv_cmd == CALL_DRV_OPEN) {
        ret = driver_open_func(params);
    } else if (drv_cmd == CALL_DRV_IOCTL) {
        ret = driver_ioctl(args[DRV_IOCTL_FD_INDEX], params, get_drv_func(), &fn_ret);
    } else if (drv_cmd == CALL_DRV_CLOSE) {
        ret = driver_close_func(params);
    } else {
        printf("drv_cmd:%" PRIx64 " not support\n", drv_cmd);
        return -1;
    }

    if (ret == 0)
        *ret_val = fn_ret;
    else
        *ret_val = ret;

    return 0;
}

#ifdef TEE_SUPPORT_DRV_FD_DUMP
static int32_t driver_dump_handle(int64_t *ret_val, const struct tee_drv_param *params)
{
    taskid_t drv_mgr_pid = get_drv_mgr_pid();
    if (taskid_to_pid(drv_mgr_pid) != (taskid_to_pid(params->caller_pid))) {
        tloge("this task not support dump fd\n");
        return -1;
    }

    tloge("========= driver dump begin ===========\n");
    driver_dump();
    tloge("========= driver dump end ===========\n");

    *ret_val = 0;
    return 0;
}
#endif

static int32_t driver_syscall_dispatch(int32_t swi_id, struct tee_drv_param *params, int64_t *ret_val)
{
    int32_t ret = -1;

    switch (swi_id) {
    case DRV_GENERAL_CMD_ID:
        ret = driver_general_handle(params, ret_val);
        break;
#ifdef TEE_SUPPORT_DRV_FD_DUMP
    case DRV_DUMP_CMD_ID:
        ret = driver_dump_handle(ret_val, params);
        break;
#endif
    case REGISTER_DRV_CMD_PERM:
        ret = driver_register_cmd_perm(params, ret_val);
        break;
    default:
        tloge("swi_id:0x%x cannot handle\n", swi_id);
    }

    return ret;
}

static int32_t driver_syscall(const struct drv_req_msg_t *msg, const struct hmcap_message_info *info,
                              struct tee_drv_param *params, int32_t swi_id, int64_t *ret_val)
{
    int32_t ret;
    tid_t tid;

    ret = get_drv_params(params, msg, info);
    if (ret != 0) {
        tloge("get driver parameters failed\n");
        return -1;
    }

    tid = gettid();
    if (tid < 0) {
        tloge("failed to get tid\n");
        return -1;
    }

    update_callerpid_by_tid(tid, params->caller_pid);
    ret = driver_syscall_dispatch(swi_id, params, ret_val);
    update_callerpid_by_tid(tid, INVALID_CALLER_PID);
    if (ret != 0)
        tloge("handle swi 0x%x failed\n", swi_id);

    return ret;
}

static void driver_reply_error_handle(int32_t swi_id, const struct tee_drv_param *params, int64_t ret_val)
{
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("args is invalid\n");
        return;
    }

    if (!((swi_id == DRV_GENERAL_CMD_ID) && (args[DRV_FRAM_CMD_INDEX] == CALL_DRV_OPEN)))
        return;

    if (ret_val <= 0)
        return;

    tloge("drv open reply failed, call drv close fd:%"PRIx64"\n", ret_val);
    uint32_t drv_index = get_drv_index();
    int64_t close_ret = driver_close((((uint64_t)drv_index << DRV_INDEX_OFFSET) | (uint64_t)ret_val), params);
    if (close_ret != 0)
        tloge("close fd:%" PRIx64 " failed in reply error handle\n", ret_val);
}

static int32_t driver_handle_message(const struct drv_req_msg_t *msg, const struct hmcap_message_info *info,
                                     struct drv_reply_msg_t *rmsg, const cref_t *msg_hdl)
{
    int64_t ret_val = -1;
    int32_t ret;
    struct tee_drv_param params = { 0 };
    int32_t swi_id = msg->header.send.msg_id;

    ret = driver_syscall(msg, info, &params, swi_id, &ret_val);
    if (ret != 0)
        tloge("handle driver syscall failed ret:0x%x\n", ret);

    rmsg->header.reply.ret_val = (ret == 0) ? ret_val : (int64_t)ret;
    ret = ipc_msg_reply(*msg_hdl, rmsg, sizeof(struct drv_reply_msg_t));
    if (ret != 0) {
        tloge("ipc msg reply failed\n");
        /*
         * should clear system resource information alloced by this cmd when reply failed,
         * otherwise it will cause memory leak
         */
        driver_reply_error_handle(swi_id, &params, ret_val);
    }

    return ret;
}

intptr_t driver_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info)
{
    struct drv_reply_msg_t reply_raw_buf;
    int32_t ret;

    if ((p_msg_hdl == NULL) || (info == NULL) || (msg == NULL)) {
        tloge("invalid dispatch param\n");
        return -1;
    }

    (void)memset_s(&reply_raw_buf, sizeof(reply_raw_buf), 0, sizeof(reply_raw_buf));

    ret = driver_handle_message((struct drv_req_msg_t *)msg, info,
        &reply_raw_buf, p_msg_hdl);
    if (ret != 0)
        tloge("driver handle message failed\n");

    return ret;
}
