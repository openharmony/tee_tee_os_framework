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
#include <ipclib.h>
#include <tee_log.h>
#include <ta_framework.h>
#include <drv.h>
#include <tee_drv_internal.h>
#include <tee_drv_errno.h>
#include <target_type.h>
#include <ta_lib_img_unpack.h>
#include "tee_driver_module.h"
#include "drv_thread.h"
#include "drv_fd_ops.h"
#include "drv_ipc_mgr.h"
#include "drv_auth.h"
#include "drv_dyn_conf_mgr.h"
#include "drvcall_dyn_conf_mgr.h"
#include "drv_process_mgr.h"
#include "task_mgr.h"
#include "base_drv_node.h"
#include <ipclib_hal.h>
#include <spawn_ext.h>
#include <unistd.h>

static int32_t get_drv_params(struct tee_drv_param *params, const struct drv_req_msg_t *msg,
                              const struct cap_message_info *info)
{
    spawn_uuid_t uuid;
    int32_t ret;
    if (msg == NULL || info == NULL) {
        tloge("invalid parameters\n");
        return -1;
    }

    uint32_t cnode_idx = info->src_cnode_idx;
    if ((cnode_idx == 0) || (info->msg_size < sizeof(struct drv_req_msg_t))) {
        tloge("invalid cnode or invalid msg size\n");
        return -1;
    }

    ret = getuuid(info->src_cred.pid, &uuid);
    if (ret != 0) {
        tloge("get pid:%u uuid failed\n", info->src_cred.pid);
        return -1;
    }

    ret = memcpy_s(&(params->uuid), sizeof(params->uuid), &uuid.uuid, sizeof(uuid.uuid));
    if (ret != 0) {
        tloge("copy pid:%u uuid:0x%x to params failed\n", info->src_cred.pid, uuid.uuid.timeLow);
        return -1;
    }

    params->args = (uintptr_t)msg->args;
    params->data = (uintptr_t)msg->data;
    params->caller_pid = pid_to_taskid(TCBCREF2TID(info->src_tcb_cref), info->src_cred.pid);

    return 0;
}

static int32_t get_drv_name(const struct tee_drv_param *params, char *drv_name, uint32_t len)
{
    char *indata = (char *)(uintptr_t)params->data;
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    uint64_t name_len = args[DRV_NAME_LEN_INDEX];
    uint64_t drv_name_offset = args[DRV_NAME_INDEX];

    if (indata == NULL) {
        tloge("invalid input buffer\n");
        return -1;
    }

    if (name_len == 0 || name_len >= len) {
        tloge("drv name len %"PRIx64" is invalid\n", name_len);
        return -1;
    }

    if (drv_name_offset != args[DRV_PARAM_LEN_INDEX] ||
        (drv_name_offset > (SYSCAL_MSG_BUFFER_SIZE - sizeof(struct drv_req_msg_t))) ||
        (drv_name_offset + name_len > (SYSCAL_MSG_BUFFER_SIZE - sizeof(struct drv_req_msg_t)))) {
        tloge("drv name offset %"PRIx64" is invalid\n", args[DRV_NAME_INDEX]);
        return -1;
    }

    if (memcpy_s(drv_name, len, (indata + drv_name_offset), name_len) != EOK) {
        tloge("copy drv name failed\n");
        return -1;
    }

    drv_name[name_len] = '\0';

    return 0;
}

static bool is_drv_call_invalid(const struct task_node *call_node, const char *drv_name, uint32_t len)
{
    if (call_node->target_type != DRV_TARGET_TYPE)
        return false;

    if (call_node->tlv.drv_conf == NULL) {
        tloge("something wrong, drv conf is null\n");
        return true;
    }

    tlogd("this is drv:%s call other drv:%s\n", call_node->tlv.drv_conf->mani.service_name, drv_name);
    if ((len == call_node->tlv.drv_conf->mani.service_name_size) &&
        (strncmp(call_node->tlv.drv_conf->mani.service_name, drv_name, len + 1) == 0)) {
        tloge("drv:%s call yourself not support\n", drv_name);
        return true;
    }

    return false;
}

static struct task_node *alloc_drvcall_node_internal_drv(const struct tee_uuid *uuid, uint32_t taskid)
{
    struct drvcall_conf_t *tlv = malloc(sizeof(struct drvcall_conf_t));
    if (tlv == NULL) {
        tloge("malloc tlv node failed\n");
        return NULL;
    }
    (void)memset_s(tlv, sizeof(*tlv), 0, sizeof(*tlv));
    (void)memcpy_s(&(tlv->uuid), sizeof(tlv->uuid), uuid, sizeof(*uuid));

    tlv->drvcall_perm_apply.base_perm = true;
    struct task_node *node = alloc_and_init_ta_node(tlv);
    if (node == NULL) {
        free(tlv);
        tloge("create drvcall node fail\n ");
        return NULL;
    }

    node->pid = taskid_to_pid(taskid);
    if (receive_task_conf(node) != 0) {
        tloge("receive task conf fail\n");
        free(tlv);
        free_task_node(node);
        return NULL;
    }
    free(tlv);

    return node;
}

static struct task_node *get_valid_drvcall_node(const struct tee_uuid *uuid,
    uint32_t taskid, const char *drv_name, uint32_t len)
{
    bool base_drv_flag = get_base_drv_flag(drv_name, len);

    struct task_node *call_node = get_node_by_uuid_with_lock(uuid, taskid);
    if (call_node == NULL) {
        if (base_drv_flag) {
            call_node = alloc_drvcall_node_internal_drv(uuid, taskid);
        } else {
            tloge("cannot get caller node:0x%x taskid is 0x%x\n", uuid->timeLow, taskid);
            return NULL;
        }
    }

    if (is_drv_call_invalid(call_node, drv_name, len))
        goto put_drvcall;
    /* first check whether caller has the right to access this drv */
    if (!base_drv_flag) {
        if (!caller_open_auth_check(call_node, drv_name, len)) {
            tloge("caller:0x%x cannot access %s\n", uuid->timeLow, drv_name);
            goto put_drvcall;
        }
    }

    int32_t ret = get_fd_count(call_node);
    if (ret != 0) {
        tloge("caller:0x%x get fd count fail\n", uuid->timeLow);
        goto put_drvcall;
    }

    return call_node;

put_drvcall:
    put_node_with_lock(call_node, 1);
    return NULL;
}

#define ELF_APPEND_LEN 4 /* ".elf" */
static void unlink_drv_elf(const char *drv_name)
{
    char drv_elf[DRV_NAME_MAX_LEN + ELF_APPEND_LEN] = { 0 };

    int32_t ret = snprintf_s(drv_elf, sizeof(drv_elf), (sizeof(drv_elf) - 1), "%s%s",
        drv_name, ".elf");
    if (ret < 0) {
        tloge("set unlink drv:%s elf fail\n", drv_name);
        return;
    }

    uint32_t ipc_ret = ipc_msg_snd(TEE_UNLINK_DYNAMIC_DRV, GLOBAL_HANDLE, drv_elf, sizeof(drv_elf));
    if (ipc_ret != 0)
        tloge("send unlink drv:%s msg fail:0x%x", drv_name, ipc_ret);

    tlogd("unlink drv:%s succ\n", drv_elf);
}

static struct task_node *get_valid_drv_node(const struct tee_uuid *caller_uuid, const char *drv_name, uint32_t len)
{
    struct task_node *dnode = get_drv_node_by_name_with_lock(drv_name, len);
    if (dnode == NULL) {
        tloge("cannot find drv:%s\n", drv_name);
        return NULL;
    }

    if (!drv_mac_open_auth_check(dnode->tlv.drv_conf, caller_uuid)) {
        tloge("drv:%s mac check fail 0x%x", drv_name, caller_uuid->timeLow);
        goto put_drv;
    }

    int32_t ret = check_drv_node_state(dnode);
    if (ret == DRV_NEED_SPAWN) {
        /* spawn process */
        tlogd("SPAWN drv:%s begin\n", drv_name);
        ret = spawn_driver_handle(dnode);
        if (ret != 0) {
            tloge("spawn drv:%s fail\n", drv_name);
            broadcast_drv_state(dnode, false);
        } else {
            tlogd("spawn drv:%s succ and broadcast\n", drv_name);
            broadcast_drv_state(dnode, true);
            unlink_drv_elf(drv_name);
            return dnode;
        }
    } else if (ret == DRV_SUCC) {
        tlogd("drv:%s has spawn succ\n", drv_name);
        return dnode;
    }

    tloge("cannot find drv:%s spawn node\n", drv_name);

put_drv:
    put_node_with_lock(dnode, 1);
    return NULL;
}

static int64_t driver_open_func(const struct tee_drv_param *params)
{
    char drv_name[DRV_NAME_MAX_LEN] = { 0 };
    if (get_drv_name(params, drv_name, sizeof(drv_name)) != 0)
        return -1;

    struct task_node *call_node = get_valid_drvcall_node(&params->uuid, params->caller_pid, drv_name, strlen(drv_name));
    if (call_node == NULL)
        return -1;

    struct fd_node *data = alloc_and_init_fd_node();
    if (data == NULL)
        goto put_drvcall;

    struct task_node *dnode = get_valid_drv_node(&params->uuid, drv_name, strlen(drv_name));
    if (dnode == NULL)
        goto free_fd;

    /*
     * get drvcall cmd permission, and send to driver process
     * it will be used in ioctl function to check whether drvcaller has special cmd permission
     */
    uint64_t caller_perm;
    bool base_drv_flag = get_base_drv_flag(drv_name, strlen(drv_name));
    if (base_drv_flag) {
        caller_perm = 0;
    } else {
        int32_t ret = get_drvcaller_cmd_perm(call_node, dnode, &caller_perm);
        if (ret != 0) {
            tloge("get caller:0x%x drv:%s cmd perm fail\n", params->uuid.timeLow, drv_name);
            goto put_drv;
        }
    }
    int64_t fd = drv_open_handle(params, dnode, caller_perm);
    if (fd <= 0) {
        tloge("drv:%s open fd fail:0x%llx\n", drv_name, fd);
        goto put_drv;
    }

    data->fd = fd;
    data->drv = dnode;

    if (add_fd_to_drvcall_node(data, call_node) != 0) {
        tloge("add fd fail\n");
        goto close_fd;
    }

    tlogd("caller:0x%x open drv:%s fd:0x%llx end\n", params->uuid.timeLow, drv_name, fd);

    return fd;

close_fd:
    if (call_drv_close(call_node->pid, &params->uuid, fd, dnode->drv_task.channel) != 0)
        tloge("call drv:%s close fd:0x%llx fail\n", drv_name, fd);

put_drv:
    put_node_with_lock(dnode, 1);

free_fd:
    free(data);

put_drvcall:
    put_fd_count(call_node);
    put_node_with_lock(call_node, 1);
    return -1;
}

static int64_t driver_close_func_ops(struct task_node *call_node, int64_t fd, struct fd_node **data)
{
    struct task_node *dnode = (*data)->drv;
    if (dnode == NULL) {
        tloge("something wrong, task:0x%x uuid:0x%x fd:0x%llx data has no drv\n",
            call_node->pid, call_node->tlv.uuid.timeLow, fd);
        del_fd_to_drvcall_node(data, call_node);
        return -1;
    }

    /*
     * must del fd in drvcall node before call drv_close
     * otherwise will cause fd data cannot close in this case:
     * two session of the same TA call the same drv,
     * session 0 in cpux close the fd1 and session 1 in cpuy open new fd
     * when drv free fd1 first, it may alloc fd1 to session 1 (session 0 close fd1, and session 1 open fd1 again)
     * if not del fd data of this task in drvmgr, it may cannot find valid fd1 (close_flag = false)
     * when session 1 close fd1 opened before since this task in drvmgr has two fd1,
     * one opened by session 0 has set close_flag, another opened by session 1 has not set close_flag,
     * session 1 close fd1 may find the session 0 opened since it just compare the fd1 value
     */
    del_fd_to_drvcall_node(data, call_node);

    int64_t ret = call_drv_close(call_node->pid, &call_node->tlv.uuid, fd, dnode->drv_task.channel);
    if (ret != 0)
        tloge("call drv close fd:0x%llx for task:0x%x fail ret:0x%x\n", fd, call_node->pid, ret);

    /* pair with dnode ref_cnt add one in open */
    put_node_with_lock(dnode, 1);

    return ret;
}

static int64_t driver_close_func(int64_t fd, const struct tee_drv_param *params)
{
    int64_t ret = DRV_GENERAL_ERR;

    tlogd("call drv fd:0x%llx close begin\n", fd);

    struct task_node *call_node = get_node_by_uuid_with_lock(&params->uuid, params->caller_pid);
    if (call_node == NULL) {
        tloge("cannot get call node pid:0x%x uuid:0x%x for fd:0x%llx\n",
            params->caller_pid, params->uuid.timeLow, fd);
        return ret;
    }

    struct fd_node *data = close_get_fd_node_with_lock(call_node, fd);
    if (data == NULL) {
        /*
         * two case:
         * 1. the caller has not open this fd
         * 2. this fd has been closed in exception handle
         */
        tloge("task:0x%x uuid:0x%x cannot find fd:0x%llx\n",
            params->caller_pid, params->uuid.timeLow, fd);
        put_node_with_lock(call_node, 1);
        return DRV_GENERAL_ERR;
    }

    ret = driver_close_func_ops(call_node, fd, &data);

    /*
     * one for get_drvcall_by_uuid_with_lock
     * one for pair with open
     */
    put_node_with_lock(call_node, DRVCALL_DEC_CNT_INCLUDE_REGISTER_ONE);

    tlogd("drv fd:0x%llx close ret:0x%llx\n", fd, ret);

    /*
     * In this case must dec channel ref_cnt in lib
     * because this fd can be find in drvmgr
     */
    if (ret != DRV_SUCCESS) {
        tloge("find fd:0x%llx but close fail\n", fd);
        return DRV_CLOSE_FD_FAIL;
    }

    return ret;
}

static int32_t driver_general_handle(const struct tee_drv_param *params, int64_t *ret_val)
{
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("args is invalid\n");
        return -1;
    }

    uint64_t drv_cmd = args[DRV_FRAM_CMD_INDEX];
    int64_t ret;

    if (drv_cmd == CALL_DRV_OPEN) {
        ret = driver_open_func(params);
    } else if (drv_cmd == CALL_DRV_CLOSE) {
        ret = driver_close_func(args[DRV_CLOSE_FD_INDEX], params);
    } else {
        tloge("drv cmd:%" PRIx64 " not support\n", drv_cmd);
        return -1;
    }

    *ret_val = ret;

    return 0;
}

#define EXIT_PID_INDEX 0
static int32_t driver_exception_handle(const struct tee_drv_param *params, int64_t *ret_val)
{
    uint32_t pid = taskid_to_pid(params->caller_pid);
    if (pid != GLOBAL_HANDLE) {
        tloge("task:0x%x not gtask, cannot call exception handle\n", pid);
        return -1;
    }

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("args is invalid\n");
        return -1;
    }

    uint64_t exit_pid = args[EXIT_PID_INDEX];
    if (exit_pid > UINT32_MAX) {
        tloge("invalid exit_pid\n");
        return -1;
    }

    tloge("receive drv crash taskid:0x%x\n", (uint32_t)exit_pid);
    if (find_drv_node_by_taskid(exit_pid) != NULL)
        tee_abort("drv taskid:0x%x abort\n", (uint32_t)exit_pid);

    *ret_val = 0;
    return 0;
}

/*
 * register or unregister maybe called by permission service
 * if the permission service is supported
 */
static bool check_caller_from_legal_service(const struct tee_drv_param *params)
{
    uint32_t pid = taskid_to_pid(params->caller_pid);
    if (pid == GLOBAL_HANDLE)
        return true;

#if defined(TEE_SUPPORT_PERM_64BIT) || defined(TEE_SUPPORT_PERM_32BIT)
    struct tee_uuid perm_srv = TEE_SERVICE_PERM;
    if (memcmp(&params->uuid, &perm_srv, sizeof(perm_srv)) == 0)
        return true;
#endif

    return false;
}

#define DRV_CONF_LEN_INDEX 1
#define DRV_CONF_OFF_INDEX 0

static int32_t drv_conf_register_handle(const struct tee_drv_param *params, int64_t *ret_val)
{
    uint64_t *args = (uint64_t *)(uintptr_t)(params->args);
    char *indata = (char *)(uintptr_t)params->data;
    if (args == NULL || indata == NULL) {
        tloge("drv conf register handle invalied args and indata params\n");
        return -1;
    }

    uint64_t len = args[DRV_CONF_LEN_INDEX];

    if (len != sizeof(struct drv_tlv) || args[DRV_CONF_OFF_INDEX] != 0) {
        tloge("invalied params\n");
        return -1;
    }

    if (!check_caller_from_legal_service(params)) {
        tloge("drv conf can only register from legal service\n");
        return -1;
    }

    struct drv_tlv tlv;
    if (memcpy_s(&tlv, sizeof(tlv), indata, len) != 0) {
        tloge("memcpy for tlv failed\n");
        return -1;
    }

    struct task_node *node = alloc_and_init_drv_node(&tlv);
    if (node == NULL) {
        tloge("alloc drv node fail\n");
        return -1;
    }

    if (receive_task_conf(node) != 0) {
        tloge("receive drv task fail\n");
        free_task_node(node);
        return -1;
    }

    if (check_hardware_type(node, HARDWARE_ENGINE_CRYPTO))
        free_task_node(node);

    *ret_val = 0;
    return 0;
}

static int32_t drv_conf_unregister_handle(const struct tee_drv_param *params, int64_t *ret_val)
{
    uint64_t *args = (uint64_t *)(uintptr_t)(params->args);
    char *indata = (char *)(uintptr_t)params->data;
    if (args == NULL || indata == NULL) {
        tloge("drv conf unregister handle invalied args and indata params\n");
        return -1;
    }

    uint64_t len = args[DRV_CONF_LEN_INDEX];
    char service_name[DRV_NAME_MAX_LEN + 1] = { 0 };

    if (len == 0 || len >= DRV_NAME_MAX_LEN || args[DRV_CONF_OFF_INDEX] != 0) {
        tloge("invalied params\n");
        return -1;
    }

    if (!check_caller_from_legal_service(params)) {
        tloge("drv conf can only unregist from legal service\n");
        return -1;
    }

    if (memcpy_s(service_name, DRV_NAME_MAX_LEN, indata, (size_t)len) != 0) {
        tloge("memcpy service_name failed\n");
        return -1;
    }

    if (free_drv_conf_by_service_name(service_name, len) != 0) {
        tloge("free drv conf failed\n");
        return -1;
    }

    *ret_val = 0;
    return 0;
}

#define DRVCALL_CONF_LEN_INDEX 1
#define DRVCALL_CONF_OFF_INDEX 0
#define DRVCALL_TASKID_INDEX 2

static int32_t drvcall_conf_register_handle(const struct tee_drv_param *params, int64_t *ret_val)
{
    uint64_t *args = (uint64_t *)(uintptr_t)(params->args);
    char *indata = (char *)(uintptr_t)params->data;
    if (args == NULL || indata == NULL) {
        tloge("drvcall conf register handle invalied args and indata params\n");
        return -1;
    }

    uint64_t len = args[DRVCALL_CONF_LEN_INDEX];
    if (len != sizeof(struct drvcall_conf_t) || args[DRVCALL_CONF_OFF_INDEX] != 0) {
        tloge("drvcall conf register handle invalied params\n");
        return -1;
    }

    if (!check_caller_from_legal_service(params)) {
        tloge("drvcall conf can only register from legal service\n");
        return -1;
    }

    struct drvcall_conf_t drvcall;
    if (memcpy_s(&drvcall, sizeof(drvcall), indata, len) != 0) {
        tloge("memcpy for drvcall failed\n");
        return -1;
    }

    drvcall.drvcall_perm_apply.base_perm = false;

    struct task_node *node = alloc_and_init_ta_node(&drvcall);
    if (node == NULL) {
        tloge("create drvcall node fail\n ");
        return -1;
    }

    if (receive_task_conf(node) != 0) {
        tloge("receive task conf fail\n");
        free_task_node(node);
        return -1;
    }

    *ret_val = 0;
    return 0;
}

static int32_t drvcall_conf_unregister_handle(const struct tee_drv_param *params,
    cref_t reply_hdl, struct drv_reply_msg_t *reply, int64_t *ret_val)
{
    uint64_t *args = (uint64_t *)(uintptr_t)(params->args);
    char *indata = (char *)(uintptr_t)params->data;
    if (args == NULL || indata == NULL) {
        tloge("drvcall conf unregister handle invalied args and indata params\n");
        return -1;
    }

    uint64_t len = args[DRVCALL_CONF_LEN_INDEX];
    struct tee_uuid uuid;

    if (len != sizeof(uuid) || args[DRVCALL_CONF_OFF_INDEX] != 0) {
        tloge("invalied params\n");
        return -1;
    }

    if (!check_caller_from_legal_service(params)) {
        tloge("drvcall conf can only unregist from legal service\n");
        return -1;
    }

    if (memcpy_s(&uuid, sizeof(uuid), indata, (size_t)len) != 0) {
        tloge("memcpy uuid failed\n");
        return -1;
    }

    struct task_node *node = get_ta_node_and_set_exit(&uuid);

    reply->header.reply.ret_val = 0;
    int32_t ret = ipc_msg_reply(reply_hdl, reply, sizeof(*reply));
    if (ret != 0)
        tloge("exception reply fail:0x%x\n", ret);

    if (node != NULL) {
        uint32_t close_fd = exception_close_handle(node);

        /*
         * close_fd for those fd that not close normally
         * 2: one for get_drvcall_and_set_exit, another one for register drvcall
         */
        put_node_with_lock(node, (close_fd + DRVCALL_DEC_CNT_INCLUDE_REGISTER_ONE));
    } else {
        /* maybe the exit process has not register */
        tlogd("cannot find taskid:0x%x drvcall\n", taskid);
    }

    *ret_val = 0;
    return 0;
}

#ifdef TEE_SUPPORT_DYN_CONF_DEBUG
static int32_t drvcall_conf_dump_handle(const struct tee_drv_param *params, int64_t *ret_val)
{
    (void)params;
    *ret_val = 0;

    dump_task_node();

    return 0;
}
#endif

static int32_t driver_syscall_dispatch(int32_t swi_id, const struct tee_drv_param *params,
    cref_t reply_hdl, struct drv_reply_msg_t *reply, int64_t *ret_val)
{
    int32_t ret = -1;

    switch (swi_id) {
    case DRV_GENERAL_CMD_ID:
        ret = driver_general_handle(params, ret_val);
        break;
    case DRV_EXCEPTION_CMD_ID:
        ret = driver_exception_handle(params, ret_val);
        break;
    case REGISTER_DRV_CONF:
        ret = drv_conf_register_handle(params, ret_val);
        break;
    case UNREGISTER_DRV_CONF:
        ret = drv_conf_unregister_handle(params, ret_val);
        break;
    case REGISTER_DRVCALL_CONF:
        ret = drvcall_conf_register_handle(params, ret_val);
        break;
    case UNREGISTER_DRVCALL_CONF:
        ret = drvcall_conf_unregister_handle(params, reply_hdl, reply, ret_val);
        break;
#ifdef TEE_SUPPORT_DYN_CONF_DEBUG
    case DUMP_DRVCALL_CONF:
        ret = drvcall_conf_dump_handle(params, ret_val);
        break;
#endif
    default:
        tloge("swi_id:0x%x cannot handle\n", swi_id);
    }

    return ret;
}

static void driver_open_reply_error_callback(int64_t fd, const struct tee_drv_param *params)
{
    struct task_node *call_node = NULL;
    struct fd_node *data = NULL;

    int32_t ret = get_drvcall_and_fd_node(fd, params, &call_node, &data);
    if (ret != 0)
        return;

    tloge("open callback find fd:0x%llx for taskid:0x%x uuid:0x%x\n",
        fd, params->caller_pid, params->uuid.timeLow);

    /* no care whether succ or fail */
    (void)driver_close_func_ops(call_node, fd, &data);

    /*
     * one for get_drvcall_and_fd_node
     * one pair with register drvcall
     */
    put_node_with_lock(call_node, DRVCALL_DEC_CNT_INCLUDE_REGISTER_ONE);
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
    driver_open_reply_error_callback(ret_val, params);
}

static int32_t driver_handle_message(const struct drv_req_msg_t *msg, const struct cap_message_info *info,
                                     struct drv_reply_msg_t *rmsg, const cref_t *msg_hdl)
{
    int64_t ret_val = -1;
    int32_t ret;
    struct tee_drv_param params = { 0 };
    int32_t swi_id = msg->header.send.msg_id;

    ret = get_drv_params(&params, msg, info);
    if (ret != 0) {
        tloge("get driver parameters failed\n");
        return -1;
    }

    tid_t tid = gettid();
    if (tid < 0) {
        tloge("failed to get tid\n");
        return -1;
    }

    update_callerpid_by_tid(tid, params.caller_pid);
    ret = driver_syscall_dispatch(swi_id, &params, *msg_hdl, rmsg, &ret_val);
    update_callerpid_by_tid(tid, INVALID_CALLER_PID);
    if (ret != 0)
        tloge("handle swi 0x%x failed\n", swi_id);

    /*
     * in exception_close_handle, will send reply msg when handle succ,
     * but not send reply msg when handle fail
     */
    if ((swi_id != UNREGISTER_DRVCALL_CONF) || (swi_id == UNREGISTER_DRVCALL_CONF && ret != 0)) {
        rmsg->header.reply.ret_val = (ret == 0) ? ret_val : (int64_t)ret;
        ret = ipc_msg_reply(*msg_hdl, rmsg, sizeof(struct drv_reply_msg_t));
        if (ret != 0) {
            tloge("msg reply for 0x%x failed\n", swi_id);
            /*
             * should clear system resource information alloced by this cmd when reply failed,
             * otherwise it will cause memory leak
             */
            driver_reply_error_handle(swi_id, &params, ret_val);
        }
    }

    return ret;
}

intptr_t driver_dispatch(void *msg, cref_t *p_msg_hdl, struct cap_message_info *info)
{
    int32_t ret;
    struct drv_reply_msg_t reply_raw_buf;

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
