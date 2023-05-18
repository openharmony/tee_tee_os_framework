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
#include <stdio.h>
#include <sys/mman.h>
#include <tee_log.h>
#include <ipclib.h>             /* for channel */
#include <sys/priorities.h>
#include <pthread.h>            /* for thread */
#include <stdlib.h>
#include <tee_defines.h>
#include <tee_init.h>
#include <tee_ext_api.h>
#include <ta_framework.h>
#include <tee_internal_task_pub.h>
#include "permission_service.h"
#include "perm_srv_common.h"
#include "perm_srv_ta_crl_cmd.h"
#include "perm_srv_ta_crl.h"
#include "perm_srv_elf_verify_cmd.h"
#include "perm_srv_cms_crl_storage.h"
#include "perm_srv_ta_cert.h"
#include "perm_srv_ta_config.h"
#include "perm_srv_ta_ctrl.h"
#include <ipclib_hal.h>
#include <spawn_ext.h>
#include <securec.h>

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG   "permission service"
#define CERT_PATH "permservice"

#define WEAK __attribute__((weak))
#define BSS_START_MAGIC 0x12345678
#define BSS_END_MAGIC   0x87654321

uint32_t WEAK TA_BSS_START = BSS_START_MAGIC;
uint32_t WEAK TA_BSS_END = BSS_END_MAGIC;

static void clear_ta_bss(void)
{
    uint32_t ta_bss_start = (uint32_t)&TA_BSS_START;
    uint32_t ta_bss_end = (uint32_t)&TA_BSS_END;

    if (TA_BSS_START == BSS_START_MAGIC && TA_BSS_END == BSS_END_MAGIC) {
        tlogd("only weak bss define\n");
        return;
    }

    if (ta_bss_end > ta_bss_start)
        (void)memset_s((void *)(uintptr_t)ta_bss_start, ta_bss_end - ta_bss_start, 0, ta_bss_end - ta_bss_start);
    else if (ta_bss_end == ta_bss_start)
        tlogd("bss addr end equals to start\n");
    else
        tloge("failed\n");
}

static const struct ta_init_msg g_permsrv_init_msg = {
    .prop.uuid = TEE_SERVICE_PERM,
};

static TEE_Result perm_srv_load_crl_and_ctrl_list(const perm_srv_req_msg_t *req_msg, uint32_t sndr_taskid,
                                  const TEE_UUID *sndr_uuid, perm_srv_reply_msg_t *rsp)
{
    TEE_Result ret;

    (void)req_msg;
    (void)sndr_taskid;
    (void)sndr_uuid;

    ret = perm_srv_global_ta_crl_list_loading(false);
    if (ret != TEE_SUCCESS) {
        tloge("CRL list loading fail, ret is 0x%x\n", ret);
        goto out;
    }

    ret = perm_srv_global_ta_ctrl_list_loading(false);
    if (ret != TEE_SUCCESS)
        tloge("TA control list loading fail, ret is 0x%x\n", ret);

out:
    rsp->reply.ret = ret;
    return ret;
}

/* check the cmd permission of TAs who are not gtask. */
static bool check_file_cmd_perm(uint32_t sndr_taskid, uint32_t cmd)
{
    TEE_Result ret;
    struct config_info config;

    (void)memset_s(&config, sizeof(config), 0, sizeof(config));
    ret = perm_srv_get_config_by_taskid(sndr_taskid, &config);
    if (ret != TEE_SUCCESS) {
        tloge("get config by taskid failed\n");
        return false;
    }

    bool is_cert_import_enable = false;
    ret = perm_srv_check_cert_import_enable(&config, cmd, &is_cert_import_enable);
    if (ret != TEE_SUCCESS) {
        tloge("check cert import enable failed\n");
        return false;
    }
    if (is_cert_import_enable)
        return true;

    static const TEE_UUID crl_agent_uuid = TEE_SERVICE_CRLAGENT;
    bool is_crl_ctrl_enable = TEE_MemCompare(&crl_agent_uuid, &config.uuid, sizeof(config.uuid)) == 0 &&
        (cmd == PERMSRV_SET_CRL_CERT || cmd == PERMSRV_SET_TA_CTRL_LIST);
    if (is_crl_ctrl_enable)
        return true;

    return false;
}

static const perm_srv_cmd_t g_file_thread_cmd_tbl[] = {
    {TEE_TASK_LOAD_CRL_AND_CTRL_LIST, perm_srv_load_crl_and_ctrl_list},
    {PERMSRV_SET_CRL_CERT, perm_srv_set_crl_cert},
};
static const uint32_t g_file_thread_cmd_num = sizeof(g_file_thread_cmd_tbl) / sizeof(g_file_thread_cmd_tbl[0]);

static TEE_Result handle_file_msg_cmd(const perm_srv_req_msg_t *req_msg, uint32_t cmd_id, uint32_t sndr_taskid,
                                      perm_srv_reply_msg_t *rsp)
{
    TEE_Result ret = TEE_ERROR_INVALID_CMD;
    uint32_t i;

    /* File_OPT subthread cannot receive synchronization messages sent by gtask to avoid deadlock. */
    for (i = 0; i < g_file_thread_cmd_num; i++) {
        if (cmd_id != g_file_thread_cmd_tbl[i].cmd)
            continue;
        ret = g_file_thread_cmd_tbl[i].func(req_msg, sndr_taskid, NULL, rsp);
        break;
    }
    if (i >= g_file_thread_cmd_num)
        tloge("not support the cmd id 0x%x\n", cmd_id);

    if (ret != TEE_SUCCESS)
        tloge("handle msg cmd fail 0x%x\n", ret);
    return ret;
}

static void perm_thread_handle_file_msg(const perm_srv_req_msg_t *req_msg, uint32_t sndr_taskid,
                                        uint16_t msg_type, cref_t msghdl)
{
    uint32_t cmd_id = req_msg->header.send.msg_id;
    perm_srv_reply_msg_t rsp;
    TEE_Result ret;
    int32_t rc;

    (void)memset_s(&rsp, sizeof(rsp), 0, sizeof(rsp));

    bool is_access_perm = (sndr_taskid == GLOBAL_HANDLE) || check_file_cmd_perm(sndr_taskid, cmd_id);
    if (is_access_perm == false) {
        rsp.reply.ret = TEE_ERROR_ACCESS_DENIED;
        goto end;
    }

    ret = handle_file_msg_cmd(req_msg, cmd_id, sndr_taskid, &rsp);
    if (ret != TEE_SUCCESS)
        tlogd("handle file msg cmd fail 0x%x\n", ret);

end:
    if (msg_type == MSG_TYPE_CALL) {
        rc = ipc_msg_reply(msghdl, &rsp, sizeof(rsp));
        if (rc != 0)
            tloge("reply error 0x%x\n", rc);
    }
    return;
}

static TEE_Result perm_thread_file_create_ipc_channel(cref_t *msghdl, cref_t *native_channel, cref_t *file_channel)
{
    TEE_Result ret;

    *msghdl = ipc_msg_create_hdl();
    if (!check_ref_valid(*msghdl)) {
        tloge("thread file operation function create msg_hdl failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (ipc_create_channel_native(PERMSRV_FILE_OPT, native_channel) != 0) {
        tloge("thread file operation function create native channel failed\n");
        return TEE_ERROR_GENERIC;
    }

    /* create IPC channel */
    if (ipc_create_single_channel(PERMSRV_SAVE_FILE, file_channel, true, false, true) != 0) {
        tloge("thread file operation function create file channel failed\n");
        return TEE_ERROR_GENERIC;
    }

    /* The tee_init() cannot be deleted from subthread 2. Otherwise, the ssa function will be affected. */
    ret = tee_init(&g_permsrv_init_msg);
    if (ret != TEE_SUCCESS)
        /* no care the return code */
        tloge("TEE init error\n");

    return TEE_SUCCESS;
}

static void perm_thread_remove_channel(const char *name, cref_t channel)
{
    taskid_t pid;

    pid = get_self_taskid();
    if (pid < 0) {
        tloge("get self pid error\n");
        return;
    }

    if (ipc_remove_channel(pid, name, 0, channel) != 0)
        tloge("remove the file channel failed\n");
}

void *perm_thread_init_file(void *data)
{
    int32_t rc;
    perm_srv_req_msg_t req_msg;
    uint32_t sender_taskid = 0;
    cref_t native_channel = 0;
    cref_t file_channel = 0;
    struct src_msginfo info = { 0 };
    cref_t msghdl;
    (void)data;

    (void)memset_s(&req_msg, sizeof(req_msg), 0, sizeof(req_msg));

    rc = (int32_t)perm_thread_file_create_ipc_channel(&msghdl, &native_channel, &file_channel);
    if (rc != 0)
        goto exit;

    while (true) {
        rc = ipc_msg_receive(native_channel, &req_msg, (unsigned long)sizeof(req_msg), msghdl, &info, -1);
        if (rc < 0) {
            tloge("%s: message receive failed, %llx\n", LOG_TAG, rc);
            continue;
        }

        if (info.src_pid == 0)
            sender_taskid = GLOBAL_HANDLE;
        else
            sender_taskid = (uint32_t)pid_to_taskid(info.src_tid, info.src_pid);

        perm_thread_handle_file_msg(&req_msg, sender_taskid, info.msg_type, msghdl);
    }

    perm_thread_remove_channel(PERMSRV_SAVE_FILE, file_channel);

exit:
    ipc_msg_delete_hdl(msghdl);
    return NULL;
}

static const perm_srv_cmd_t g_async_file_thread_cmd_tbl[] = {
    {TEE_TASK_ELF_VERIFY, perm_srv_elf_verify},
};
static const uint32_t g_async_file_thread_cmd_num = sizeof(g_async_file_thread_cmd_tbl) /
                                                    sizeof(g_async_file_thread_cmd_tbl[0]);

static TEE_Result handle_async_file_msg_cmd(const perm_srv_req_msg_t *req_msg, uint32_t cmd_id, uint32_t sndr_taskid)
{
    TEE_Result ret = TEE_ERROR_INVALID_CMD;
    uint32_t i;

    /* Async_file_OPT subthread cannot receive synchronization messages sent by gtask to avoid deadlock. */
    for (i = 0; i < g_async_file_thread_cmd_num; i++) {
        if (cmd_id != g_async_file_thread_cmd_tbl[i].cmd)
            continue;
        ret = g_async_file_thread_cmd_tbl[i].func(req_msg, sndr_taskid, NULL, NULL);
        break;
    }
    if (i >= g_async_file_thread_cmd_num)
        tloge("not support the cmd id 0x%x\n", cmd_id);

    if (ret != TEE_SUCCESS)
        tloge("handle msg cmd fail 0x%x\n", ret);

    perm_srv_cms_crl_store(cmd_id);

    return ret;
}

static void perm_thread_handle_async_file_msg(const perm_srv_req_msg_t *req_msg, uint32_t sndr_taskid)
{
    uint32_t cmd_id = req_msg->header.send.msg_id;
    TEE_Result ret;

    if (sndr_taskid != GLOBAL_HANDLE) {
        /* only gtask can call this interface */
        tloge("sender 0x%x no perm\n", sndr_taskid);
        return;
    }

    /*
    * TA_verify\CA_verify\CRL_update need to load\store cms crl from\to ssa and update cms crl in memory,
    * so they cannot be in the same thread with other sync cmds,
    * and concurrent invokcation is not supported.
    */
    perm_srv_cms_crl_load();

    ret = handle_async_file_msg_cmd(req_msg, cmd_id, sndr_taskid);
    if (ret != TEE_SUCCESS)
        tlogd("handle async file msg cmd fail 0x%x\n", ret);
}

static TEE_Result perm_thread_async_file_create_ipc_channel(cref_t *msghdl, cref_t *native_channel,
                                                            cref_t *file_channel)
{
    *msghdl = ipc_msg_create_hdl();
    if (!check_ref_valid(*msghdl)) {
        tloge("thread async file operation function create msg_hdl failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (ipc_create_channel_native(PERMSRV_ASYNC_OPT, native_channel) != 0) {
        tloge("thread async file operation function create native channel failed\n");
        return TEE_ERROR_GENERIC;
    }

    /* create IPC channel */
    if (ipc_create_single_channel(PERMSRV_ASYNC_OPT_FILE, file_channel, true, false, false) != 0) {
        tloge("thread async file operation function create file channel failed\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

void *perm_thread_init_async_file(void *data)
{
    int32_t rc;
    perm_srv_req_msg_t req_msg;
    uint32_t sender_taskid = 0;
    cref_t async_native_channel = 0;
    cref_t async_file_channel = 0;
    struct src_msginfo info = { 0 };
    cref_t msghdl;
    (void)data;

    (void)memset_s(&req_msg, sizeof(req_msg), 0, sizeof(req_msg));

    rc = (int32_t)perm_thread_async_file_create_ipc_channel(&msghdl, &async_native_channel, &async_file_channel);
    if (rc != 0)
        goto del_hdl;

    while (true) {
        rc = ipc_msg_receive(async_native_channel, &req_msg, (unsigned long)sizeof(req_msg), msghdl, &info, -1);
        if (rc < 0) {
            tloge("%s: async msg receive failed, %llx\n", LOG_TAG, rc);
            continue;
        }

        if (info.src_pid == 0)
            sender_taskid = GLOBAL_HANDLE;
        else
            sender_taskid = (uint32_t)pid_to_taskid(info.src_tid, info.src_pid);

        perm_thread_handle_async_file_msg(&req_msg, sender_taskid);
    }

    perm_thread_remove_channel(PERMSRV_ASYNC_OPT_FILE, async_file_channel);

del_hdl:
    ipc_msg_delete_hdl(msghdl);
    return NULL;
}

#define THREAD_STACK (16 * 4096)

TEE_Result perm_srv_create_rw_thread(void *(*thread_entry)(void *), const char *file, const char *buff,
                                     size_t buff_size)
{
    pthread_t thread = NULL;
    pthread_attr_t attr = { 0 };
    uint32_t stack_size = THREAD_STACK;
    int32_t rc;

    (void)file;
    (void)buff_size;
    (void)buff;
    /* Init pthread attr */
    if (pthread_attr_init(&attr) != 0) {
        tloge("pthread attr init failed\n");
        return TEE_ERROR_GENERIC;
    }

    /* Set stack size for new thread */
    if (pthread_attr_setstacksize(&attr, stack_size) != 0) {
        tloge("pthread set stack failed, size = 0x%x\n", stack_size);
        return TEE_ERROR_GENERIC;
    }

    rc = pthread_create(&thread, &attr, thread_entry, NULL);
    if (rc != 0) {
        tloge("create thread error 0x%x\n", rc);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result perm_srv_register_ta(const perm_srv_req_msg_t *msg, uint32_t sndr_taskid,
                                       const TEE_UUID *sndr_uuid, perm_srv_reply_msg_t *rsp)
{
    TEE_Result ret;

    (void)sndr_uuid;
    (void)rsp;
    if (sndr_taskid != GLOBAL_HANDLE)
        return TEE_ERROR_ACCESS_DENIED;

    TEE_UUID uuid = msg->req_msg.reg_ta.uuid;
    ret = perm_srv_register_ta_taskid(&uuid, msg->req_msg.reg_ta.taskid,
                                      msg->req_msg.reg_ta.userid);
    if (ret != TEE_SUCCESS)
        tloge("register ta error, 0x%x\n", ret);

    return ret;
}

static TEE_Result perm_srv_unregister_ta(const perm_srv_req_msg_t *msg, uint32_t sndr_taskid,
                                         const TEE_UUID *sndr_uuid, perm_srv_reply_msg_t *rsp)
{
    TEE_Result ret;

    (void)sndr_uuid;
    (void)rsp;
    if (sndr_taskid != GLOBAL_HANDLE)
        return TEE_ERROR_ACCESS_DENIED;

    TEE_UUID uuid = msg->req_msg.reg_ta.uuid;
    ret = perm_srv_unregister_ta_taskid(&uuid, msg->req_msg.reg_ta.taskid);
    if (ret != TEE_SUCCESS)
        tloge("unregister ta error, 0x%x\n", ret);

    return ret;
}

static TEE_Result perm_srv_release_ta(const perm_srv_req_msg_t *msg, uint32_t sndr_taskid,
                                      const TEE_UUID *sndr_uuid, perm_srv_reply_msg_t *rsp)
{
    (void)sndr_uuid;
    (void)rsp;
    if (sndr_taskid != GLOBAL_HANDLE) {
        tloge("sender has no permission\n");
        return TEE_ERROR_ACCESS_DENIED;
    }

    TEE_UUID uuid = msg->req_msg.ta_unload.uuid;

    perm_srv_clear_ta_permissions(&uuid);
    return TEE_SUCCESS;
}

static const perm_srv_cmd_t g_main_thread_cmd_tbl[] = {
    {TEE_TASK_OPEN_TA_SESSION, perm_srv_register_ta},
    {TEE_TASK_CLOSE_TA_SESSION, perm_srv_unregister_ta},
    {TEE_TASK_RELEASE_TA_SERVICE, perm_srv_release_ta},
};
static const uint32_t g_main_thread_cmd_num = sizeof(g_main_thread_cmd_tbl) / sizeof(g_main_thread_cmd_tbl[0]);

static TEE_Result handle_main_thread_msg_cmd(const perm_srv_req_msg_t *req_msg, uint32_t cmd_id, uint32_t sndr_taskid,
                                             const TEE_UUID *sndr_uuid, perm_srv_reply_msg_t *rsp)
{
    TEE_Result ret = TEE_ERROR_INVALID_CMD;
    uint32_t i;

    /* Main thread cannot receive synchronization messages sent by gtask to avoid deadlock. */
    for (i = 0; i < g_main_thread_cmd_num; i++) {
        if (cmd_id != g_main_thread_cmd_tbl[i].cmd)
            continue;
        ret = g_main_thread_cmd_tbl[i].func(req_msg, sndr_taskid, sndr_uuid, rsp);
        break;
    }
    if (i >= g_main_thread_cmd_num)
        tloge("not support the cmd id 0x%x\n", cmd_id);

    if (ret != TEE_SUCCESS)
        tloge("handle msg cmd fail 0x%x\n", ret);

    return ret;
}

static void  perm_thread_handle_main_msg(const perm_srv_req_msg_t *req_msg, uint32_t sndr_taskid,
                                   const TEE_UUID *sndr_uuid, uint16_t msg_type, cref_t msghdl)
{
    uint32_t cmd_id = req_msg->header.send.msg_id;
    perm_srv_reply_msg_t rsp;
    TEE_Result ret;

    (void)memset_s(&rsp, sizeof(rsp), 0, sizeof(rsp));

    ret = handle_main_thread_msg_cmd(req_msg, cmd_id, sndr_taskid, sndr_uuid, &rsp);
    if (ret != TEE_SUCCESS)
        tlogd("handle main msg cmd fail 0x%x\n", ret);
    if (msg_type == MSG_TYPE_CALL) {
        if (ipc_msg_reply(msghdl, &rsp, sizeof(rsp)) != 0) {
            tloge("reply error\n");
            return;
        }
    }
}

#define TEE_TASK_EXIT   (-1)
static void create_subthreads(void)
{
    /*
     * File thread can process messages from TAs, except for gtask synchronization messages.
     * The reason for naming is that this thread currently mainly handles file operations.
     */
    if (perm_srv_create_rw_thread(perm_thread_init_file, NULL, NULL, 0) != TEE_SUCCESS) {
        tloge("file opt thread created fail\n");
        exit(TEE_TASK_EXIT);
    }

    /*
     * Async_file thread can only process asynchronous messages from gtask.
     * The reason for naming is that this thread currently mainly handles asynchronous file operations.
     */
    if (perm_srv_create_rw_thread(perm_thread_init_async_file, NULL, NULL, 0) != TEE_SUCCESS) {
        tloge("async file opt thread created fail\n");
        exit(TEE_TASK_EXIT);
    }
}

__attribute__((visibility("default"))) void tee_task_entry(int32_t init_build)
{
    perm_srv_req_msg_t req_msg;
    uint32_t sender_taskid = 0;
    spawn_uuid_t sender_uuid;
    int32_t ret;

    (void)memset_s(&req_msg, sizeof(req_msg), 0, sizeof(req_msg));
    cref_t native_channel = 0;
    struct src_msginfo info = { 0 };
    cref_t msghdl;

    if (init_build == 0)
        clear_ta_bss();

    msghdl = ipc_get_my_msghdl();
    if (!check_ref_valid(msghdl)) {
        tloge("Cannot create msg_hdl, %x\n", (int32_t)msghdl);
        exit((int32_t)msghdl);
    }

    if (ipc_create_channel_native(CERT_PATH, &native_channel) != 0) {
        tloge("create main thread native channel failed\n");
        exit(TEE_TASK_EXIT);
    }

    create_subthreads();

    while (true) {
        ret = ipc_msg_receive(native_channel, &req_msg, sizeof(req_msg), msghdl, &info, -1);
        if (ret < 0) {
            tloge("%s: message receive failed, %llx\n", LOG_TAG, ret);
            continue;
        }

        if (info.src_pid == 0)
            sender_taskid = GLOBAL_HANDLE;
        else
            sender_taskid = (uint32_t)pid_to_taskid(info.src_tid, info.src_pid);

        (void)memset_s(&sender_uuid, sizeof(sender_uuid), 0, sizeof(sender_uuid));
        if (getuuid((pid_t)info.src_pid, &sender_uuid) != 0)
            tloge("get uuid failed\n");

        perm_thread_handle_main_msg(&req_msg, sender_taskid, &sender_uuid.uuid, info.msg_type, msghdl);
    }
    tloge("permission service abort\n");
}
