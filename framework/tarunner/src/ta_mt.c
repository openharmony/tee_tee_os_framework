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
#include "ta_mt.h"
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <pthread.h>
#include <ipclib.h>
#include <unistd.h>
#include <ta_framework.h>
#include <tee_log.h>
#include "load_init.h"
#include <ipclib_hal.h>
#include <spawn_ext.h>
#include <priorities.h>

#ifndef THREAD_STACK_SIZE
#define THREAD_STACK_SIZE (4096 * 4 * 5)
#endif

#define CREATE_IPC_CHANNEL_NUM 2

struct thread_info {
    struct {
        ta_entry_type ta_entry;
        uint32_t inited;
        int32_t priority;
        const char *name;
        const struct ta_routine_info *append_args;
    } args;
    pthread_t thread;  /* pthread handler */
    cref_t thread_ref; /* thread cref, used to terminated it. */
    uint32_t tid;
    cref_t t_channel[CH_CNT_MAX];
    cref_t t_msghdl;
};
static struct thread_info g_tinfos[TA_SESSION_MAX];

struct create_thread_info {
    size_t stack_size;
    int32_t priority;
};

static struct thread_info *find_thread_by_tid(uint32_t tid)
{
    for (int32_t i = 0; i < TA_SESSION_MAX; i++) {
        if (g_tinfos[i].thread != 0 && g_tinfos[i].tid == tid)
            return &g_tinfos[i];
    }

    return NULL;
}

static struct thread_info *get_free_thread_info_slot(void)
{
    for (int32_t i = 0; i < TA_SESSION_MAX; i++) {
        if (g_tinfos[i].thread == 0)
            return &g_tinfos[i];
    }

    return NULL;
}

/* pti: no concurrent write access, write access is atomic. */
static void release_thread_info(struct thread_info *pti)
{
    pti->thread = 0;
}

#define INVALID_SENDER 0xffffffffU
/*
 * This is a wrapper of ipc_msg_rcv_a.
 * It use to process the possible result of ipc_msg_rcv_a,
 * So no need to process this function's return value.
 * if ipc_msg_rcv_a return NOT OK, only log it and return.
 * if ipc_msg_rcv_a return OK, but the MsgSender is NOT GLOBAL_HANDLE,
 * then try ipc_msg_rcv_a again, until get the Msg from globaltask.
 */
static void msg_rcv_elf(uint32_t timeout, uint32_t *msg_id, void *msgp, uint16_t size)
{
    uint32_t ret;
    uint32_t sender = INVALID_SENDER;

    while (sender != GLOBAL_HANDLE) {
        ret = ipc_msg_rcv_a(timeout, msg_id, msgp, size, &sender);
        if (ret != SRE_OK) {
            tloge("Msg rcv failed, ret = %u\n", ret);
            return;
        }

        if (sender != GLOBAL_HANDLE)
            tlogw("Msg recv from sender = %u\n", sender);
    }
}

static void remove_all_ipc_channel(uint32_t tid, const struct thread_info *pti)
{
    int32_t i;
    int32_t rc;
    pid_t pid;

    for (i = 0; i < CH_CNT_MAX; i++) {
        pid = getpid();
        if (pid == -1) {
            tloge("get pid failed\n");
            continue;
        }

        rc = ipc_remove_channel((taskid_t)pid_to_taskid(tid, pid), NULL, i, pti->t_channel[i]);
        if (rc != 0)
            tloge("remove ipc channel #%d failed: rc=%d\n", i, rc);
    }
}

static TEE_Result ta_recycle_thread(uint32_t tid)
{
    struct thread_info *pti = NULL;
    int32_t rc;

    pti = find_thread_by_tid(tid);
    if ((pti == NULL) || (pti->thread == NULL)) {
        tloge("Cannot find dest thread to recycle, tid = 0x%x\n", tid);
        return TEE_ERROR_GENERIC;
    }
    tlogi("Suspend thread, tid=0x%x\n", tid);

    /* cleanup thread resources, ignore any failed cleanup */
    rc = thread_terminate(pti->thread);
    if (rc != 0)
        tloge("terminate thread failed tid=0x%" PRIx32 " rc=%d\n", tid, rc);

    rc = pthread_join(pti->thread, NULL);
    if (rc != 0)
        tloge("pthread join failed: rc=%d\n", rc);

    remove_all_ipc_channel(tid, pti);
    ipc_msg_delete_hdl(pti->t_msghdl);
    /* clear thread info struct */
    release_thread_info(pti);

    return TEE_SUCCESS;
}

static bool is_agent(const char *task_name)
{
    return strncmp(task_name, SSA_SERVICE_NAME, sizeof(SSA_SERVICE_NAME)) == 0;
}

static int32_t create_ipc_channel(const char *task_name, cref_t *ch[])
{
    bool reg_tamgr = is_agent(task_name);
    struct reg_items_st reg_items;
    reg_items.reg_pid = true;
    reg_items.reg_name = false;
    reg_items.reg_tamgr = reg_tamgr;
    if (ipc_create_channel(task_name, CREATE_IPC_CHANNEL_NUM, ch, reg_items) != 0) {
        tloge("Cannot create thread channel\n");
        return -1;
    }

    return 0;
}

static void call_task_entry(const struct thread_info *pti)
{
    int32_t rc = set_priority(pti->args.priority);
    if (rc < 0)
        tloge("set priority failed: %x\n", rc);

    /* call real TA entry */
    if (pti->args.append_args != NULL)
        (*pti->args.ta_entry.ta_entry)(pti->args.inited, pti->args.append_args);
    else
        (*pti->args.ta_entry.ta_entry_orig)(pti->args.inited);

    /* should never get here, crash myself */
    tee_abort("tee task entry exit!\n");
}

static void *tee_task_entry_thread(void *data)
{
    struct thread_info *pti = data;
    int32_t tid;
    cref_t msghdl;
    cref_t *ch[CH_CNT_MAX];
    int32_t i;
    const char *name = pti->args.name;

    /* get self tid */
    tid = gettid();
    if (tid < 0) {
        tloge("thread self failed: ret=%d\n", tid);
        goto err_get_tid;
    }
    pti->tid = (uint32_t)tid;

    /* prepare message handle */
    msghdl = ipc_msg_create_hdl();
    if (!check_ref_valid(msghdl)) {
        tloge("Cannot create msg_hdl\n");
        goto err_get_tid;
    }
    pti->t_msghdl = msghdl;

    /* store msghdl in self tls */
    if(ipc_save_my_msghdl(msghdl) != 0) {
        tloge("save hdl error");
        goto err_save_hdl;
    }
    /* create IPC channel, and save to tls */
    for (i = 0; i < CH_CNT_MAX; i++)
        ch[i] = &pti->t_channel[i];

    if (create_ipc_channel(name, ch) != 0)
        goto err_save_hdl;

    /* send tid reply to gtask, just pass msg id as 0 */
    if (ipc_msg_qsend(pti->tid, GLOBAL_HANDLE, SECOND_CHANNEL) != SRE_OK) {
        tloge("Msg send failed\n");
        goto err_reply_tid;
    }

    call_task_entry(pti);

err_reply_tid:
    remove_all_ipc_channel(tid, pti);

err_save_hdl:
    ipc_msg_delete_hdl(pti->t_msghdl);

err_get_tid:
    /* reply error for TaskCreate */
    if (ipc_msg_qsend(CREATE_THREAD_FAIL, GLOBAL_HANDLE, SECOND_CHANNEL) != SRE_OK)
        tloge("Msg send 1 failed\n");
    release_thread_info(pti);
    return NULL;
}

static TEE_Result ta_create_thread(ta_entry_type entry, uint32_t inited, const struct create_thread_info *info,
    const char *name, const struct ta_routine_info *append_args)
{
    int32_t rc;
    pthread_attr_t attr;
    struct thread_info *pti = NULL;

    pti = get_free_thread_info_slot();
    if (pti == NULL) {
        tloge("out of thread\n");
        return TEE_ERROR_SESSION_MAXIMUM;
    }

    if (pthread_attr_init(&attr) != 0) {
        tloge("pthread attr init failed\n");
        goto err_out;
    }

    /* set stack size for new thread */
    if (pthread_attr_setstacksize(&attr, info->stack_size) != 0) {
        tloge("pthread attr set stack size failed, size=0x%zx\n", info->stack_size);
        goto err_out;
    }

    /* set thread args */
    pti->args.ta_entry = entry;
    pti->args.inited = inited;
    pti->args.priority = info->priority;
    pti->args.name = name;
    pti->args.append_args = append_args;

    /* create working thread, and get its thread ref */
    rc = pthread_create(&pti->thread, &attr, tee_task_entry_thread, pti);
    if (rc) {
        tloge("pthread create failed: %d\n", rc);
        goto err_out;
    }

    return TEE_SUCCESS;

err_out:
    release_thread_info(pti);
    return TEE_ERROR_GENERIC;
}

static void close_ta2ta_session(uint32_t tid)
{
    void (*delete_ta2ta_session)(uint32_t tid) = NULL;
    void *libtee_handle = NULL;

    libtee_handle = get_libtee_handle();
    if (libtee_handle == NULL) {
        tloge("libtee has not open\n");
        return;
    }

    delete_ta2ta_session = dlsym(libtee_handle, "delete_all_ta2ta_session");
    if (delete_ta2ta_session == NULL) {
        tloge("cannot get delete ta2ta session symbol\n");
        return;
    }
    delete_ta2ta_session(tid);
}

static void clear_session(uint32_t session_id)
{
    void (*clear_session_ops)(uint32_t session_id) = NULL;
    void *libtee_handle = NULL;

    libtee_handle = get_libtee_handle();
    if (libtee_handle == NULL) {
        tloge("libtee has not open\n");
        return;
    }

    clear_session_ops = dlsym(libtee_handle, "clear_session_exception");
    if (clear_session_ops == NULL) {
        tloge("cannot get clear session symbol\n");
        return;
    }
    clear_session_ops(session_id);
}

static void close_session_exception(uint32_t session_id)
{
    clear_session(session_id);
}

static void handle_thread_create(ta_entry_type entry, const struct create_thread_info *info, const char *name,
    const struct ta_routine_info *append_args)
{
    TEE_Result ret;

    ret = ta_create_thread(entry, NON_INIT_BUILD, info, name, append_args);
    if (ret != TEE_SUCCESS) {
        tloge("ta create thread error!!! %x\n", ret);
        if (ipc_msg_qsend(CREATE_THREAD_FAIL, GLOBAL_HANDLE, SECOND_CHANNEL) != SRE_OK)
            tloge("Msg send failed\n");
    }
}

static void handle_thread_remove(uint32_t tid, uint32_t session_id)
{
    TEE_Result ret;
    ret = ta_recycle_thread(tid);
    if (ret != TEE_SUCCESS)
        tloge("ta recycle thread stack error!!! %x\n", ret);
    /* close all ta2ta session opened by this thread */
    close_ta2ta_session(tid);
    close_session_exception(session_id);
    /* send reply to gtask, just pass msg id as 0, ret as TEE_SUCCESS for success */
    if (ipc_msg_qsend((uint32_t)ret, GLOBAL_HANDLE, SECOND_CHANNEL) != SRE_OK)
        tloge("Msg send failed\n");
}

static void tee_task_entry_handle(ta_entry_type ta_entry, int32_t priority, const char *name,
    const struct ta_routine_info *append_args)
{
    uint32_t cmd;
    uint32_t tid;
    uint32_t session_id;
    struct create_thread_info info;
    while (1) {
        struct global_to_service_thread_msg entry_msg = { { { 0 } } };
        cmd = 0;
        tlogd("++ Service TA task enter suspend\n");
        msg_rcv_elf(OS_WAIT_FOREVER, (uint32_t *)(&cmd), &entry_msg, sizeof(entry_msg));
        tlogd("-- Service TA rsv cmd : 0x%x\n", cmd);
        switch (cmd) {
        case CALL_TA_CREATE_THREAD:
            tlogd("++ CALL TA CREATE THREAD\n");
            info.stack_size = entry_msg.create_msg.stack_size;
            info.priority = priority;
            handle_thread_create(ta_entry, &info, name, append_args);
            break;
        case CALL_TA_REMOVE_THREAD:
            tlogd("++ CALL TA REMOVE THREAD\n");
            tid = entry_msg.remove_msg.tid;
            session_id = entry_msg.remove_msg.session_id;
            handle_thread_remove(tid, session_id);
            break;
        case CALL_TA_STHREAD_EXIT: /* no need to break, cos this proc exit directly */
            tlogd("++ CALL TA STHREAD EXIT\n");
            exit(0);
        default:
            tloge("invalid cmdid 0x%x\n", cmd);
            break;
        }
    }
}

/* return from this function will cause taldr crash itself */
void tee_task_entry_mt(ta_entry_type ta_entry, int32_t priority, const char *name,
    const struct ta_routine_info *append_args)
{
    TEE_Result ret;
    size_t stack_size;
    struct create_thread_info info;

    /* no need check ta_entry_orig since ta_entry_type is a union */
    if (ta_entry.ta_entry == NULL || name == NULL) {
        tloge("bad TA entry\n");
        return;
    }

    stack_size = getstacksize();
    if (stack_size == 0) {
        tloge("get stack size failed, use default stack size 0x%x\n", THREAD_STACK_SIZE);
        stack_size = THREAD_STACK_SIZE;
    }

    info.stack_size = stack_size;
    info.priority = priority;
    /* Create a working thread at startup */
    ret = ta_create_thread(ta_entry, INIT_BUILD, &info, name, append_args);
    if (ret != TEE_SUCCESS) {
        tloge("ta create thread error!!! %x\n", ret);
        /* notify gtask that thread creating fails */
        if (ipc_msg_qsend(CREATE_THREAD_FAIL, GLOBAL_HANDLE, SECOND_CHANNEL) != SRE_OK)
            tloge("Msg send failed\n");
        return;
    }

    tee_task_entry_handle(ta_entry, priority, name, append_args);
}
