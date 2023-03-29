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
#include "drv_thread.h"
#include <errno.h>
#include <ipclib.h>
#include <tee_log.h>
#include <mem_page_ops.h>
#include <tee_drv_internal.h>
#include <ipclib_hal.h>

#define IPC_CHANNEL_NUM 2
static pthread_mutex_t g_drv_caller_info_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct syscaller_info *g_syscaller_info = NULL;
static uint32_t g_thread_num = 1; /* one for main thread */
static sem_t g_thread_sem;

static int32_t thread_syscaller_init(uint32_t thread_num)
{
    g_thread_num += thread_num;
    uint32_t size = g_thread_num * sizeof(struct syscaller_info);

    g_syscaller_info = malloc(size);
    if (g_syscaller_info == NULL) {
        tloge("cannot alloc for syscaller thread_num:%u\n", g_thread_num);
        return -1;
    }

    if (memset_s(g_syscaller_info, size, 0, size) != 0) {
        free(g_syscaller_info);
        g_syscaller_info = NULL;
        return -1;
    }

    uint32_t i;
    for (i = 0; i < g_thread_num; i++)
        g_syscaller_info[i].current_thread = INVALID_CALLER_PID;

    return 0;
}

int32_t get_callerpid_and_job_handler_by_tid(tid_t tid, pid_t *caller_pid, uint64_t *job_handler)
{
    if (caller_pid == NULL || job_handler == NULL) {
        printf("invalid parameter\n");
        return DRV_CALL_ERROR;
    }

    for (uint32_t i = 0; i < g_thread_num; i++) {
        if (g_syscaller_info[i].current_thread == tid) {
            *caller_pid = g_syscaller_info[i].caller_pid;
            *job_handler = g_syscaller_info[i].job_handler;
            return DRV_CALL_OK;
        }
    }

    tloge("get caller pid and job_handler failed\n");

    return DRV_CALL_ERROR;
}

int32_t get_callerpid_by_tid(tid_t tid, pid_t *caller_pid)
{
    uint64_t job_handler;
    int32_t ret = get_callerpid_and_job_handler_by_tid(tid, caller_pid, &job_handler);
    return ret;
}

void update_callerpid_by_tid(tid_t tid, pid_t caller_pid)
{
    uint32_t i;
    if (pthread_mutex_lock(&g_drv_caller_info_mutex) != 0) {
        tloge("mutex lock failed\n");
        return;
    }

    for (i = 0; i < g_thread_num; i++) {
        if (g_syscaller_info[i].current_thread == tid) {
            g_syscaller_info[i].caller_pid = caller_pid;
            if (pthread_mutex_unlock(&g_drv_caller_info_mutex) != 0)
                tloge("mutex unlock failed\n");
            return;
        }
    }

    for (i = 0; i < g_thread_num; i++) {
        if (g_syscaller_info[i].current_thread == INVALID_CALLER_PID) {
            g_syscaller_info[i].current_thread = tid;
            g_syscaller_info[i].caller_pid = caller_pid;
            if (pthread_mutex_unlock(&g_drv_caller_info_mutex) != 0)
                tloge("mutex unlock failed\n");
            return;
        }
    }

    if (pthread_mutex_unlock(&g_drv_caller_info_mutex) != 0)
        tloge("mutex unlock failed\n");
}

void update_caller_info_by_tid(tid_t tid, pid_t caller_pid, uint64_t job_handler)
{
    uint32_t i;
    if (pthread_mutex_lock(&g_drv_caller_info_mutex) != 0) {
        tloge("get mutex lock failed\n");
        return;
    }

    for (i = 0; i < g_thread_num; i++) {
        if (g_syscaller_info[i].current_thread == tid) {
            g_syscaller_info[i].caller_pid = caller_pid;
            g_syscaller_info[i].job_handler = job_handler;
            if (pthread_mutex_unlock(&g_drv_caller_info_mutex) != 0)
                tloge("mutex unlock failed\n");
            return;
        }
    }

    for (i = 0; i < g_thread_num; i++) {
        if (g_syscaller_info[i].current_thread == INVALID_CALLER_PID) {
            g_syscaller_info[i].current_thread = tid;
            g_syscaller_info[i].caller_pid = caller_pid;
            g_syscaller_info[i].job_handler = job_handler;
            if (pthread_mutex_unlock(&g_drv_caller_info_mutex) != 0)
                tloge("mutex unlock failed\n");
            return;
        }
    }

    if (pthread_mutex_unlock(&g_drv_caller_info_mutex) != 0)
        tloge("mutex unlock failed\n");
}

static void *tee_driver_thread(void *args)
{
    struct thread_init_info *pthread_info = (struct thread_init_info *)args;
    struct reg_items_st reg_items = { true, false, false };

    cref_t channel = pthread_info->channel;
    dispatch_fn_t dispatch_fns_thread[] = {
        [0] = driver_dispatch,
    };

    int32_t ret = ipc_create_channel(NULL, IPC_CHANNEL_NUM, NULL, reg_items);
    if (ret != 0) {
        tloge("fail to create channel ret: 0x%x\n", ret);
        return NULL;
    }

    sem_post(pthread_info->thread_sem);

    cs_server_loop(channel, dispatch_fns_thread, ARRAY_SIZE(dispatch_fns_thread), NULL, pthread_info);

    return NULL;
}

static int32_t init_pthread_info(struct thread_init_info *pthread_info, cref_t channel,
    size_t stack_size, uint32_t thread_limit)
{
    pthread_info->channel = channel;
    pthread_info->func = tee_driver_thread;
    pthread_info->max_thread = thread_limit;
    pthread_info->thread_sem = &g_thread_sem;
    pthread_info->stack_size = stack_size;
    return DRV_CALL_OK;
}

static void creat_server_thread(cref_t channel, size_t stack_size, uint32_t thread_limit)
{
    pthread_attr_t attr;
    struct thread_init_info *info = NULL;
    int32_t ret;
    pthread_t thread_id;

    /* create thread, thread0 is common thread. */
    info = malloc(sizeof(*info));
    if (info == NULL)
        tee_abort("malloc thread info mem error\n");

    ret = pthread_attr_init(&attr);
    if (ret != 0) {
        free(info);
        tee_abort("init pthread attr failed\n");
    }

    if (stack_size != 0) {
        ret = pthread_attr_setstacksize(&attr, stack_size);
        if (ret != 0) {
            free(info);
            (void)pthread_attr_destroy(&attr);
            tee_abort("set attr stack size fail\n");
        }
    }

    ret = init_pthread_info(info, channel, stack_size, thread_limit);
    if (ret != DRV_CALL_OK) {
        free(info);
        tee_abort("init thread info error\n");
    }

    ret = pthread_create(&thread_id, &attr, tee_driver_thread, info);
    if (ret != 0) {
        free(info);
        tee_abort("create pthread failed\n");
    }
    (void)pthread_attr_destroy(&attr);
}

static int32_t thread_init_param_check(uint32_t thread_limit, uint32_t *stack_size)
{
    /* thread_limit is 0 means only have main thread */
    if (thread_limit > DRV_THREAD_MAX) {
        tloge("thread limit:%u invalid\n", thread_limit);
        return -1;
    }

    uint32_t stack = *stack_size;
    uint32_t temp_stack = PAGE_ALIGN_UP(stack);
    if (temp_stack < stack) {
        tloge("invalid stack size:0x%x\n", stack);
        return -1;
    }

    *stack_size = temp_stack;

    return 0;
}

int32_t drv_thread_init(const char *thread_name, uint32_t stack_size, uint32_t thread_limit)
{
    cref_t channel;

    if ((thread_name == NULL) || (strnlen(thread_name, DRV_NAME_MAX_LEN) == 0) ||
        (strnlen(thread_name, DRV_NAME_MAX_LEN) >= DRV_NAME_MAX_LEN)) {
        tloge("thread init invalid name\n");
        return -1;
    }

    int32_t ret = ipc_create_channel_native(thread_name, &channel);
    if (ret != 0)
        tee_abort("%s: failed to create channel :%d\n", thread_name, ret);

    return multi_drv_framwork_init(thread_limit, stack_size, channel);
}

int32_t multi_drv_framwork_init(uint32_t thread_limit, uint32_t stack_size, cref_t channel)
{
    uint32_t stack = stack_size;
    if (thread_init_param_check(thread_limit, &stack) != 0)
        return -1;

    if (g_syscaller_info != NULL)
        return 0;

    tlogd("thread_limit:%u stack_size:0x%x\n", thread_limit, stack_size);

    int32_t ret = thread_syscaller_init(thread_limit);
    if (ret != 0)
        return -1;

    if (thread_limit > 0) {
        (void)sem_init(&g_thread_sem, 0, 0);
        creat_server_thread(channel, stack, thread_limit);
        if (sem_wait(&g_thread_sem) != 0)
            tee_abort("sem wait failed\n");
    }

    return 0;
}
