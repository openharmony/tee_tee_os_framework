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

#include "init.h"
#include "teesmcmgr.h"
#include <securec.h>

#include <spawn_ext.h>
#include <stdlib.h>
#include <ipclib.h>
#include <mem_ops.h>
#include <tee_config.h>

#include <stdbool.h>
#include <stdio.h>
#include <tee_log.h>
#include "tee_inner_uuid.h"
#include <sched.h>

#define CASAN_DEFAULT_STACK_SIZE 0x20000

/* Will be used by tloge and its variants */
const char *g_debug_prefix = "GTask";

struct proc_mem_info {
    size_t heap_size;
    size_t stack_size;
};

static int32_t set_proc_mem_size(const struct proc_mem_info *info, posix_spawnattr_t *spawnattr)
{
    int32_t ret;

    if (info->stack_size != 0) {
        ret = spawnattr_setstack(spawnattr, info->stack_size);
        if (ret != 0)
            return ret;
    }

    if (info->heap_size != 0) {
        ret = spawnattr_setheap(spawnattr, info->heap_size);
        if (ret != 0)
            return ret;
    }

    return 0;
}

static int run_init_task(char *name, char *envp[], const struct proc_mem_info *info,
                         const struct tee_uuid *uuid, uint32_t *pid_ptr)
{
    char *subargv[] = { name, NULL };
    pid_t pid       = 0;
    char **p        = NULL;
    posix_spawnattr_t spawnattr;
    spawn_uuid_t suuid;
    int ret;

    for (p = subargv; *p != NULL; p++)
        tlogd("init: subargv %d: %s\n", (int)(p - subargv), *p);
    for (p = envp; *p != NULL; p++)
        tlogd("init: envp %d: %s\n", (int)(p - envp), *p);

    (void)memset_s(&spawnattr, sizeof(spawnattr), 0, sizeof(spawnattr));
    (void)memset_s(&suuid, sizeof(suuid), 0, sizeof(suuid));
    suuid.uuid = *uuid;

    ret = spawnattr_init(&spawnattr);
    if (ret != 0)
        return ret;

    spawnattr_setuuid(&spawnattr, &suuid);
    if (info->stack_size != 0 || info->heap_size != 0) {
        ret = set_proc_mem_size(info, &spawnattr);
        if (ret != 0)
            return ret;
    }
    ret = posix_spawn_ex(&pid, subargv[0], NULL, &spawnattr, subargv, envp, NULL);
    if (ret < 0) {
        tloge("spawn %s failed: %d.\n", name, ret);
        return ret;
    }

    tlogi("init: \"%s\" started with pid %d.\n", name, pid);

    if (pid_ptr != NULL)
        *pid_ptr = (uint32_t)pid;

    return 0;
}

static uint32_t g_timer_pid;

uint32_t get_timer_pid(void)
{
    return g_timer_pid;
}

int32_t get_drvmgr_pid(uint32_t *task_id)
{
    if (task_id == NULL) {
        tloge("invalid task id\n");
        return -1;
    }

    const struct drv_frame_info *drv_info_list = get_drv_frame_infos();
    const uint32_t nr = get_drv_frame_nums();
    uint32_t i;

    for (i = 0; i < nr; i++) {
        /* sizeof include '\0' */
        if (strncmp(drv_info_list[i].drv_name, "drvmgr", sizeof("drvmgr")) == 0) {
            *task_id = drv_info_list[i].pid;
            return 0;
        }
    }

    tloge("drvmgr not found\n");
    return -1;
}

bool is_sys_task(uint32_t task_id)
{
    const struct drv_frame_info *drv_info_list = get_drv_frame_infos();
    const uint32_t nr = get_drv_frame_nums();
    uint32_t i;

    if (taskid_to_pid(task_id) == taskid_to_pid((uint32_t)RESERVED_SYSMGR_CRED) ||
        (taskid_to_pid(task_id) == taskid_to_pid((uint32_t)g_timer_pid)))
        return true;

    for (i = 0; i < nr; i++) {
        if (taskid_to_pid(task_id) == taskid_to_pid((uint32_t)drv_info_list[i].pid))
            return true;
    }
    return false;
}

static int run_drv_frame_tasks(void)
{
    uint32_t i;
    struct drv_frame_info *drv_info_list = get_drv_frame_infos();
    const uint32_t nr = get_drv_frame_nums();
    int ret;
    char *envp[] = { NULL };
    char path[PATHNAME_MAX] = { 0 };
    struct proc_mem_info info = { 0 };

    for (i = 0; i < nr; i++) {
        if (!drv_info_list[i].is_elf)
            continue;
        if (snprintf_s(path, PATHNAME_MAX, PATHNAME_MAX - 1, "/%s.elf", drv_info_list[i].drv_name) < 0) {
            tloge("pack path failed\n");
            return -1;
        }

        info.stack_size = drv_info_list[i].stack_size;
        info.heap_size = drv_info_list[i].heap_size;
        struct tee_uuid *drv_uuid = &drv_info_list[i].uuid;
        ret = run_init_task(path, envp, &info, drv_uuid, &drv_info_list[i].pid);

        (void)memset_s(path, PATHNAME_MAX, 0, PATHNAME_MAX);
        if (ret != 0)
            tloge("run drv: %s failed\n", drv_info_list[i].drv_name);
    }

    return 0;
}

int init_main(void)
{
    int ret;
    char *envp[] = { NULL };
    struct proc_mem_info info = {0};

    struct tee_uuid smc_uuid = TEE_SMC_MGR;
    info.stack_size = SMCMGR_STACK_SIZE;
    ret = run_init_task("/teesmcmgr.elf", envp, &info, &smc_uuid, NULL);
    if (ret)
        return ret;

    ret = run_drv_frame_tasks();
    if (ret != 0)
        return ret;

    return 0;
}

void init_shell(void)
{
    tloge("gtask: *ERROR* GTask exit unexpectedly\n");
    exit(0);
    while (true)
        (void)sched_yield();
}
