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
#include "tee_drv_entry.h"
#include <stdio.h>
#include <inttypes.h>
#include <priorities.h>
#include <ipclib.h>
#include <spawn_init.h>
#include <tee_log.h>
#include "drv_dispatch.h"
#include "drv_thread.h"
#include "drv_operations.h"
#include "cs.h"
#ifdef CRYPTO_MGR_SERVER_ENABLE
#include "drv_random.h"
#include "crypto_manager.h"
#endif

static taskid_t g_drv_mgr_pid;
static const struct tee_driver_module *g_drv_func = NULL;
static uint32_t g_drv_index;

static int32_t hunt_drv_mgr_pid(taskid_t *pid)
{
    uint32_t ret = ipc_hunt_by_name("drvmgr", pid);
    if (ret != 0) {
        tloge("get drv mgr pid failed\n");
        return -1;
    }

    return 0;
}

taskid_t get_drv_mgr_pid(void)
{
    return g_drv_mgr_pid;
}

const struct tee_driver_module *get_drv_func(void)
{
    return g_drv_func;
}

uint32_t get_drv_index(void)
{
    return g_drv_index;
}

static int32_t send_succ_msg_to_drvmgr(void)
{
    cref_t ch = -1;
    int32_t ret = ipc_get_ch_from_path(DRV_SPAWN_SYNC_NAME, &ch);
    if (ret != 0) {
        tloge("something wrong, spawn succ get sync channel fail:0x%x\n", ret);
        return -1;
    }

    struct spawn_sync_msg msg = { 0 };
    msg.msg_id = PROCESS_INIT_SUCC;

    ret = ipc_msg_notification(ch, &msg, sizeof(msg));
    if (ret != 0) {
        tloge("spawn succ notify fail:0x%x\n", ret);
        return -1;
    }

    uint32_t ipc_ret = ipc_release_from_path(DRV_SPAWN_SYNC_NAME, ch);
    if (ipc_ret != 0)
        tloge("spawn succ release sync channel fail:0x%x\n", ipc_ret);

    return 0;
}

static int32_t param_check(const struct tee_driver_module *drv_func, const char *drv_name,
    const struct env_param *param)
{
    if (drv_func == NULL || drv_name == NULL || param == NULL) {
        tloge("invalid drv param\n");
        return -1;
    }

    if (param->thread_limit == 0) {
        tloge("invalid thread limit\n");
        return -1;
    }

    if (drv_func->open == NULL || drv_func->ioctl == NULL || drv_func->close == NULL) {
        tloge("invalid drv func\n");
        return -1;
    }

    return 0;
}

static int32_t call_drv_init_func(const char *drv_name, const struct tee_driver_module *drv_func)
{
    if (drv_func->init != NULL) {
        init_func func = drv_func->init;
        int32_t ret = func();
        if (ret != 0) {
            tloge("drv:%s init fail ret:0x%x\n", drv_name, ret);
            return -1;
        }
    }

    return 0;
}

__attribute__((visibility("default"))) \
void tee_drv_entry(const struct tee_driver_module *drv_func, const char *drv_name,
    cref_t ch, const struct env_param *param)
{
    static dispatch_fn_t dispatch_fns[] = {
        [0] = driver_dispatch,
    };

    int32_t ret = param_check(drv_func, drv_name, param);
    if (ret != 0)
        return;

    tlogi("%s begin thread_limit:%u drv_index:%u\n", drv_name, param->thread_limit, param->drv_index);

    g_drv_func = drv_func;
    g_drv_index = param->drv_index;

    ret = hunt_drv_mgr_pid(&g_drv_mgr_pid);
    if (ret != 0)
        return;

    ret = set_priority(param->priority);
    if (ret < 0) {
        tloge("failed to set drv server priority\n");
        return;
    }

    ret = call_drv_init_func(drv_name, drv_func);
    if (ret != 0)
        return;

    ret = multi_drv_framwork_init(param->thread_limit - 1, param->stack_size, ch);
    if (ret != 0) {
        tloge("multi drv framework init fail\n");
        return;
    }

    ret = send_succ_msg_to_drvmgr();
    if (ret != 0)
        return;

    tlogi("%s start server loop\n", drv_name);
    cs_server_loop(ch, dispatch_fns, ARRAY_SIZE(dispatch_fns), NULL, NULL);
}
