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
#include "libdrv_frame.h"
#include <stdio.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <ipclib.h>
#include <fileio.h>
#include <timer.h>
#include <tee_tag.h>
#include <tee_drv_internal.h>
#include <ipclib_hal.h>
#include <tee_log.h>

#define IPC_CHANNEL_NUM 2

static int32_t ipc_init(const char *name, cref_t *ch)
{
    int32_t ret;
    struct reg_items_st reg_items = { true, false, false };

    ret = ipc_create_channel(NULL, IPC_CHANNEL_NUM, NULL, reg_items);
    if (ret != 0) {
        tloge("%s: failed to create SRE channel with pid %d: %d\n", name, getpid(), ret);
        return -1;
    }

    ret = ipc_create_channel_native(name, ch);
    if (ret != 0) {
        tloge("%s: failed to create channel :%d\n", name, ret);
        return -1;
    }

#ifndef CONFIG_TIMER_DISABLE
    ret = tee_timer_init();
    if (ret != 0) {
        tloge("%s :failed to init timer: %d\n", name, ret);
        return -1;
    }
#endif

    return 0;
}

static void print_drv_info(const char *name)
{
    printf(" _______________________________________________________\n");
    printf("|  _____________________________________________________\n");
    printf("| |\n");
    printf("| |  %s init - pid %d\n", name, getpid());
    printf("| |_____________________________________________________\n");
    printf("|_______________________________________________________\n");
}

static int32_t system_init(const char *name)
{
    int32_t ret;

    set_log_use_tid_flag();

    ret = tamgr_register(name);
    if (ret != 0) {
        tloge("%s: tamgr registration for platdrv failed\n", name);
        return -1;
    }

    return 0;
}

int32_t register_drv_framework(const struct drv_frame_t *drv_frame, cref_t *ch, bool new_frame)
{
    int32_t ret;

    if (drv_frame == NULL || drv_frame->name == NULL || ch == NULL) {
        tloge("invalid params\n");
        return -1;
    }

    print_drv_info(drv_frame->name);

    ret = ipc_init(drv_frame->name, ch);
    if (ret != 0)
        return ret;

    ret = system_init(drv_frame->name);
    if (ret != 0)
        return ret;

    if (!new_frame) {
        ret = drv_framework_init(drv_frame);
        if (ret != 0)
            return ret;
    }

    return 0;
}
