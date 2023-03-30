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
#include <ipclib.h>
#include <drv.h>
#include <fileio.h>
#include <timer.h>
#include <inttypes.h>
#include <tee_log.h>
#include <usrsyscall_irq.h>
#include "teesmcmgr.h"
#include "tee_crypto_api.h"
#include "global_task.h"
#include "init.h"
#include <sched.h>

#define GT_CHANNEL_NUM 2

static void wait_for_kill(void)
{
    while (true)
        (void)sched_yield();
}

static void gtask_init(void)
{
    int32_t ret;
    struct reg_items_st reg_items = { true, true, true };

    ret = ipc_create_channel("TEEGlobalTask", GT_CHANNEL_NUM, NULL, reg_items);
    if (ret != 0) {
        tloge("GTASK: create ipc chnl failed: %d\n", ret);
        wait_for_kill();
    }

    ret = init_main();
    if (ret != 0) {
        tloge("GTASK: init failed: %d\n", ret);
        wait_for_kill();
    }
}

static void gtask_init_fileio(void)
{
    int32_t ret;

    ret = fileio_init();
    if (ret != 0) {
        tloge("GTASK: fileio_init failed: %d\n", ret);
        wait_for_kill();
    }
}

static void gtask_init_timer_irqmgr(void)
{
    init_sysctrl_hdlr();
#if (!defined CONFIG_OFF_DRV_TIMER)
    int32_t ret;

    ret = tee_timer_init();
    if (ret != 0) {
        tloge("GTASK: tee_timer_init failed: %d\n", ret);
        wait_for_kill();
    }
#endif
}

static void gtask_set_priority(void)
{
    int32_t ret;
    ret = set_priority(PRIO_TEE_GT);
    if (ret < 0) {
        tee_abort("GTASK: failed to set priority to PRIO_TEE_GT: %x\n", ret);
        wait_for_kill();
    }
}

static void gtask_run_and_destory(void)
{
    /* smcmgr threads must be created after setting stack guard */
    gtask_set_priority();

    gtask_main();

    tloge("Gtask error. teesmcmgr error is expected\n");
    init_shell();
}

int main(void)
{
    tlogi("GTASK: Starting up...\n");

    /*
     * gtask will init something :
     * hm_mmgr_client, cs_client, ipc_channels, main, ccmgr
     */
    gtask_init();

    gtask_init_timer_irqmgr();

    gtask_init_fileio();

    /*
     * gtask will set affinity to use all cpus
     * gtask will set high priority
     * gtask will extend utable to use more utilities
     * use gtask_main to run
     * finally gtask will destory itself
     */
    gtask_run_and_destory();

    return 0;
}
