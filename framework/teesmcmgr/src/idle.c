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
#include <securec.h>
#include "teesmcmgr.h"
#include <usrsyscall_smc.h>
#include <ipclib.h>
#include <sched.h>

#define GTASK_MSG_ID 0xDEADBEEF
#define RECV_BUF_SIZE 32

struct gtask_msg {
    uint32_t msg_id;
    char payload[PAY_LOAD_SIZE];
} __attribute__((packed));

const char *g_debug_prefix = "teesmcmgr";
static bool g_tz_started;
static bool g_send_to_gtask = false;

static void send_to_gtask(void)
{
    if (g_send_to_gtask)
        return;

    int32_t err;
    struct gtask_msg gtask_msg;
    static const char magic_msg[] = MAGIC_MSG;
    char recv_buf[RECV_BUF_SIZE] = {0};
    gtask_msg.msg_id = GTASK_MSG_ID;
    errno_t ret_s = memcpy_s(gtask_msg.payload, sizeof(gtask_msg.payload), magic_msg, sizeof(magic_msg));
    if (ret_s != EOK)
        panic("memory copy failed\n");

    /*
     * Why we need this ipc_msg_call?
     * As smcmgr send notification to gtask after check smc.ops is valid,
     * but the first normal request 'set smc buffer' is send by raw_smc_send
     * that smc.ops is set to be smc buffer's physical addr.
     */
    err = ipc_msg_call(get_gtask_channel_hdlr(), &gtask_msg, sizeof(struct gtask_msg), recv_buf, sizeof(recv_buf), -1);
    if (err < 0)
        panic("failed to send magic to gtask: %x\n", err);
    debug("GT return %d\n", err);

    g_send_to_gtask = true;
}

static void starttz_core(void)
{
    g_tz_started = true;
    int32_t err = smc_switch_req(CAP_TEESMC_REQ_STARTTZ);
    if (err < 0)
        panic("starttz failed: %x\n", err);

    send_to_gtask();
}

__attribute__((noreturn)) void *tee_idle_thread(void *arg)
{
    (void)arg;

    int32_t err = set_priority(HM_PRIO_TEE_SMCMGR_IDLE);
    if (err < 0)
        panic("api set priority failed: %x\n", err);
    (void)sched_yield();

    starttz_core();
    error("StartTZ done\n");

    while (1) {
        debug("calling smc_switch_req\n");
        err = smc_switch_req(CAP_TEESMC_REQ_IDLE);
        debug("smc_switch_req return err=%x\n", err);
        if (err != 0)
            panic("something wrong");
    }
}
