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
#include <inttypes.h>
#include <securec.h>
#include <ipclib.h>
#include <usrsyscall_smc.h>
#include <usrsyscall_irq.h>
#include "teesmcmgr.h"
#include <sched.h>

#define NORMAL_MSG_ID 0xDEADBEEF
#define SMC_BUF_OPS (-1ULL)

struct gtask_msg {
    uint32_t msg_id;
    union {
        char payload[PAY_LOAD_SIZE];
        uint64_t kill_ca;
    };
} __attribute__((packed));

static void teeapi_configure(void)
{
    int32_t err;

    err = set_priority(PRIO_TEE_SMCMGR);
    if (err < 0)
        panic("api set priority failed: %x\n", err);

    err = disable_local_irq();
    if (err < 0)
        panic("hmex disable local irq failed: %x\n", err);
}

__attribute__((noreturn)) void *tee_smc_thread(void *arg)
{
    (void)arg;
    int32_t err;
    errno_t ret_s;
    struct cap_teesmc_buf smc_buf = {0};
    struct gtask_msg normal_msg = {0};
    static const char magic_msg[] = MAGIC_MSG;

    normal_msg.msg_id = NORMAL_MSG_ID;
    ret_s = memcpy_s(normal_msg.payload, sizeof(normal_msg.payload), magic_msg, sizeof(magic_msg));
    if (ret_s != EOK)
        panic("memory copy failed\n");

    info("Start teesmc\n");
    teeapi_configure();
    (void)sched_yield();

    while (1) {
        debug("tee smc thread: wait for switch req\n");
        smc_buf.ops = SMC_BUF_OPS;
        err = smc_wait_switch_req(&smc_buf);
        debug("tee smc thread: return from REE, err=%d, ops=%" PRIx64 "\n", err, smc_buf.ops);

        if (err == 0) {
            if (get_is_gtask_alive() == 0)
                continue;

            err = 0;
            if (smc_buf.ops == CAP_TEESMC_OPS_NORMAL)
                err = ipc_msg_notification(get_gtask_channel_hdlr(), NULL, 0);

            if (err < 0)
                error("failed to notify gtask, err=0x%x\n", err);
        } else {
            error("unexpected err=%x\n", err);
        }
    }
}
