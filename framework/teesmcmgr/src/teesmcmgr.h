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
#ifndef TEESMCMGR_H
#define TEESMCMGR_H

#include <stdint.h>
#include <tee_log.h>
#include <stdbool.h>
#include <ipclib.h>
#include <priorities.h>
#define SMCMGR_STACK_SIZE  0x2000

#define PAY_LOAD_SIZE 24
#define MAGIC_MSG "IDLE_0xDEADBEEF"

#define panic(fmt...)                             \
    do {                                          \
        tee_abort(fmt);                           \
    } while (0)
#define error(fmt...)                             \
    do {                                          \
        tloge(fmt);                               \
    } while (0)
#define info(fmt...)                              \
    do {                                          \
        tlogi(fmt);                               \
    } while (0)
#define debug(fmt...)                             \
    do {                                          \
        tlogd(fmt);                               \
    } while (0)

void *tee_idle_thread(void *arg);
void *tee_smc_thread(void *arg);

cref_t acquire_gtask_channel(void);

void set_gtask_channel_hdlr(cref_t value);
void set_is_gtask_alive(bool value);

cref_t get_gtask_channel_hdlr(void);
bool   get_is_gtask_alive(void);

#endif
