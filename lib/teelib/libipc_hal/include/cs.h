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
#ifndef __CS_H
#define __CS_H

#include <tee_msg_type.h>
#include <ipclib.h>
#include <stdint.h>
#include <stddef.h>
#include <semaphore.h>

#define CS_SERVER_MAX_MSG_LEN 2048

struct cs_req_msg {
    msg_header hdr;
    char payload[];
} __attribute__((__packed__));

struct reply_cs_msg {
    msg_header hdr;
} __attribute__((__packed__));

struct thread_init_info {
    cref_t channel;
    void *(*func)(void *arg);
    uint32_t max_thread;
    sem_t *thread_sem;
    int32_t capid;
    int32_t task_id;
    int32_t shadow;
    size_t stack_size;
    void* args;
};

typedef intptr_t (*dispatch_fn_t)(void *msg, cref_t *p_msg_hdl, struct src_msginfo *info);

void cs_server_loop(cref_t channel, const dispatch_fn_t dispatch_fns[], unsigned n_dispatch_fns, int (*hook)(void), void *cur_thread);

#endif
