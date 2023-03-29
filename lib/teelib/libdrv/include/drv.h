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

#ifndef LIBDRV_DRV_H
#define LIBDRV_DRV_H

#include <ipclib.h>
#include "tee_msg_type.h"
#define MAX_ARGS 16

#ifndef SYSCALL_DATA_MAX
#define SYSCALL_DATA_MAX 512
#define SYSCAL_MSG_BUFFER_SIZE 2048
#endif

struct drv_req_msg_t {
    msg_header header;
    uint64_t args[MAX_ARGS];
    cref_t job_handler;
    char data[];
} __attribute__((__packed__));

struct drv_reply_msg_t {
    msg_header header;
    uint64_t __rsvd;
    char rdata[];
} __attribute__((__packed__));

struct drv_call_params {
    uint64_t *args;
    uint32_t *lens;
    int32_t nr;
    void *rdata;
    uint32_t rdata_len;
};

int32_t drv_init(const char *path);

int64_t drv_call_new(const char *name, uint16_t id, uint64_t *args, uint32_t *lens, int32_t nr);

#endif /* LIBDRV_DRV_H */
