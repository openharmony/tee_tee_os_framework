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
#ifndef GTASK_TEE_TAK_H
#define GTASK_TEE_TAK_H
#include <stdint.h>
#include "ta_framework.h"

#define NORMAL_FAIL_RET  (-1)
#define TIMEOUT_FAIL_RET (-2)
#define SUCC_RET         0

#define ARG_NUM 4
#define ARGV_SIZE         64
#define ARGV0_SIZE        100
#define ARGV2_SIZE        8

struct tsk_init_param {
    uint16_t task_prior;       /* task prior */
    uint16_t que_num;          /* msg queue number */
    uint32_t args[ARG_NUM];    /* param number */
    const char *task_name;     /* task name */
    uint32_t reserved;
    uint32_t private_data;     /* private data of task */
    uint32_t usr_space_num;
    uint64_t perm;             /* Permission bit field */
    uint32_t srvc_provider_id; /* Service Provider ID */
    struct tee_uuid uuid;
};

struct msg_recv_param {
    uint32_t msghandle;
    uint32_t msg_id;
};

int sre_task_create(const struct tsk_init_param *init_param, uint32_t *task_id);
int32_t sre_task_delete_ex(uint32_t uw_task_pid, bool is_service_dead, uint32_t session_id);
#endif /* GTASK_TEE_TAK_H */
