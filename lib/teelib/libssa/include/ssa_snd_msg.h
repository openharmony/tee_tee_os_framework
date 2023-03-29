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
#ifndef SSA_MSG_H
#define SSA_MSG_H
#include "stdint.h"

#define SSA_SERVICE_PATH "ssa_service"
#define MSG_MAX_LEN 128

struct msg_st {
    uint32_t msg_id;
    char payload[MSG_MAX_LEN];
} __attribute__((__packed__));

uint32_t send_msg_to_ssa(uint32_t cmd_id, const void *msg, uint32_t msg_size);
#endif
