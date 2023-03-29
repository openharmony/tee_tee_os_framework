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

#ifndef TEE_S_CMD_DISPATCH_H
#define TEE_S_CMD_DISPATCH_H

#include <stdint.h>

typedef int32_t (*proc_func)(uint32_t cmd_id, uint32_t task_id,
    const uint8_t *msg_buf, uint32_t msg_size);

struct s_cmd_proc_t {
    uint32_t cmd_id;
    proc_func func;
};

int32_t handle_s_cmd(uint32_t cmd_id, uint32_t task_id, const uint8_t *msg_buf, uint32_t msg_size);

#endif
