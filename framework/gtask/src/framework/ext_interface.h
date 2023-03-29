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
#ifndef GTASK_EXT_INTERFACE_H
#define GTASK_EXT_INTERFACE_H

#include <stdint.h>
#include "ta_framework.h"
#include "tee_defines.h"

TEE_Result map_rdr_mem(const smc_cmd_t *cmd);
int32_t handle_info_query(uint32_t cmd_id, uint32_t task_id,
    const uint8_t *msg_buf, uint32_t msg_size);

#endif /* GTASK_EXT_INTERFACE_H */
