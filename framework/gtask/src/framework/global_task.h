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

#ifndef GLOBAL_TASK_H
#define GLOBAL_TASK_H

#include "ta_framework.h"
#include "gtask_inner.h"

void gtask_main(void);
int put_last_out_cmd(const smc_cmd_t *cmd);
TEE_Result get_tee_version(const smc_cmd_t *cmd);
TEE_Result process_load_image(smc_cmd_t *cmd, bool *async);
TEE_Result process_ta_common_cmd(smc_cmd_t *cmd, uint32_t cmd_type, uint32_t task_id, bool *async,
                                 const struct ta2ta_info_t *ta2ta_info);
TEE_Result handle_time_adjust(const smc_cmd_t *cmd);
void ns_cmd_response(smc_cmd_t *cmd);
bool is_abort_cmd(const smc_cmd_t *cmd);
void restore_cmd_in(const smc_cmd_t *cmd);

#endif
