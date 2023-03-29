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
#ifndef GTASK_TEE_APP_LOAD_SRV_H
#define GTASK_TEE_APP_LOAD_SRV_H

#include <ta_lib_img_unpack.h>
#include "tee_defines.h"
#include "ta_framework.h"
#include <openssl/rsa.h>

TEE_Result load_secure_file_image(const smc_cmd_t *cmd, bool *async);
TEE_Result need_load_app(const smc_cmd_t *cmd);
void free_img_load_buf(void);
TEE_Result rename_tmp_file(const char *new_name, uint32_t len);
int32_t process_register_elf_req(uint32_t cmd_id, uint32_t task_id, const uint8_t *msg_buf, uint32_t msg_size);
void elf_verify_crash_callback(void);
#endif
