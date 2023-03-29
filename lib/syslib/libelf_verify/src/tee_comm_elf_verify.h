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
#ifndef TEE_COMM_ELF_VERIFY_H
#define TEE_COMM_ELF_VERIFY_H

#include "tee_defines.h"
#include "tee_elf_verify.h"

TEE_Result tee_secure_img_header_check(uint32_t img_version);
TEE_Result tee_secure_img_unpack_v2(uint32_t rsa_algo_byte_len,
    uint32_t ta_hd_len, uint8_t *img_buf, uint32_t img_size, elf_hash_data *hash_data);
TEE_Result secure_img_copy_rsp_v2(elf_verify_reply *rep);
void free_verify_v2(void);

#endif

