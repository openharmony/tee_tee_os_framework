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
#ifndef TEE_V3_ELF_VERIFY_H
#define TEE_V3_ELF_VERIFY_H

#include "tee_defines.h"
#include "tee_perm_img.h"
#include "tee_elf_verify.h"
#include "ta_load_key.h"
#include "tee_elf_verify_inner.h"

#define SIGN_SEC_ALG_ECDSA   1
#define SIGN_SEC_ALG_RSA     2
#define SIGN_SEC_ALG_DEFAULT 0
#define HASH_LEN_MAX 64

ta_cipher_layer_t *get_ta_cipher_layer(void);
TEE_Result process_header_v3(const uint8_t *share_buf, uint32_t buf_len);
TEE_Result judge_rsa_key_type(uint32_t rsa_cipher_size, enum ta_type *type);
TEE_Result secure_img_copy_rsp_v3(elf_verify_reply *rep);
void free_verify_v3();
TEE_Result tee_secure_img_unpack_v3(uint32_t rsa_algo_byte_len,
    uint32_t ta_hd_len, uint8_t *img_buf, uint32_t img_size, elf_hash_data *hash_data);
void get_sign_config(struct sign_config_t *config);
uint32_t get_v3_cipher_layer_len(void);
bool check_img_format_valid(struct sign_config_t *config);

#endif

