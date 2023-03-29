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
#ifndef GTASK_TEE_LOAD_KEYOPS_H
#define GTASK_TEE_LOAD_KEYOPS_H

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "tee_defines.h"
#include "ta_load_key.h"

RSA *get_private_key(int32_t img_version, enum ta_type type);
void free_private_key(RSA *priv_key);

TEE_Result tee_secure_ta_release_verify(const uint8_t *hash, uint32_t hash_size, const uint8_t *signature,
                                        uint32_t signature_size);
TEE_Result tee_secure_img_hash_ops(const uint8_t *hash_context, size_t context_size, uint8_t *hash_result,
                                   size_t hash_result_size);
#endif
