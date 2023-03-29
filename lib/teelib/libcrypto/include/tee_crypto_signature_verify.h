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

#ifndef TEE_CRYPTO_SIGNATURE_VERIFY_H
#define TEE_CRYPTO_SIGNATURE_VERIFY_H

#include <openssl/rsa.h>
#include <crypto_wrapper.h>
#include <tee_crypto_api.h>

uint32_t get_effective_size(const uint8_t *buff, uint32_t len);
TEE_Result tee_secure_img_release_verify(const uint8_t *hash, uint32_t hash_size, const uint8_t *signature,
    uint32_t signature_size, RSA *pub_key);
RSA *rsa_build_public_key(const rsa_pub_key_t *pub_key);

#endif
