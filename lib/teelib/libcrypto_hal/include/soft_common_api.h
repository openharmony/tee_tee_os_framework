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
#ifndef _SOFT_COMMON_API_H
#define _SOFT_COMMON_API_H

#include <crypto_inner_defines.h>
#include "crypto_driver_adaptor.h"

#define AES_MAX_IV_SIZE              16
#define AES_TEN_ROUNDS_KEY_SIZE      16
#define AES_TWELVE_ROUNDS_KEY_SIZE   24
#define AES_FOURTEEN_ROUNDS_KEY_SIZE 32
#define SM4_GCM_KEY_SIZE             16
#define AES_MAX_KEY_SIZE             64
#define DES_KEY_SIZE                 8
#define DES3_KEY_SIZE                24
#define ARRAY_NUM(array)             (sizeof(array) / sizeof((array)[0]))
#define ED25519_SIGN_LEN             64
#define X25519_SHARE_KEY_LEN         32
#define SHARE_KEY_MAX_LEN            128
#define BORINGSSL_OK                 1
#define BORINGSSL_ERR                0
#define AES_CCM_MAX_TAG_LEN          16
#define AES_MODE_ENCRYPT             1
#define AES_MODE_DECRYPT             0
#define SOFT_NUMBER_TWO              2
#define OPENSSL_OK                   1
#define MD5_LEN                      16
#define SHA1_LEN                     20
#define SHA224_LEN                   28
#define SHA256_LEN                   32
#define SHA384_LEN                   48
#define SHA512_LEN                   64
#define MAX_VALID_ALGO_SIZE          32
#define CRYPTO_TYPE_DIGEST           0x50000000
#define CRYPTO_TYPE_HMAC             0x30000000
#define CRYPTO_TYPE_CIPHER           0x10000000
#define CRYPTO_TYPE_AES_MAC          0x30000010
#define CRYPTO_TYPE_AES              0x40000000
#define TEE_PARAM_MAX                9

int32_t check_params(const struct asymmetric_params_t *params);
int32_t check_valid_algorithm(uint32_t algorithm, const uint32_t *array, uint32_t array_size);
uint32_t get_hash_context_size(uint32_t algorithm);
void free_cipher_context(uint64_t *ctx);
void free_hmac_context(uint64_t *ctx);
int32_t soft_crypto_ctx_copy(const struct ctx_handle_t *src_ctx, struct ctx_handle_t *dest_ctx);
int32_t get_boring_nid_by_tee_curve(uint32_t tee_domain, uint32_t *nid);
int32_t get_openssl_rand(unsigned char *buf, int num);
#ifdef OPENSSL_ENABLE
void free_openssl_drbg_mem(void);
#endif
#endif
