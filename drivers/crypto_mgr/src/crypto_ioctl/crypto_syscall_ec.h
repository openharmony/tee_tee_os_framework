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
#ifndef CRYPTO_SYSCALL_EC_H
#define CRYPTO_SYSCALL_EC_H

#include "crypto_syscall_common.h"

int32_t check_ecc_private_key_len(const struct ecc_priv_key_t *ecc_private_key);
int32_t check_ecc_pub_key_len(const struct ecc_pub_key_t *ecc_pub_key);
int32_t ecc_generate_keypair_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops);
int32_t ecc_encrypt_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops);
int32_t ecc_decrypt_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops);
int32_t ecc_sign_digest_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops);
int32_t ecc_verify_digest_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops);

#endif
