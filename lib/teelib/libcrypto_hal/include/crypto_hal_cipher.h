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
#ifndef CRYPTO_HAL_CIPHER_H
#define CRYPTO_HAL_CIPHER_H

#include <crypto_driver_adaptor.h>

struct ctx_handle_t *tee_crypto_cipher_init(uint32_t alg_type, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv, uint32_t engine);
int32_t tee_crypto_cipher_update(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out);
int32_t tee_crypto_cipher_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out);
int32_t tee_crypto_cipher(uint32_t alg_type, uint32_t direction, const struct symmerit_key_t *key,
    const struct memref_t *iv, const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine);

#endif
