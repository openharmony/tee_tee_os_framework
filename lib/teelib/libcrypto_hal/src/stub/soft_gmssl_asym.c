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

#include "../boringssl/soft_gmssl.h"

int32_t sm4_cipher_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key, const struct memref_t *iv)
{
    (void)ctx;
    (void)key;
    (void)iv;
    return CRYPTO_NOT_SUPPORTED;
}

int32_t sm4_cipher_update(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    (void)ctx;
    (void)data_in;
    (void)data_out;
    return CRYPTO_NOT_SUPPORTED;
}

int32_t sm4_cipher_do_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    (void)ctx;
    (void)data_in;
    (void)data_out;
    return CRYPTO_NOT_SUPPORTED;
}
