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

#ifndef CRYPTO_HAL_DERIVE_KEY_H
#define CRYPTO_HAL_DERIVE_KEY_H

#include <crypto_driver_adaptor.h>

int32_t tee_crypto_dh_generate_key(const struct dh_key_t *dh_generate_key_data,
    struct memref_t *pub_key, struct memref_t *priv_key, uint32_t engine);
int32_t tee_crypto_dh_derive_key(const struct dh_key_t *dh_derive_key_data, struct memref_t *secret, uint32_t engine);
int32_t tee_crypto_ecdh_derive_key(uint32_t alg_type, const struct ecc_pub_key_t *client_key,
    const struct ecc_priv_key_t *server_key, const struct asymmetric_params_t *ec_params,
    struct memref_t *secret, uint32_t engine);
int32_t tee_crypto_derive_root_key(uint32_t derive_type, const struct memref_t *data_in,
    struct memref_t *data_out, uint32_t iter_num);
int32_t tee_crypto_pbkdf2_derive_key(const struct memref_t *password, const struct memref_t *salt,
    uint32_t iterations, uint32_t digest_type, struct memref_t *data_out, uint32_t engine);
#endif
