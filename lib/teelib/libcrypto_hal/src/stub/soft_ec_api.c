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

#include "soft_ec_api.h"
#include "crypto_inner_interface.h"
#include "soft_common_api.h"

int32_t soft_crypto_ecc_generate_keypair(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key)
{
    (void)key_size;
    (void)curve;
    (void)public_key;
    (void)private_key;
    return CRYPTO_NOT_SUPPORTED;
}

int32_t soft_crypto_ecc_encrypt(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)alg_type;
    (void)public_key;
    (void)ec_params;
    (void)data_in;
    (void)data_out;
    return CRYPTO_NOT_SUPPORTED;
}


int32_t soft_crypto_ecc_decrypt(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)alg_type;
    (void)private_key;
    (void)ec_params;
    (void)data_in;
    (void)data_out;
    return CRYPTO_NOT_SUPPORTED;
}

int32_t soft_crypto_ecc_sign_digest(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *digest,
    struct memref_t *signature)
{
    (void)alg_type;
    (void)private_key;
    (void)ec_params;
    (void)digest;
    (void)signature;
    return CRYPTO_NOT_SUPPORTED;
}

int32_t soft_crypto_ecc_verify_digest(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *digest,
    const struct memref_t *signature)
{
    (void)alg_type;
    (void)public_key;
    (void)ec_params;
    (void)digest;
    (void)signature;
    return CRYPTO_NOT_SUPPORTED;
}
