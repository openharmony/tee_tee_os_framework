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

#include "crypto_hal_rsa.h"
#include <tee_log.h>
#include <tee_crypto_hal.h>
#include "crypto_manager.h"
#include "soft_rsa_api.h"

#define HALF_LENGTH  2
#define MAX_KEY_SIZE 512
#define BITS_OF_BYTE 8

int32_t tee_crypto_rsa_generate_keypair(uint32_t key_size, const struct memref_t *e_value, bool crt_mode,
    struct rsa_priv_key_t *key_pair, uint32_t engine)
{
    if ((e_value == NULL) || (key_pair == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    key_pair->e_len = e_value->size;
    key_pair->n_len = key_size;
    key_pair->d_len = key_size;
    key_pair->p_len = key_size / HALF_LENGTH;
    key_pair->q_len = key_size / HALF_LENGTH;
    key_pair->dp_len = key_size / HALF_LENGTH;
    key_pair->dq_len = key_size / HALF_LENGTH;
    key_pair->qinv_len = key_size / HALF_LENGTH;

    if (engine == SOFT_CRYPTO)
        return soft_crypto_rsa_generate_keypair(key_size, e_value, crt_mode, key_pair);

    if (key_size > MAX_KEY_SIZE) {
        tloge("key is too long\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    key_size *= BITS_OF_BYTE;
    return crypto_driver_rsa_generate_keypair(key_size, e_value, crt_mode, key_pair, engine);
}

int32_t tee_crypto_rsa_encrypt(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *data_in,
    struct memref_t *data_out, uint32_t engine)
{
    bool check = ((public_key == NULL) || (data_in == NULL) || (data_out == NULL));
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (engine == SOFT_CRYPTO)
        return soft_crypto_rsa_encrypt(alg_type, public_key, rsa_params, data_in, data_out);
    return crypto_driver_rsa_encrypt(alg_type, public_key, rsa_params, data_in, data_out, engine);
}

int32_t tee_crypto_rsa_decrypt(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *data_in,
    struct memref_t *data_out, uint32_t engine)
{
    if ((private_key == NULL) || (data_in == NULL) || (data_out == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (engine == SOFT_CRYPTO)
        return soft_crypto_rsa_decrypt(alg_type, private_key, rsa_params, data_in, data_out);
    return crypto_driver_rsa_decrypt(alg_type, private_key, rsa_params, data_in, data_out, engine);
}

int32_t tee_crypto_rsa_sign_digest(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *digest,
    struct memref_t *signature, uint32_t engine)
{
    if ((private_key == NULL) || (digest == NULL) || (signature == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (engine == SOFT_CRYPTO)
        return soft_crypto_rsa_sign_digest(alg_type, private_key, rsa_params, digest, signature);
    return crypto_driver_rsa_sign_digest(alg_type, private_key, rsa_params, digest, signature, engine);
}

int32_t tee_crypto_rsa_verify_digest(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *digest,
    const struct memref_t *signature, uint32_t engine)
{
    if ((public_key == NULL) || (digest == NULL) || (signature == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (engine == SOFT_CRYPTO)
        return soft_crypto_rsa_verify_digest(alg_type, public_key, rsa_params, digest, signature);
    return crypto_driver_rsa_verify_digest(alg_type, public_key, rsa_params, digest, signature, engine);
}
