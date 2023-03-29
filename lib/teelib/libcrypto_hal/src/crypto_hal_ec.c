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

#include "crypto_hal_ec.h"
#include <tee_log.h>
#include <tee_crypto_hal.h>
#include "crypto_manager.h"
#include "soft_ec_api.h"

#define BITS_OF_BYTE 8

int32_t tee_crypto_ecc_generate_keypair(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key, uint32_t engine)
{
    if ((public_key == NULL) || (private_key == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (engine == SOFT_CRYPTO) {
        public_key->x_len = sizeof(public_key->x);
        public_key->y_len = sizeof(public_key->y);
        private_key->r_len = sizeof(private_key->r);
        return soft_crypto_ecc_generate_keypair(key_size, curve, public_key, private_key);
    }

    public_key->x_len = key_size / BITS_OF_BYTE;
    public_key->y_len = key_size / BITS_OF_BYTE;
    private_key->r_len = key_size / BITS_OF_BYTE;

    return crypto_driver_ecc_generate_keypair(key_size, curve, public_key, private_key, engine);
}

int32_t tee_crypto_ecc_encrypt(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *data_in,
    struct memref_t *data_out, uint32_t engine)
{
    if ((public_key == NULL) || (data_in == NULL) || (data_out == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (engine == SOFT_CRYPTO)
        return soft_crypto_ecc_encrypt(alg_type, public_key, ec_params, data_in, data_out);
    return crypto_driver_ecc_encrypt(alg_type, public_key, ec_params, data_in, data_out, engine);
}

int32_t tee_crypto_ecc_decrypt(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *data_in,
    struct memref_t *data_out, uint32_t engine)
{
    if ((private_key == NULL) || (data_in == NULL) || (data_out == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (engine == SOFT_CRYPTO)
        return soft_crypto_ecc_decrypt(alg_type, private_key, ec_params, data_in, data_out);
    return crypto_driver_ecc_decrypt(alg_type, private_key, ec_params, data_in, data_out, engine);
}

int32_t tee_crypto_ecc_sign_digest(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *digest,
    struct memref_t *signature, uint32_t engine)
{
    if ((private_key == NULL) || (digest == NULL) || (signature == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (engine == SOFT_CRYPTO)
        return soft_crypto_ecc_sign_digest(alg_type, private_key, ec_params, digest, signature);
    return crypto_driver_ecc_sign_digest(alg_type, private_key, ec_params, digest, signature, engine);
}

int32_t tee_crypto_ecc_verify_digest(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *digest,
    const struct memref_t *signature, uint32_t engine)
{
    if ((public_key == NULL) || (digest == NULL) || (signature == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (engine == SOFT_CRYPTO)
        return soft_crypto_ecc_verify_digest(alg_type, public_key, ec_params, digest, signature);
    return crypto_driver_ecc_verify_digest(alg_type, public_key, ec_params, digest, signature, engine);
}
