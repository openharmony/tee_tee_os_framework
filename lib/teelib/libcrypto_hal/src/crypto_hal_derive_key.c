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

#include "crypto_hal_derive_key.h"
#include <securec.h>
#include <tee_log.h>
#include <tee_crypto_hal.h>
#include "crypto_manager.h"
#include "soft_derive_key_api.h"

int32_t tee_crypto_dh_generate_key(const struct dh_key_t *dh_generate_key_data,
    struct memref_t *pub_key, struct memref_t *priv_key, uint32_t engine)
{
    if ((dh_generate_key_data == NULL) || (pub_key == NULL) || (priv_key == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    return crypto_driver_dh_generate_key(dh_generate_key_data, pub_key, priv_key, engine);
}

int32_t tee_crypto_dh_derive_key(const struct dh_key_t *dh_derive_key_data, struct memref_t *secret, uint32_t engine)
{
    if ((dh_derive_key_data == NULL) || (secret == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    return crypto_driver_dh_derive_key(dh_derive_key_data, secret, engine);
}

int32_t tee_crypto_ecdh_derive_key(uint32_t alg_type, const struct ecc_pub_key_t *client_key,
    const struct ecc_priv_key_t *server_key, const struct asymmetric_params_t *ec_params,
    struct memref_t *secret, uint32_t engine)
{
    if ((client_key == NULL) || (server_key == NULL) || (secret == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (engine == SOFT_CRYPTO)
        return soft_crypto_ecdh_derive_key(alg_type, client_key, server_key, ec_params, secret);
    return crypto_driver_ecdh_derive_key(alg_type, client_key, server_key, ec_params, secret, engine);
}

int32_t tee_crypto_derive_root_key(uint32_t derive_type, const struct memref_t *data_in,
    struct memref_t *data_out, uint32_t iter_num)
{
    if ((data_in == NULL) || (data_out == NULL) || (iter_num == 0)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
#if defined (CONFIG_NO_PLAT_ROOT_KEY)
    (void)derive_type;
    if (data_out->buffer == 0) {
        tloge("data_out Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    (void)memset_s((void *)(uintptr_t)data_out->buffer, data_out->size, 0xFF, data_out->size);
    return CRYPTO_SUCCESS;
#else
    return crypto_driver_derive_root_key(derive_type, data_in, data_out, iter_num);
#endif
}

int32_t tee_crypto_pbkdf2_derive_key(const struct memref_t *password, const struct memref_t *salt,
    uint32_t iterations, uint32_t digest_type, struct memref_t *data_out, uint32_t engine)
{
    if ((password == NULL) || (salt == NULL) || (data_out == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (engine == SOFT_CRYPTO)
        return soft_crypto_pbkdf2(password, salt, iterations, digest_type, data_out);
    return crypto_driver_pbkdf2(password, salt, iterations, digest_type, data_out, engine);
}
