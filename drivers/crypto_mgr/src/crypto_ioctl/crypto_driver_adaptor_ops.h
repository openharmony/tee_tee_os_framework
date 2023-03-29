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
#ifndef CRYPTO_DRIVER_ADAPTOR_OPS_H
#define CRYPTO_DRIVER_ADAPTOR_OPS_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "crypto_driver_adaptor.h"

struct crypto_drv_ops_t {
    int32_t (*init)(void);
    bool (*is_alg_support)(uint32_t alg_type);
    int32_t (*power_on)(void);
    int32_t (*power_off)(void);
    int32_t (*get_ctx_size)(uint32_t alg_type);
    int32_t (*ctx_copy)(uint32_t alg_type, const void *src_ctx, uint32_t src_size, void *dest_ctx, uint32_t dest_size);
    int32_t (*get_driver_ability)(void);
    int32_t (*hash_init)(void *ctx, uint32_t alg_type);
    int32_t (*hash_update)(void *ctx, const struct memref_t *data_in);
    int32_t (*hash_dofinal)(void *ctx, const struct memref_t *data_in, struct memref_t *data_out);
    int32_t (*hash)(uint32_t alg_type, const struct memref_t *data_in, struct memref_t *data_out);
    int32_t (*hmac_init)(uint32_t alg_type, void *ctx, const struct symmerit_key_t *key);
    int32_t (*hmac_update)(void *ctx, const struct memref_t *data_in);
    int32_t (*hmac_dofinal)(void *ctx, const struct memref_t *data_in, struct memref_t *data_out);
    int32_t (*hmac)(uint32_t alg_type, const struct symmerit_key_t *key,
        const struct memref_t *data_in, struct memref_t *data_out);
    int32_t (*cipher_init)(uint32_t alg_type, void *ctx, uint32_t direction,
        const struct symmerit_key_t *key, const struct memref_t *iv);
    int32_t (*cipher_update)(void *ctx, const struct memref_t *data_in, struct memref_t *data_out);
    int32_t (*cipher_dofinal)(void *ctx, const struct memref_t *data_in, struct memref_t *data_out);
    int32_t (*cipher)(uint32_t alg_type, uint32_t direction, const struct symmerit_key_t *key,
        const struct memref_t *iv, const struct memref_t *data_in, struct memref_t *data_out);
    int32_t (*ae_init)(uint32_t alg_type, void *ctx, uint32_t direction,
        const struct symmerit_key_t *key, const struct ae_init_data *ae_init_param);
    int32_t (*ae_update_aad)(void *ctx, const struct memref_t *aad_data);
    int32_t (*ae_update)(void *ctx, const struct memref_t *data_in, struct memref_t *data_out);
    int32_t (*ae_enc_final)(void *ctx, const struct memref_t *data_in,
        struct memref_t *data_out, struct memref_t *tag_out);
    int32_t (*ae_dec_final)(void *ctx, const struct memref_t *data_in, const struct memref_t *tag_in,
        struct memref_t *data_out);
    int32_t (*rsa_generate_keypair)(uint32_t key_size, const struct memref_t *e_value, bool crt_mode,
        struct rsa_priv_key_t *key_pair);
    int32_t (*rsa_encrypt)(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
        const struct asymmetric_params_t *rsa_params,
        const struct memref_t *data_in, struct memref_t *data_out);
    int32_t (*rsa_decrypt)(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
        const struct asymmetric_params_t *rsa_params,
        const struct memref_t *data_in, struct memref_t *data_out);
    int32_t (*rsa_sign_digest)(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
        const struct asymmetric_params_t *rsa_params,
        const struct memref_t *digest, struct memref_t *signature);
    int32_t (*rsa_verify_digest)(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
        const struct asymmetric_params_t *rsa_params,
        const struct memref_t *digest, const struct memref_t *signature);
    int32_t (*ecc_generate_keypair)(uint32_t keysize, uint32_t curve,
        struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key);
    int32_t (*ecc_encrypt)(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
        const struct asymmetric_params_t *ec_params,
        const struct memref_t *data_in, struct memref_t *data_out);
    int32_t (*ecc_decrypt)(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
        const struct asymmetric_params_t *ec_params,
        const struct memref_t *data_in, struct memref_t *data_out);
    int32_t (*ecc_sign_digest)(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
        const struct asymmetric_params_t *ec_params,
        const struct memref_t *digest, struct memref_t *signature);
    int32_t (*ecc_verify_digest)(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
        const struct asymmetric_params_t *ec_params,
        const struct memref_t *digest, const struct memref_t *signature);
    int32_t (*ecdh_derive_key)(uint32_t alg_type,
        const struct ecc_pub_key_t *client_key, const struct ecc_priv_key_t *server_key,
        const struct asymmetric_params_t *ec_params, struct memref_t *secret);
    int32_t (*dh_generate_key)(const struct dh_key_t *dh_generate_key_data,
        struct memref_t *pub_key, struct memref_t *priv_key);
    int32_t (*dh_derive_key)(const struct dh_key_t *dh_derive_key_data, struct memref_t *secret);
    int32_t (*generate_random)(void *buffer, size_t size);
    int32_t (*get_entropy)(void *buffer, size_t size);
    int32_t (*derive_root_key)(uint32_t derive_type, const struct memref_t *data_in,
        struct memref_t *data_out);
    int32_t (*pbkdf2)(const struct memref_t *password, const struct memref_t *salt, uint32_t iterations,
        uint32_t digest_type, struct memref_t *data_out);
    int32_t (*get_oemkey)(void *buffer, size_t size);
    int32_t (*suspend)(void);
    int32_t (*resume)(void);
};

#define crypto_driver_declare(init, is_alg_support, power_on, power_off, get_ctx_size, ctx_copy, get_driver_ability, \
    hash_init, hash_update, hash_dofinal, hash, hmac_init, hmac_update, hmac_dofinal, hmac, cipher_init, \
    cipher_update, cipher_dofinal, cipher, ae_init, ae_update_aad, ae_update, ae_enc_final, ae_dec_final, \
    rsa_generate_keypair, rsa_encrypt, rsa_decrypt, rsa_sign_digest, rsa_verify_digest, ecc_generate_keypair, \
    ecc_encrypt, ecc_decrypt, ecc_sign_digest, ecc_verify_digest, ecdh_derive_key, dh_generate_key, dh_derive_key, \
    generate_random, get_entropy, derive_root_key, pbkdf2, get_oemkey, suspend, resume) \
__attribute__((visibility("default"))) const struct crypto_drv_ops_t g_crypto_drv_ops = { \
    init, is_alg_support, power_on, power_off, get_ctx_size, ctx_copy, get_driver_ability, \
    hash_init, hash_update, hash_dofinal, hash, hmac_init, hmac_update, hmac_dofinal, hmac, cipher_init, \
    cipher_update, cipher_dofinal, cipher, ae_init, ae_update_aad, ae_update, ae_enc_final, ae_dec_final, \
    rsa_generate_keypair, rsa_encrypt, rsa_decrypt, rsa_sign_digest, rsa_verify_digest, ecc_generate_keypair, \
    ecc_encrypt, ecc_decrypt, ecc_sign_digest, ecc_verify_digest, ecdh_derive_key, dh_generate_key, dh_derive_key, \
    generate_random, get_entropy, derive_root_key, pbkdf2, get_oemkey, suspend, resume}

#endif
