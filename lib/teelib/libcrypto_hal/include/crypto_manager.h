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
#ifndef CRYPTO_MANAGER_H
#define CRYPTO_MANAGER_H

#include <crypto_driver_adaptor.h>

#define TEE_CRYPTO_DRIVER_NAME   "crypto_mgr"

uint32_t crypto_get_default_engine(uint32_t algorithm);

uint32_t crypto_get_default_generate_key_engine(uint32_t algorithm);

int32_t crypto_driver_get_ctx_size(uint32_t alg_type, int64_t fd);
int32_t crypto_driver_get_driver_ability(int64_t fd);

int32_t crypto_driver_ctx_copy(const struct ctx_handle_t *src_ctx, struct ctx_handle_t *dest_ctx);


int32_t crypto_driver_hash_init(struct ctx_handle_t *ctx);

int32_t crypto_driver_hash_update(struct ctx_handle_t *ctx, const struct memref_t *data_in);

int32_t crypto_driver_hash_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out);

int32_t crypto_driver_hash(uint32_t alg_type, const struct memref_t *data_in,
    struct memref_t *data_out, uint32_t engine);

int32_t crypto_driver_hmac_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key);

int32_t crypto_driver_hmac_update(struct ctx_handle_t *ctx, const struct memref_t *data_in);

int32_t crypto_driver_hmac_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out);

int32_t crypto_driver_hmac(uint32_t alg_type, const struct symmerit_key_t *key,
    const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine);

int32_t crypto_driver_cipher_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key,
    const struct memref_t *iv);

int32_t crypto_driver_cipher_update(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out);

int32_t crypto_driver_cipher_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out);

int32_t crypto_driver_cipher(uint32_t alg_type, uint32_t direction, const struct symmerit_key_t *key,
    const struct memref_t *iv, const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine);

int32_t crypto_driver_ae_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key,
    const struct ae_init_data *ae_init_param);

int32_t crypto_driver_ae_update_aad(struct ctx_handle_t *ctx, const struct memref_t *aad_data);

int32_t crypto_driver_ae_update(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out);

int32_t crypto_driver_ae_enc_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out, struct memref_t *tag_out);

int32_t crypto_driver_ae_dec_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    const struct memref_t *tag_in, struct memref_t *data_out);

int32_t crypto_driver_rsa_generate_keypair(uint32_t key_size, const struct memref_t *e_value, bool crt_mode,
    struct rsa_priv_key_t *key_pair, uint32_t engine);

int32_t crypto_driver_rsa_encrypt(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct asymmetric_params_t *rsa_params,
    const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine);

int32_t crypto_driver_rsa_decrypt(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
    const struct asymmetric_params_t *rsa_params,
    const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine);

int32_t crypto_driver_rsa_sign_digest(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
    const struct asymmetric_params_t *rsa_params,
    const struct memref_t *digest, struct memref_t *signature, uint32_t engine);

int32_t crypto_driver_rsa_verify_digest(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct asymmetric_params_t *rsa_params,
    const struct memref_t *digest, const struct memref_t *signature, uint32_t engine);

int32_t crypto_driver_ecc_generate_keypair(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key, uint32_t engine);

int32_t crypto_driver_ecc_encrypt(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params,
    const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine);

int32_t crypto_driver_ecc_decrypt(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params,
    const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine);

int32_t crypto_driver_ecc_sign_digest(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params,
    const struct memref_t *digest, struct memref_t *signature, uint32_t engine);

int32_t crypto_driver_ecc_verify_digest(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params,
    const struct memref_t *digest, const struct memref_t *signature, uint32_t engine);

int32_t crypto_driver_ecdh_derive_key(uint32_t alg_type,
    const struct ecc_pub_key_t *client_key, const struct ecc_priv_key_t *server_key,
    const struct asymmetric_params_t *ec_params, struct memref_t *secret, uint32_t engine);

int32_t crypto_driver_dh_generate_key(const struct dh_key_t *dh_generate_key_data,
    struct memref_t *pub_key, struct memref_t *priv_key, uint32_t engine);

int32_t crypto_driver_dh_derive_key(const struct dh_key_t *dh_derive_key_data,
    struct memref_t *secret, uint32_t engine);

int32_t crypto_driver_generate_random(void *buffer, uint32_t size, bool is_hw_rand);

int32_t crypto_driver_get_entropy(void *buffer, uint32_t size);

int32_t crypto_driver_derive_root_key(uint32_t derive_type,
    const struct memref_t *data_in, struct memref_t *data_out, uint32_t iter_num);

int32_t crypto_driver_pbkdf2(const struct memref_t *password, const struct memref_t *salt, uint32_t iterations,
    uint32_t digest_type, struct memref_t *data_out, uint32_t engine);

int32_t soft_random_get(uint8_t *trng_addr, uint32_t length);
int32_t tee_crypto_get_oemkey(void *buf, uint32_t size);
int32_t tee_crypto_check_alg_support(uint32_t alg_type);
#endif
