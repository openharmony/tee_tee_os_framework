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
#ifndef __SOFT_GMSSL_H__
#define __SOFT_GMSSL_H__

#include <tee_defines.h>
#include <crypto_driver_adaptor.h>
#include <openssl/evp.h>

int32_t sm3_digest_init(struct ctx_handle_t *ctx);

int32_t sm3_digest_update(struct ctx_handle_t *ctx, const struct memref_t *data_in);

int32_t sm3_digest_dofinal(struct ctx_handle_t *ctx, struct memref_t *data_out);

int32_t crypto_sm3_hash(const struct memref_t *data_in, struct memref_t *data_out);

int32_t sm3_mac_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key);

int32_t sm3_mac_update(struct ctx_handle_t *ctx, const struct memref_t *data_in);

int32_t sm3_mac_computefinal(struct ctx_handle_t *ctx, struct memref_t *data_out);

int32_t crypto_sm3_hmac(const struct symmerit_key_t *key, const struct memref_t *data_in, struct memref_t *data_out);

int32_t sm2_sign_verify(const void *sm2_key, uint32_t mode, const struct memref_t *digest,
    struct memref_t *signature);

int32_t sm2_encrypt_decypt(const void *sm2_key, uint32_t mode,
    const struct memref_t *data_in, struct memref_t *data_out);

int32_t sm4_cipher_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key, const struct memref_t *iv);

int32_t sm4_cipher_update(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out);

int32_t sm4_cipher_do_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out);

int32_t sm2_generate_keypair(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key);

int32_t soft_copy_gmssl_info(struct ctx_handle_t *dest, const struct ctx_handle_t *src);

void free_sm4_context(uint64_t *ctx);

#endif
