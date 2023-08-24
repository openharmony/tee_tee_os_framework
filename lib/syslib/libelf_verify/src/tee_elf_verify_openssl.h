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
#ifndef TEE_ELF_VERIFY_OPENSSL_H
#define TEE_ELF_VERIFY_OPENSSL_H

#include "tee_defines.h"
#include "tee_perm_img.h"
#include "ta_load_key.h"
#include <openssl/rsa.h>

#define AES_KEY_LEN         32
#define RSA_PRIV_SIZE       257
#define ECIES_PUB_LEN       65
#define ECIES_PRIV_LEN      32
#define ECIES_PRIV_ORIG_LEN 193

#define WITH_ZERO    65
#define WITHOUT_ZERO 64
#define RESULT1      320

struct rsa_priv_key {
    uint8_t p[RSA_PRIV_SIZE];
    uint32_t p_size;
    uint8_t q[RSA_PRIV_SIZE];
    uint32_t q_size;
    uint8_t dq[RSA_PRIV_SIZE];
    uint32_t dq_size;
    uint8_t dp[RSA_PRIV_SIZE];
    uint32_t dp_size;
    uint8_t qinv[RSA_PRIV_SIZE];
    uint32_t qinv_size;
    uint8_t d[WRAPPED_PUB_LEN_D];
    uint32_t d_size;
    uint8_t e[WRAPPED_PUB_LEN_E];
    uint32_t e_size;
};

struct ecc_derive_data_st {
    const uint8_t *ec1_priv;
    uint32_t ec1_len;
    const uint8_t *ec2_pub;
    uint32_t ec2_len;
};

TEE_Result tee_secure_img_decrypt_cipher_layer(const uint8_t *cipher_layer, uint32_t cipher_size,
    uint8_t *plaintext_layer, uint32_t *plaintext_size);
RSA *get_ta_verify_key(void);
int32_t aes_cbc_256_decrypt(const uint8_t *key, const uint8_t *iv,
    const uint8_t *in, uint32_t in_len, uint8_t *out);
int32_t ecies_kem_decrypt(const struct ecc_derive_data_st *ecc_data, uint8_t *key, uint32_t key_len);
const struct ecies_key_struct *get_ecies_key_data(int32_t img_version, enum ta_type type);
TEE_Result get_rsa_priv_aes_key(const struct ecies_key_struct *ecies_key_data, uint8_t *key_buff,
    uint32_t buff_size);
TEE_Result aes_decrypt_rsa_private(const struct ecies_key_struct *ecies_data, const uint8_t *aes_key,
    uint32_t key_size, struct rsa_priv_key *priv);
TEE_Result get_key_data(int32_t img_version, struct key_data *key_data);
#endif

