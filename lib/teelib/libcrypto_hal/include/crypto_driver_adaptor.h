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
#ifndef CRYPTO_DRIVER_ADAPTOR_H
#define CRYPTO_DRIVER_ADAPTOR_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define ENC_MODE             0x00
#define DEC_MODE             0x01
#define SIGN_MODE            0x02
#define VERIFY_MODE          0x03
#define DH_PKCS3_MODE        0x1
#define RSA_EXPONENT_LEN     4
#define RSA_MAX_KEY_SIZE     512
#define RSA_MAX_KEY_SIZE_CRT (RSA_MAX_KEY_SIZE / 2)
#define ECC_KEY_LEN          68
#define DRIVER_PADDING       0x00000001
#define DRIVER_CACHE         0x00000002
#define AES_MAC_LEN          16
#define CIPHER_CACHE_LEN     16

enum crypto_engine {
    DX_CRYPTO_FLAG,
    EPS_CRYPTO_FLAG,
    SOFT_CRYPTO_FLAG,
    SEC_CRYPTO_FLAG,
    CRYPTO_ENGINE_MAX_FLAG,
};

enum crypto_err {
    CRYPTO_NOT_SUPPORTED        = -1,
    CRYPTO_CIPHERTEXT_INVALID   = -2,
    CRYPTO_BAD_FORMAT           = -3,
    CRYPTO_BAD_PARAMETERS       = -4,
    CRYPTO_BAD_STATE            = -5,
    CRYPTO_SHORT_BUFFER         = -6,
    CRYPTO_OVERFLOW             = -7,
    CRYPTO_MAC_INVALID          = -8,
    CRYPTO_SIGNATURE_INVALID    = -9,
    CRYPTO_ERROR_SECURITY       = -10,
    CRYPTO_ERROR_OUT_OF_MEMORY  = -11,
    CRYPTO_SUCCESS              = 0,
};

enum crypto_alg_type {
    CRYPTO_TYPE_AES_ECB_NOPAD                      = 0x10000010,
    CRYPTO_TYPE_AES_CBC_NOPAD                      = 0x10000110,
    CRYPTO_TYPE_AES_ECB_PKCS5                      = 0x10000020,
    CRYPTO_TYPE_AES_CBC_PKCS5                      = 0x10000220,
    CRYPTO_TYPE_AES_CTR                            = 0x10000210,
    CRYPTO_TYPE_AES_CTS                            = 0x10000310,
    CRYPTO_TYPE_AES_XTS                            = 0x10000410,
    CRYPTO_TYPE_AES_OFB                            = 0x10000510,
    CRYPTO_TYPE_SM4_ECB                            = 0x10000014,
    CRYPTO_TYPE_SM4_CBC                            = 0x10000114,
    CRYPTO_TYPE_SM4_CBC_PKCS7                      = 0xF0000003,
    CRYPTO_TYPE_SM4_CTR                            = 0x10000214,
    CRYPTO_TYPE_SM4_CFB128                         = 0xF0000000,
    CRYPTO_TYPE_SM4_GCM                            = 0xF0000005,
    CRYPTO_TYPE_SM4_XTS                            = 0x10000414,
    CRYPTO_TYPE_SM4_OFB                            = 0x10000514,
    CRYPTO_TYPE_DES_ECB_NOPAD                      = 0x10000011,
    CRYPTO_TYPE_DES_CBC_NOPAD                      = 0x10000111,
    CRYPTO_TYPE_DES3_ECB_NOPAD                     = 0x10000013,
    CRYPTO_TYPE_DES3_CBC_NOPAD                     = 0x10000113,
    CRYPTO_TYPE_HMAC_MD5                           = 0x30000001,
    CRYPTO_TYPE_HMAC_SHA1                          = 0x30000002,
    CRYPTO_TYPE_HMAC_SHA224                        = 0x30000003,
    CRYPTO_TYPE_HMAC_SHA256                        = 0x30000004,
    CRYPTO_TYPE_HMAC_SHA384                        = 0x30000005,
    CRYPTO_TYPE_HMAC_SHA512                        = 0x30000006,
    CRYPTO_TYPE_HMAC_SM3                           = 0x30000007,
    CRYPTO_TYPE_AES_CMAC                           = 0x30000610,
    CRYPTO_TYPE_AES_CBC_MAC_NOPAD                  = 0x30000110,
    CRYPTO_TYPE_AES_CBC_MAC_PKCS5                  = 0x30000510,
    CRYPTO_TYPE_AES_GMAC                           = 0x30000810,
    CRYPTO_TYPE_DES_CBC_MAC_NOPAD                  = 0x30000111,
    CRYPTO_TYPE_DES3_CBC_MAC_NOPAD                 = 0x30000113,
    CRYPTO_TYPE_AES_CCM                            = 0x40000710,
    CRYPTO_TYPE_AES_GCM                            = 0x40000810,
    CRYPTO_TYPE_DIGEST_MD5                         = 0x50000001,
    CRYPTO_TYPE_DIGEST_SHA1                        = 0x50000002,
    CRYPTO_TYPE_DIGEST_SHA224                      = 0x50000003,
    CRYPTO_TYPE_DIGEST_SHA256                      = 0x50000004,
    CRYPTO_TYPE_DIGEST_SHA384                      = 0x50000005,
    CRYPTO_TYPE_DIGEST_SHA512                      = 0x50000006,
    CRYPTO_TYPE_DIGEST_SM3                         = 0x50000007,
    CRYPTO_TYPE_RSAES_PKCS1_V1_5                   = 0x60000130,
    CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA1         = 0x60210230,
    CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA224       = 0x60211230,
    CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA256       = 0x60212230,
    CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA384       = 0x60213230,
    CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA512       = 0x60214230,
    CRYPTO_TYPE_RSA_NO_PAD                         = 0x60000030,
    CRYPTO_TYPE_SM2_KEP                            = 0x60000045,
    CRYPTO_TYPE_SM2_DSA_SM3                        = 0x70006045,
    CRYPTO_TYPE_RSASSA_PKCS1_V1_5_MD5              = 0x70001830,
    CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA1             = 0x70002830,
    CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA224           = 0x70003830,
    CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA256           = 0x70004830,
    CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA384           = 0x70005830,
    CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA512           = 0x70006830,
    CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_MD5          = 0x70111930,
    CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA1         = 0x70212930,
    CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA224       = 0x70313930,
    CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA256       = 0x70414930,
    CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA384       = 0x70515930,
    CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA512       = 0x70616930,
    CRYPTO_TYPE_ECDSA_SHA1                         = 0x70001042,
    CRYPTO_TYPE_ECDSA_SHA224                       = 0x70002042,
    CRYPTO_TYPE_ECDSA_SHA256                       = 0x70003042,
    CRYPTO_TYPE_ECDSA_SHA384                       = 0x70004042,
    CRYPTO_TYPE_ECDSA_SHA521                       = 0x70005042,
    CRYPTO_TYPE_ED25519                            = 0x70005043,
    CRYPTO_TYPE_DH_DERIVE_SECRET                   = 0x80000032,
    CRYPTO_TYPE_ECDH_DERIVE_SECRET                 = 0x80000042,
    CRYPTO_TYPE_X25519                             = 0x80000044,
    CRYPTO_TYPE_SM2_PKE                            = 0x80000045,
    CRYPTO_TYPE_GENERATE_RANDOM                    = 0xf0000001,
#ifndef MBEDTLS_ENABLE
    CRYPTO_TYPE_SIP_HASH                           = 0xF0000002,
#endif
};

enum crypto_curve_type {
    ECC_CURVE_NIST_P192    = 0x1,
    ECC_CURVE_NIST_P224    = 0x2,
    ECC_CURVE_NIST_P256    = 0x3,
    ECC_CURVE_NIST_P384    = 0x4,
    ECC_CURVE_NIST_P521    = 0x5,
    ECC_CURVE_X25519       = 0x6,
    ECC_CURVE_ED25519      = 0x7,
    ECC_CURVE_SM2          = 0x8,
};

enum crypto_attribute_id {
    CRYPTO_ATTR_RSA_OAEP_LABEL                      = 0xD0000930,
    CRYPTO_ATTR_RSA_MGF1_HASH                       = 0xF0000830,
    CRYPTO_ATTR_RSA_PSS_SALT_LENGTH                 = 0xF0000A30,
    CRYPTO_ATTR_ED25519_PH                          = 0xF0000543,
    CRYPTO_ATTR_ED25519_CTX                         = 0xD0000643,
    CRYPTO_ATTR_DH_PUBLIC_VALUE                     = 0xD0000132,
    CRYPTO_ATTR_ECC_PUBLIC_VALUE_X                  = 0xD0000141,
    CRYPTO_ATTR_ECC_PUBLIC_VALUE_Y                  = 0xD0000241,
    CRYPTO_ATTR_X25519_PUBLIC_VALUE                 = 0xD0000944,
    CRYPTO_ATTR_SM2_KEP_USER                        = 0x30010005,
    CRYPTO_ATTR_ECC_EPHEMERAL_PUBLIC_VALUE_X        = 0x30000006,
    CRYPTO_ATTR_ECC_EPHEMERAL_PUBLIC_VALUE_Y        = 0x30000007,
    CRYPTO_ATTR_SM2_ID_INITIATOR                    = 0x30000008,
    CRYPTO_ATTR_SM2_ID_RESPONDER                    = 0x30000009,
    CRYPTO_ATTR_SM2_KEP_CONFIRMATION_IN             = 0x3000000a,
    CRYPTO_ATTR_SM2_KEP_CONFIRMATION_OUT            = 0x3000000b,
};

enum key_type_t {
    CRYPTO_KEYTYPE_DEFAULT = 0x0,
    CRYPTO_KEYTYPE_USER    = 0x1,
    CRYPTO_KEYTYPE_HUK     = 0x2,
    CRYPTO_KEYTYPE_GID     = 0x3,
    CRYPTO_KEYTYPE_RPMB    = 0x4,
};

enum crypto_key_type_id {
    CRYPTO_KEY_TYPE_RSA_KEYPAIR        = 0xA1000030,
    CRYPTO_KEY_TYPE_DH_KEYPAIR         = 0xA1000032,
    CRYPTO_KEY_TYPE_ECDSA_KEYPAIR      = 0xA1000041,
    CRYPTO_KEY_TYPE_ECDH_KEYPAIR       = 0xA1000042,
    CRYPTO_KEY_TYPE_ED25519_KEYPAIR    = 0xA1000043,
    CRYPTO_KEY_TYPE_X25519_KEYPAIR     = 0xA1000044,
    CRYPTO_KEY_TYPE_SM2_DSA_KEYPAIR    = 0xA1000045,
    CRYPTO_KEY_TYPE_SM2_PKE_KEYPAIR    = 0xA1000047,
};

struct ctx_handle_t {
    uint64_t ctx_buffer;
    uint32_t ctx_size;
    uint32_t engine;
    uint32_t alg_type;
    uint32_t direction;
    bool is_support_ae_update;
    uint64_t cache_buffer;
    uint8_t cbc_mac_buffer[AES_MAC_LEN];
    uint32_t tag_len;
    uint8_t cipher_cache_data[CIPHER_CACHE_LEN];
    uint32_t cipher_cache_len;
    void (*free_context)(uint64_t *);
    uint64_t aad_cache;
    uint32_t aad_size;
    uint32_t driver_ability;
    uint64_t fd;
};

struct drv_memref_t {
    uint64_t buffer;
    uint32_t size;
    bool need_copy;
};

struct memref_t {
    uint64_t buffer;
    uint32_t size;
};

struct symmerit_key_t {
    uint32_t key_type;
    uint64_t key_buffer;
    uint32_t key_size;
};

struct ae_init_data {
    uint64_t nonce;
    uint32_t nonce_len;
    uint32_t tag_len;
    uint32_t aad_len;
    uint32_t payload_len;
};

struct rsa_pub_key_t {
    uint8_t  e[RSA_EXPONENT_LEN];
    uint32_t e_len;
    uint8_t  n[RSA_MAX_KEY_SIZE];
    uint32_t n_len;
};

struct rsa_priv_key_t {
    bool     crt_mode;
    uint8_t  e[RSA_EXPONENT_LEN];
    uint32_t e_len;
    uint8_t  n[RSA_MAX_KEY_SIZE];
    uint32_t n_len;
    uint8_t  d[RSA_MAX_KEY_SIZE];
    uint32_t d_len;
    uint8_t  p[RSA_MAX_KEY_SIZE_CRT];
    uint32_t p_len;
    uint8_t  q[RSA_MAX_KEY_SIZE_CRT];
    uint32_t q_len;
    uint8_t  dp[RSA_MAX_KEY_SIZE_CRT];
    uint32_t dp_len;
    uint8_t  dq[RSA_MAX_KEY_SIZE_CRT];
    uint32_t dq_len;
    uint8_t  qinv[RSA_MAX_KEY_SIZE_CRT];
    uint32_t qinv_len;
};

struct crypto_attribute_t {
    uint32_t attribute_id;
    union {
        struct {
            uint64_t buffer;
            uint32_t length;
        } ref;
        struct {
            uint32_t a;
            uint32_t b;
        } value;
    } content;
};

struct asymmetric_params_t {
    uint32_t param_count;
    uint64_t attribute;
};

struct ecc_pub_key_t {
    uint32_t domain_id;
    uint8_t  x[ECC_KEY_LEN];
    uint32_t x_len;
    uint8_t  y[ECC_KEY_LEN];
    uint32_t y_len;
};

struct ecc_priv_key_t {
    uint32_t domain_id;
    uint8_t  r[ECC_KEY_LEN];
    uint32_t r_len;
};

struct dh_key_t {
    uint64_t prime;
    uint32_t prime_size;
    uint64_t generator;
    uint32_t generator_size;
    union {
        struct {
            uint64_t q;
            uint32_t q_size;
            uint32_t l;
            uint32_t dh_mode;
        } generate_key_t;
        struct {
            uint64_t pub_key;
            uint32_t pub_key_size;
            uint64_t priv_key;
            uint32_t priv_key_size;
        } derive_key_t;
    } dh_param;
};

struct crypto_ops_t {
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
};

#endif
