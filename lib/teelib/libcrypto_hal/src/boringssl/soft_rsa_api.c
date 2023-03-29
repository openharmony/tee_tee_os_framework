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

#include "soft_rsa_api.h"
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <securec.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include "soft_common_api.h"
#include "soft_err.h"

#define UINT8_SHIFT                  8
#define MD5_LEN                      16
#define SHA1_LEN                     20
#define SHA224_LEN                   28
#define SHA256_LEN                   32
#define SHA384_LEN                   48
#define SHA512_LEN                   64
#define MAX_SOFT_ASYMMETRIC_KEY_SIZE 4096

struct rsa_priv_key_bignum_t {
    BIGNUM *bn_n;
    BIGNUM *bn_e;
    BIGNUM *bn_d;
    BIGNUM *bn_p;
    BIGNUM *bn_q;
    BIGNUM *bn_dp;
    BIGNUM *bn_dq;
    BIGNUM *bn_qinv;
    BIGNUM *bn_div;
    BIGNUM *bn_gcd;
};

struct create_rsa_crypt_ctx_t {
    uint32_t alg_type;
    uint32_t mode;
    int32_t padding;
};

static void uint8_to_uint32(const uint8_t *buffer, uint32_t size, uint32_t *result)
{
    bool check = ((buffer == NULL) || (size == 0) || (size > UINT32_SHIFT_MAX));
    if (check)
        return;
    uint32_t shift = 0;
    *result = 0;
    for (int32_t i = (int32_t)(size - 1); i >= 0; i--) {
        *result += (uint32_t)buffer[i] << shift;
        shift += UINT8_SHIFT;
    }
    return;
}

static RSA *generate_boring_rsa_key(uint32_t key_size, uint32_t exponent)
{
    RSA *rsa_key = RSA_new();
    if (rsa_key == NULL) {
        tloge("New rsa key structfailed\n");
        return NULL;
    }
    BIGNUM *bn_e = BN_new();
    if (bn_e == NULL) {
        tloge("New big num e failed\n");
        RSA_free(rsa_key);
        return NULL;
    }
    if (key_size > UINT32_MAX / BIT_TO_BYTE) {
        tloge("Key size is not valid, key_size=0x%x\n", key_size);
        BN_free(bn_e);
        RSA_free(rsa_key);
        return NULL;
    }

    int32_t ret1;
    if (exponent == 0)
        ret1 = BN_set_word(bn_e, RSA_F4);
    else
        ret1 = BN_set_word(bn_e, exponent);

    int32_t ret2 = RSA_generate_key_ex(rsa_key, key_size * BIT_TO_BYTE, bn_e, NULL);
    BN_free(bn_e);
    if ((ret1 != 1) || (ret2 != 1)) {
        tloge("Set big num e value or generate rsa key pair failed\n");
        RSA_free(rsa_key);
        return NULL;
    }

    return rsa_key;
}

static int32_t convert_big_num_to_buffer(const BIGNUM *big_num, uint8_t *out, uint32_t *out_len)
{
    bool check = ((big_num == NULL) || (out == NULL) || (out_len == NULL));
    if (check) {
        tloge("Invalid param in convert big num to buffer\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t big_num_len = (uint32_t)BN_num_bytes(big_num);
    if (*out_len < big_num_len) {
        tloge("The out length is less than big num length, out_len=%u, big_num_len=%u\n", *out_len, big_num_len);
        return CRYPTO_BAD_PARAMETERS;
    }

    uint8_t *rsa_buff = (uint8_t *)TEE_Malloc(big_num_len + 1, 0);
    if (rsa_buff == NULL) {
        tloge("Malloc memory for big num failed, size=%u\n", big_num_len);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    size_t write_len = (size_t)BN_bn2bin(big_num, rsa_buff);
    if (write_len != big_num_len) {
        tloge("Convert big num to buffer failed, big_num_len=%u, write_len=%zu\n", big_num_len, write_len);
        TEE_Free(rsa_buff);
        return CRYPTO_BAD_PARAMETERS;
    }

    errno_t rc = memcpy_s(out, *out_len, rsa_buff, big_num_len);
    TEE_Free(rsa_buff);
    if (rc != EOK) {
        tloge("Copy rsa buff to param failed\n");
        return CRYPTO_ERROR_SECURITY;
    }

    *out_len = big_num_len;
    return CRYPTO_SUCCESS;
}

static int32_t convert_rsa_boring_to_non_crt(const RSA *rsa_key, struct rsa_priv_key_t *key_pair)
{
    BIGNUM *bn_n = NULL;
    BIGNUM *bn_e = NULL;
    BIGNUM *bn_d = NULL;
    int32_t i = 0;

    RSA_get0_key(rsa_key, (const BIGNUM **)&bn_n, (const BIGNUM **)&bn_e, (const BIGNUM **)&bn_d);

    BIGNUM *bn_array[] = {bn_n, bn_e, bn_d};
    uint8_t *key[] = {key_pair->n, key_pair->e, key_pair->d};
    uint32_t *key_len[] = {&(key_pair->n_len), &(key_pair->e_len), &(key_pair->d_len)};

    for (; i < RSA_KEY_PAIR_ATTRIBUTE_COUNT_NO_CRT; i++) {
        int32_t ret = convert_big_num_to_buffer(bn_array[i], key[i], key_len[i]);
        if (ret != CRYPTO_SUCCESS) {
            tloge("Convert boring rsa key to crt failed, ret=0x%x\n", ret);
            return CRYPTO_BAD_PARAMETERS;
        }
    }

    return CRYPTO_SUCCESS;
}

static int32_t convert_rsa_boring_to_crt(const RSA *rsa_key, struct rsa_priv_key_t *key_pair)
{
    struct rsa_priv_key_bignum_t key_pair_bignum = {0};
    int32_t i = 0;

    RSA_get0_key(rsa_key, (const BIGNUM **)&(key_pair_bignum.bn_n),
        (const BIGNUM **)&(key_pair_bignum.bn_e), (const BIGNUM **)&(key_pair_bignum.bn_d));
    RSA_get0_factors(rsa_key, (const BIGNUM **)&(key_pair_bignum.bn_p), (const BIGNUM **)&(key_pair_bignum.bn_q));
    RSA_get0_crt_params(rsa_key, (const BIGNUM **)&(key_pair_bignum.bn_dp),
        (const BIGNUM **)&(key_pair_bignum.bn_dq), (const BIGNUM **)&(key_pair_bignum.bn_qinv));

    BIGNUM *bn_array[] = {key_pair_bignum.bn_n, key_pair_bignum.bn_e, key_pair_bignum.bn_d, key_pair_bignum.bn_p,
        key_pair_bignum.bn_q, key_pair_bignum.bn_dp, key_pair_bignum.bn_dq, key_pair_bignum.bn_qinv};
    uint8_t *key[] = {key_pair->n, key_pair->e, key_pair->d, key_pair->p, key_pair->q,
        key_pair->dp, key_pair->dq, key_pair->qinv};
    uint32_t *key_len[] = {&(key_pair->n_len), &(key_pair->e_len), &(key_pair->d_len),
        &(key_pair->p_len), &(key_pair->q_len), &(key_pair->dp_len), &(key_pair->dq_len), &(key_pair->qinv_len)};

    for (; i < RSA_KEY_PAIR_ATTRIBUTE_COUNT; i++) {
        int32_t ret = convert_big_num_to_buffer(bn_array[i], key[i], key_len[i]);
        if (ret != CRYPTO_SUCCESS) {
            tloge("Convert boring rsa key to crt failed, ret=0x%x\n", ret);
            return CRYPTO_BAD_PARAMETERS;
        }
    }

    return CRYPTO_SUCCESS;
}

static int32_t soft_gen_rsa_key_pair(uint32_t key_size, uint32_t exponent, bool crt_mode,
    struct rsa_priv_key_t *key_pair)
{
    int32_t ret;
    RSA *rsa_key = generate_boring_rsa_key(key_size, exponent);
    if (rsa_key == NULL) {
        tloge("Generate boring rsa key failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    if (crt_mode)
        ret = convert_rsa_boring_to_crt(rsa_key, key_pair);
    else
        ret = convert_rsa_boring_to_non_crt(rsa_key, key_pair);

    RSA_free(rsa_key);
    if (ret != CRYPTO_SUCCESS)
        tloge("Convert boring rsa key to params failed!\n ret = 0x%x\n", ret);

    key_pair->crt_mode = crt_mode;
    return ret;
}

static int32_t convert_rsa_padding_to_boring(uint32_t algorithm, int32_t *padding, uint32_t *hash_len)
{
    switch (algorithm) {
    case CRYPTO_TYPE_RSAES_PKCS1_V1_5:
        *padding = RSA_PKCS1_PADDING;
        break;
    case CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA1:
        *hash_len = SHA1_LEN;
        *padding  = RSA_PKCS1_OAEP_PADDING;
        break;
    case CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA224:
        *hash_len = SHA224_LEN;
        *padding  = RSA_PKCS1_OAEP_PADDING;
        break;
    case CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA256:
        *hash_len = SHA256_LEN;
        *padding  = RSA_PKCS1_OAEP_PADDING;
        break;
    case CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA384:
        *hash_len = SHA384_LEN;
        *padding  = RSA_PKCS1_OAEP_PADDING;
        break;
    case CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA512:
        *hash_len = SHA512_LEN;
        *padding  = RSA_PKCS1_OAEP_PADDING;
        break;
    case CRYPTO_TYPE_RSA_NO_PAD:
        *padding = RSA_NO_PADDING;
        break;
    default:
        tloge("Convert rsa padding: algorithm not supported, algorithm=0x%x\n", algorithm);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

static const EVP_MD *get_mgf1_algorithm(const struct asymmetric_params_t *params)
{
    if (params == NULL)
        return NULL;
    struct crypto_attribute_t *attribute = (struct crypto_attribute_t *)(uintptr_t)(params->attribute);
    if (attribute == NULL)
        return NULL;
    for (uint32_t i = 0; i < params->param_count; i++) {
        if (attribute[i].attribute_id == CRYPTO_ATTR_RSA_MGF1_HASH) {
            switch (attribute[i].content.value.a) {
            case CRYPTO_TYPE_DIGEST_SHA1:
                return EVP_sha1();
            case CRYPTO_TYPE_DIGEST_SHA224:
                return EVP_sha224();
            case CRYPTO_TYPE_DIGEST_SHA256:
                return EVP_sha256();
            case CRYPTO_TYPE_DIGEST_SHA384:
                return EVP_sha384();
            case CRYPTO_TYPE_DIGEST_SHA512:
                return EVP_sha512();
            default:
                return NULL;
            }
        }
    }
    return NULL;
}

static int32_t get_hash_nid_from_algorithm(uint32_t algorithm, int32_t *hash_nid)
{
    size_t i = 0;
    crypto_uint2uint algorithm_to_hash_nid[] = {
        { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_MD5, NID_md5 },
        { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA1, NID_sha1 },
        { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA224, NID_sha224 },
        { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA256, NID_sha256 },
        { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA384, NID_sha384 },
        { CRYPTO_TYPE_RSASSA_PKCS1_V1_5_SHA512, NID_sha512 },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_MD5, NID_md5 },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA1, NID_sha1 },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA224, NID_sha224 },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA256, NID_sha256 },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA384, NID_sha384 },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA512, NID_sha512 },
        { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA1,  NID_sha1 },
        { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA224, NID_sha224 },
        { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA256, NID_sha256 },
        { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA384, NID_sha384 },
        { CRYPTO_TYPE_RSAES_PKCS1_OAEP_MGF1_SHA512, NID_sha512 }
    };
    size_t total_map_num = sizeof(algorithm_to_hash_nid) / sizeof(crypto_uint2uint);
    for (; i < total_map_num; i++) {
        if (algorithm_to_hash_nid[i].src == algorithm) {
            *hash_nid = (int32_t)algorithm_to_hash_nid[i].dest;
            return CRYPTO_SUCCESS;
        }
    }

    return CRYPTO_BAD_PARAMETERS;
}

static int32_t set_rsa_oaep_padding_hash(const struct asymmetric_params_t *params, uint32_t alg_type,
    EVP_PKEY_CTX *ctx, int32_t padding)
{
    if (padding != RSA_PKCS1_OAEP_PADDING)
        return CRYPTO_SUCCESS;

    int32_t hash_nid = NID_sha1;
    int32_t ret = get_hash_nid_from_algorithm(alg_type, &hash_nid);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Get hash nid from operation algorithm failed\n");
        return ret;
    }

    const EVP_MD *md = EVP_get_digestbynid(hash_nid);
    if (md == NULL) {
        tloge("Get evp digest by nid failed, hash_nid=%d\n", hash_nid);
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    ret = EVP_PKEY_CTX_set_rsa_oaep_md(ctx, (const void *)md);
    if (ret != BORINGSSL_OK) {
        tloge("Evp rsa set oaep md failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    /* The mgf1 hash is fixed sha1 in dx, so use sha1 for compatible in here */
    const EVP_MD *evp_md = get_mgf1_algorithm(params);
    if (evp_md != NULL)
        ret = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, (void *)evp_md);
    else
        ret = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, (const void *)EVP_sha1());

    if (ret != BORINGSSL_OK) {
        tloge("Evp rsa set mgf1 md failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    return CRYPTO_SUCCESS;
}

static int32_t set_evp_rsa_ctx_mode(uint32_t mode, EVP_PKEY_CTX *ctx)
{
    if (mode == ENC_MODE) {
        int32_t rc = EVP_PKEY_encrypt_init(ctx);
        if (rc != BORINGSSL_OK) {
            tloge("Evp rsa encrypt init failed\n");
            return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        }
    } else {
        int32_t rc = EVP_PKEY_decrypt_init(ctx);
        if (rc != BORINGSSL_OK) {
            tloge("Evp rsa decrypt init failed\n");
            return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        }
    }

    return CRYPTO_SUCCESS;
}

static EVP_PKEY_CTX *generate_and_init_evp_rsa_ctx(uint32_t alg_type, const struct asymmetric_params_t *params,
    uint32_t mode, int32_t padding, EVP_PKEY *evp_key)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evp_key, NULL);
    if (ctx == NULL) {
        tloge("Create rsa evp key ctx failed\n");
        return NULL;
    }

    int ret = set_evp_rsa_ctx_mode(mode, ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Set evp rsa ctx mode failed\n");
        goto error;
    }

    ret = EVP_PKEY_CTX_set_rsa_padding(ctx, padding);
    if (ret != BORINGSSL_OK) {
        tloge("Evp set rsa ctx padding failed\n");
        goto error;
    }

    ret = set_rsa_oaep_padding_hash(params, alg_type, ctx, padding);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Set rsa oaep padding failed\n");
        goto error;
    }

    return ctx;
error:
    EVP_PKEY_CTX_free(ctx);
    return NULL;
}

static RSA *convert_rsa_pub_to_boring(const struct rsa_pub_key_t *public_key)
{
    if (public_key->n_len > RSA_MAX_KEY_SIZE || public_key->e_len > RSA_EXPONENT_LEN)
        return NULL;

    BIGNUM *bn_n = BN_bin2bn(public_key->n, public_key->n_len, NULL);
    BIGNUM *bn_e = BN_bin2bn(public_key->e, public_key->e_len, NULL);
    bool check = ((bn_n == NULL) || (bn_e == NULL));
    if (check) {
        tloge("Change pub buffer num to big num failed\n");
        BN_free(bn_n);
        BN_free(bn_e);
        return NULL;
    }

    RSA *rsa_key = RSA_new();
    if (rsa_key == NULL) {
        tloge("Malloc memory for rsa key failed\n");
        BN_free(bn_n);
        BN_free(bn_e);
        return NULL;
    }

    int32_t rc = RSA_set0_key(rsa_key, bn_n, bn_e, NULL);
    if (rc != BORINGSSL_OK) {
        tloge("Set rsa key failed\n");
        BN_free(bn_n);
        BN_free(bn_e);
        RSA_free(rsa_key);
        return NULL;
    }

    return rsa_key;
}

static EVP_PKEY_CTX *create_rsa_encrypt_ctx(const struct create_rsa_crypt_ctx_t *rsa_encrypt_ctx,
    const struct asymmetric_params_t *params, const struct rsa_pub_key_t *public_key, EVP_PKEY *evp_key)
{
    RSA *rsa_key = convert_rsa_pub_to_boring(public_key);
    if (rsa_key == NULL) {
        tloge("Duplicate rsa pub key failed\n");
        return NULL;
    }
    int32_t rc = EVP_PKEY_assign_RSA(evp_key, rsa_key);
    if (rc != BORINGSSL_OK) {
        tloge("Evp assign rsa key failed\n");
        RSA_free(rsa_key);
        return NULL;
    }
    EVP_PKEY_CTX *ctx = generate_and_init_evp_rsa_ctx((rsa_encrypt_ctx->alg_type), params, (rsa_encrypt_ctx->mode),
        (rsa_encrypt_ctx->padding), evp_key);
    if (ctx == NULL) {
        tloge("Create and init rsa evp ctx failed\n");
        RSA_free(rsa_key);
        return NULL;
    }

    return ctx;
}

static RSA *convert_rsa_non_crt_to_boring(const struct rsa_priv_key_t *private_key)
{
    if (private_key->n_len > RSA_MAX_KEY_SIZE || private_key->d_len > RSA_MAX_KEY_SIZE ||
        private_key->e_len > RSA_EXPONENT_LEN)
        return NULL;

    BIGNUM *bn_n = BN_bin2bn(private_key->n, private_key->n_len, NULL);
    BIGNUM *bn_e = BN_bin2bn(private_key->e, private_key->e_len, NULL);
    BIGNUM *bn_d = BN_bin2bn(private_key->d, private_key->d_len, NULL);
    bool is_abnormal = (bn_n == NULL) || (bn_e == NULL) || (bn_d == NULL);
    if (is_abnormal) {
        tloge("Change non crt buffer num to big num failed\n");
        goto free_bn;
    }
    RSA *rsa_key = RSA_new();
    if (rsa_key == NULL) {
        tloge("Malloc memory for rsa key failed\n");
        goto free_bn;
    }
    int32_t rc = RSA_set0_key(rsa_key, bn_n, bn_e, bn_d);
    if (rc != BORINGSSL_OK) {
        tloge("Set rsa key failed\n");
        RSA_free(rsa_key);
        goto free_bn;
    }
    return rsa_key;
free_bn:
    BN_free(bn_n);
    BN_free(bn_e);
    BN_clear_free(bn_d);
    return NULL;
}

static int32_t get_rsa_crt_big_num(const struct rsa_priv_key_t *private_key, BIGNUM *bn_array[], uint32_t array_num)
{
    const uint8_t *key_array[RSA_CRT_KEY_ATTRIBUTE_COUNT] = {
        private_key->p,
        private_key->q,
        private_key->dp,
        private_key->dq,
        private_key->qinv
    };
    uint32_t key_size_array[RSA_CRT_KEY_ATTRIBUTE_COUNT] = {
        private_key->p_len,
        private_key->q_len,
        private_key->dp_len,
        private_key->dq_len,
        private_key->qinv_len
    };

    uint32_t i = 0;
    for (; i < array_num; i++) {
        bn_array[i] = BN_bin2bn(key_array[i], (int32_t)key_size_array[i], NULL);
        if (bn_array[i] == NULL) {
            tloge("Change crt buffer num to big num failed\n");
            return CRYPTO_BAD_PARAMETERS;
        }
    }

    return CRYPTO_SUCCESS;
}

#define RSA_FACTOR_P_INDEX 0
#define RSA_FACTOR_Q_INDEX 1
#define RSA_CRT_DMP1       2
#define RSA_CRT_DMQ1       3
#define RSA_CRT_IQMP       4
static RSA *set_boring_rsa_key(BIGNUM *bn_n, BIGNUM *bn_e, BIGNUM *bn_d, BIGNUM *bn_array[])
{
    RSA *rsa_key = RSA_new();
    if (rsa_key == NULL) {
        tloge("Malloc memory for rsa key failed\n");
        return NULL;
    }
    int32_t ret1 = RSA_set0_key(rsa_key, bn_n, bn_e, bn_d);
    int32_t ret2 = RSA_set0_factors(rsa_key, bn_array[RSA_FACTOR_P_INDEX], bn_array[RSA_FACTOR_Q_INDEX]);
    int32_t ret3 = RSA_set0_crt_params(rsa_key,
                                       bn_array[RSA_CRT_DMP1],
                                       bn_array[RSA_CRT_DMQ1],
                                       bn_array[RSA_CRT_IQMP]);
    bool is_abnormal = (ret1 != BORINGSSL_OK || ret2 != BORINGSSL_OK || ret3 != BORINGSSL_OK);
    if (is_abnormal) {
        tloge("Set rsa key failed, ret1=0x%x, ret2=0x%x, ret3=0x%x\n", ret1, ret2, ret3);
        RSA_free(rsa_key);
        return NULL;
    }

    return rsa_key;
}

static int32_t compute_rsa_ed_big_num(BIGNUM *bn_p, BIGNUM *bn_q, BN_CTX *ctx, BIGNUM **bn_e, BIGNUM **bn_d)
{
    struct rsa_priv_key_bignum_t key_pair_bignum = {0};
    int32_t ret1;

    key_pair_bignum.bn_p = BN_dup(bn_p);
    key_pair_bignum.bn_q = BN_dup(bn_q);
    key_pair_bignum.bn_div = BN_new();
    key_pair_bignum.bn_gcd = BN_new();
    bool is_abnormal = (key_pair_bignum.bn_p == NULL) || (key_pair_bignum.bn_q == NULL) ||
        (key_pair_bignum.bn_div == NULL) || (key_pair_bignum.bn_gcd == NULL);
    if (is_abnormal) {
        tloge("Duplicate or new big num failed\n");
        ret1 = 0;
        goto error;
    }

    ret1 = BN_sub_word(key_pair_bignum.bn_p, 1);
    int32_t ret2 = BN_sub_word(key_pair_bignum.bn_q, 1);
    is_abnormal  = (ret1 != 1) || (ret2 != 1);
    if (is_abnormal) {
        tloge("Big num sub 1 failed, ret1=%d, ret2=%d\n", ret1, ret2);
        ret1 = 0;
        goto error;
    }

    ret1 = BN_gcd(key_pair_bignum.bn_gcd, key_pair_bignum.bn_p, key_pair_bignum.bn_q, ctx);
    ret2 = BN_div(key_pair_bignum.bn_p, key_pair_bignum.bn_div, key_pair_bignum.bn_p, key_pair_bignum.bn_gcd, ctx);
    int32_t ret3 = BN_mul(key_pair_bignum.bn_div, key_pair_bignum.bn_q, key_pair_bignum.bn_p, ctx);
    is_abnormal = (ret1 != 1) || (ret2 != 1) || (ret3 != 1);
    if (is_abnormal) {
        tloge("compute e and d failed, ret1=%d, ret2=%d, ret3=%d\n", ret1, ret2, ret3);
        ret1 = 0;
        goto error;
    }
    /* Big num tmp4 is not new allocated, can not be free */
    BIGNUM *tmp4 = BN_mod_inverse(*bn_d, *bn_e, key_pair_bignum.bn_q, ctx);
    if (tmp4 == NULL) {
        tloge("Get big num d by mod inverse failed\n");
        ret1 = 0;
        goto error;
    }

    ret1 = 1;
error:
    BN_clear_free(key_pair_bignum.bn_p);
    BN_clear_free(key_pair_bignum.bn_q);
    BN_free(key_pair_bignum.bn_div);
    BN_free(key_pair_bignum.bn_gcd);
    return ret1;
}

static int32_t get_rsa_ned_big_num(BIGNUM *bn_p, BIGNUM *bn_q, BIGNUM **bn_n, BIGNUM **bn_e, BIGNUM **bn_d)
{
    BN_CTX *ctx = BN_CTX_new();
    if (ctx == NULL) {
        tloge("New bn ctx failed\n");
        return 0;
    }

    int32_t ret = BN_mul(*bn_n, bn_p, bn_q, ctx);
    if (ret != 1) {
        tloge("Big num mul failed\n");
        BN_CTX_free(ctx);
        return 0;
    }

    ret = compute_rsa_ed_big_num(bn_p, bn_q, ctx, bn_e, bn_d);
    BN_CTX_free(ctx);
    if (ret != 1) {
        tloge("Big num e and d compute failed\n");
        return 0;
    }

    return 1;
}

static bool check_private_key_len(const struct rsa_priv_key_t *private_key)
{
    if (private_key->e_len > RSA_EXPONENT_LEN ||
        private_key->n_len > RSA_MAX_KEY_SIZE ||
        private_key->d_len > RSA_MAX_KEY_SIZE ||
        private_key->p_len > RSA_MAX_KEY_SIZE_CRT ||
        private_key->q_len > RSA_MAX_KEY_SIZE_CRT ||
        private_key->dp_len > RSA_MAX_KEY_SIZE_CRT ||
        private_key->dq_len > RSA_MAX_KEY_SIZE_CRT ||
        private_key->qinv_len > RSA_MAX_KEY_SIZE_CRT)
        return false;
    return true;
}

static RSA *convert_rsa_crt_to_boring(const struct rsa_priv_key_t *private_key)
{
    bool check = check_private_key_len(private_key);
    if (!check)
        return NULL;

    BIGNUM *bn_n = BN_new();
    BIGNUM *bn_e = BN_bin2bn(private_key->e, private_key->e_len, NULL);
    BIGNUM *bn_d = BN_new();
    BIGNUM *bn_array[RSA_CRT_KEY_ATTRIBUTE_COUNT] = { 0 };
    bool is_abnormal = (bn_n == NULL) || (bn_e == NULL) || (bn_d == NULL);
    if (is_abnormal) {
        tloge("New big num n or e or d failed\n");
        goto error;
    }

    int32_t ret = get_rsa_crt_big_num(private_key, bn_array, RSA_CRT_KEY_ATTRIBUTE_COUNT);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Change crt buffer num to big num failed, ret=0x%x\n", ret);
        goto error;
    }

    ret = get_rsa_ned_big_num(bn_array[0], bn_array[1], &bn_n, &bn_e, &bn_d);
    if (ret != BORINGSSL_OK) {
        tloge("Get big num n, e, d failed\n");
        goto error;
    }

    RSA *rsa_key = set_boring_rsa_key(bn_n, bn_e, bn_d, bn_array);
    if (rsa_key == NULL) {
        tloge("Set boring rsa key failed\n");
        goto error;
    }

    return rsa_key;

error:
    BN_free(bn_n);
    BN_free(bn_e);
    BN_clear_free(bn_d);
    for (int32_t i = 0; i < RSA_CRT_KEY_ATTRIBUTE_COUNT; i++)
        BN_clear_free(bn_array[i]);
    return NULL;
}

static EVP_PKEY_CTX *create_rsa_decrypt_ctx(const struct create_rsa_crypt_ctx_t *rsa_decrypt_ctx,
    const struct asymmetric_params_t *params, const struct rsa_priv_key_t *private_key, EVP_PKEY *evp_key)
{
    RSA *rsa_key = NULL;
    if (private_key->crt_mode)
        rsa_key = convert_rsa_crt_to_boring(private_key);
    else
        rsa_key = convert_rsa_non_crt_to_boring(private_key);
    if (rsa_key == NULL) {
        tloge("Duplicate rsa priv key failed\n");
        return NULL;
    }
    int32_t rc = EVP_PKEY_assign_RSA(evp_key, rsa_key);
    if (rc != 1) {
        tloge("Evp assign rsa key failed\n");
        RSA_free(rsa_key);
        return NULL;
    }
    EVP_PKEY_CTX *ctx = generate_and_init_evp_rsa_ctx((rsa_decrypt_ctx->alg_type), params, (rsa_decrypt_ctx->mode),
        (rsa_decrypt_ctx->padding), evp_key);
    if (ctx == NULL) {
        tloge("Create and init rsa evp ctx failed\n");
        RSA_free(rsa_key);
        return NULL;
    }

    return ctx;
}

#define SOFT_RSA_PKCS1_PADDING_LEN 11
static int32_t check_pkcs1_padding(uint32_t dest_len, uint32_t key_size)
{
    if (key_size < SOFT_RSA_PKCS1_PADDING_LEN) {
        tloge("Key size is invalid\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (dest_len < (key_size - SOFT_RSA_PKCS1_PADDING_LEN)) {
        tloge("Dest len is too short, dest_len = 0x%x, max_src_len = 0x%x\n", dest_len,
            (key_size - SOFT_RSA_PKCS1_PADDING_LEN));
        return CRYPTO_SHORT_BUFFER;
    }

    return CRYPTO_SUCCESS;
}
static int32_t check_oaep_padding(uint32_t dest_len, uint32_t key_size, uint32_t hash_len)
{
    if (key_size < (SOFT_NUMBER_TWO * hash_len - SOFT_NUMBER_TWO)) {
        tloge("Key size is invalid\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (dest_len < (key_size - SOFT_NUMBER_TWO * hash_len - SOFT_NUMBER_TWO)) {
        tloge("Dest len is too short, dest_len = 0x%x, max_src_len = 0x%x\n", dest_len,
            (key_size - (SOFT_NUMBER_TWO * hash_len - SOFT_NUMBER_TWO)));
        return CRYPTO_SHORT_BUFFER;
    }

    return CRYPTO_SUCCESS;
}
static int32_t check_no_padding(uint32_t dest_len, uint32_t key_size)
{
    if (dest_len < key_size) {
        tloge("Dest len is too short\n");
        return CRYPTO_SHORT_BUFFER;
    }

    return CRYPTO_SUCCESS;
}

static int32_t check_rsa_decrypt_destlen(uint32_t dest_len, int32_t padding, uint32_t key_size, uint32_t hash_len)
{
    switch (padding) {
    case RSA_PKCS1_PADDING:
        return check_pkcs1_padding(dest_len, key_size);
    case RSA_PKCS1_OAEP_PADDING:
        return check_oaep_padding(dest_len, key_size, hash_len);
    case RSA_NO_PADDING:
        return check_no_padding(dest_len, key_size);
    default:
        return CRYPTO_BAD_PARAMETERS;
    }
}

static bool check_is_rsa_pss_sign_algorithm(uint32_t algorithm)
{
    size_t i = 0;
    uint32_t algorithm_set[] = {
        CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_MD5,
        CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA1,
        CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA224,
        CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA256,
        CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA384,
        CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA512
    };
    size_t total_set_num = sizeof(algorithm_set) / sizeof(uint32_t);
    for (; i < total_set_num; i++) {
        if (algorithm_set[i] == algorithm)
            return true;
    }

    return false;
}

static uint32_t get_pss_salt_len_from_algorithm(uint32_t algorithm)
{
    size_t i = 0;
    crypto_uint2uint algorithm_to_salt_len[] = {
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_MD5,    MD5_OUTPUT_LEN },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA1,   SHA1_OUTPUT_LEN },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA224, SHA224_OUTPUT_LEN },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA256, SHA256_OUTPUT_LEN },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA384, SHA384_OUTPUT_LEN },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA512, SHA512_OUTPUT_LEN }
    };
    size_t total_map_num = sizeof(algorithm_to_salt_len) / sizeof(crypto_uint2uint);
    for (; i < total_map_num; i++) {
        if (algorithm_to_salt_len[i].src == algorithm)
            return algorithm_to_salt_len[i].dest;
    }

    return 0;
}

static uint32_t get_pss_salt_len(const struct asymmetric_params_t *rsa_params, uint32_t algorithm)
{
    if (rsa_params != NULL) {
        struct crypto_attribute_t *attribute = (struct crypto_attribute_t *)(uintptr_t)(rsa_params->attribute);
        if (attribute == NULL)
            return 0;
        int32_t index = get_attr_index_by_id(TEE_ATTR_RSA_PSS_SALT_LENGTH,
            (const TEE_Attribute *)attribute, rsa_params->param_count);
        if (index >= 0)
            return attribute[index].content.value.a;
    }

    return get_pss_salt_len_from_algorithm(algorithm);
}

static int32_t do_rsa_sign_pss(RSA *rsa_key, const EVP_MD *md,
    const struct memref_t *digest, struct memref_t *signature, uint32_t salt_len)
{
    uint32_t em_len = (uint32_t)RSA_size(rsa_key);
    if (em_len > MAX_SOFT_ASYMMETRIC_KEY_SIZE) {
        tloge("key size is Invalid");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint8_t *em_buf = TEE_Malloc(em_len, 0);
    if (em_buf == NULL) {
        tloge("Malloc em buf failed, em_len=%u\n", em_len);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    int rc = RSA_padding_add_PKCS1_PSS_mgf1(rsa_key, em_buf, (uint8_t *)(uintptr_t)(digest->buffer), md, md, salt_len);
    if (rc != OPENSSL_OK) {
        tloge("Rsa padding add pss mgf1 failed, rc=%d\n", rc);
        TEE_Free(em_buf);
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    int out_len = RSA_private_encrypt(em_len, em_buf, (uint8_t *)(uintptr_t)(signature->buffer),
        rsa_key, RSA_NO_PADDING);
    TEE_Free(em_buf);
    em_buf = NULL;
    if (out_len < 0) {
        tloge("Rsa pss sign failed, rc=%d\n", out_len);
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    signature->size = (uint32_t)out_len;
    return CRYPTO_SUCCESS;
}

static int32_t soft_rsa_pss_sign_digest(uint32_t alg_type, const struct asymmetric_params_t *rsa_params,
    const struct rsa_priv_key_t *private_key, const struct memref_t *digest, struct memref_t *signature)
{
    int hash_nid = NID_sha1;
    RSA *rsa_key = NULL;
    if (private_key->crt_mode)
        rsa_key = convert_rsa_crt_to_boring(private_key);
    else
        rsa_key = convert_rsa_non_crt_to_boring(private_key);
    if (rsa_key == NULL) {
        tloge("Duplicate rsa priv key failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    int32_t ret = get_hash_nid_from_algorithm(alg_type, &hash_nid);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Get hash nid from algorithm failed\n");
        RSA_free(rsa_key);
        return ret;
    }

    const EVP_MD *md = EVP_get_digestbynid(hash_nid);
    if (md == NULL) {
        tloge("Get evp digest by nid failed, hash_nid=%d\n", hash_nid);
        RSA_free(rsa_key);
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    uint32_t salt_len = get_pss_salt_len(rsa_params, alg_type);
    if (salt_len == 0) {
        RSA_free(rsa_key);
        return CRYPTO_BAD_PARAMETERS;
    }
    ret = do_rsa_sign_pss(rsa_key, md, digest, signature, salt_len);
    RSA_free(rsa_key);
    return ret;
}

static RSA *get_rsa_key(const struct rsa_priv_key_t *private_key)
{
    if (private_key->crt_mode)
        return convert_rsa_crt_to_boring(private_key);

    return convert_rsa_non_crt_to_boring(private_key);
}

static int32_t soft_rsa_non_pss_sign_digest(uint32_t alg_type,
    const struct rsa_priv_key_t *private_key, const struct memref_t *digest, struct memref_t *signature)
{
    int32_t hash_nid = NID_sha1;
    RSA *rsa_key = get_rsa_key(private_key);
    if (rsa_key == NULL) {
        tloge("Duplicate rsa priv key failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    int32_t ret = get_hash_nid_from_algorithm(alg_type, &hash_nid);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Get hash nid from operation algorithm failed\n");
        RSA_free(rsa_key);
        return ret;
    }

    uint8_t *digest_buffer = (uint8_t *)(uintptr_t)(digest->buffer);
    uint8_t *signature_buffer = (uint8_t *)(uintptr_t)(signature->buffer);

    uint32_t signature_len_temp = signature->size;
    int rc = RSA_sign(hash_nid, digest_buffer, digest->size, signature_buffer, &signature_len_temp, rsa_key);
    RSA_free(rsa_key);
    if (rc != BORINGSSL_OK) {
        tloge("Soft rsa non pss sign digest failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    signature->size = signature_len_temp;
    return CRYPTO_SUCCESS;
}

static int32_t soft_rsa_non_pss_verify_digest(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct memref_t *digest, const struct memref_t *signature)
{
    int hash_nid = NID_sha1;
    RSA *rsa_key = convert_rsa_pub_to_boring(public_key);
    if (rsa_key == NULL) {
        tloge("Duplicate rsa priv key failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t ret = get_hash_nid_from_algorithm(alg_type, &hash_nid);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Get hash nid from algorithm failed\n");
        RSA_free(rsa_key);
        return ret;
    }
    uint8_t *digest_buffer = (uint8_t *)(uintptr_t)(digest->buffer);
    uint8_t *signature_buffer = (uint8_t *)(uintptr_t)(signature->buffer);

    ret = RSA_verify(hash_nid, digest_buffer, digest->size, signature_buffer,
        signature->size, rsa_key);
    RSA_free(rsa_key);
    if (ret != BORINGSSL_OK) {
        tloge("Soft rsa verify digest failed\n");
        return get_soft_crypto_error(CRYPTO_SIGNATURE_INVALID);
    }

    return CRYPTO_SUCCESS;
}

static int32_t do_rsa_verify_pss(RSA *rsa_key, const EVP_MD *md,
    const struct memref_t *digest, const struct memref_t *signature, uint32_t salt_len)
{
    uint8_t *digest_buffer = (uint8_t *)(uintptr_t)(digest->buffer);
    uint8_t *signature_buffer = (uint8_t *)(uintptr_t)(signature->buffer);

    uint32_t em_len = (uint32_t)RSA_size(rsa_key);
    if (em_len > MAX_SOFT_ASYMMETRIC_KEY_SIZE) {
        tloge("keysize is Invalid");
        return CRYPTO_BAD_PARAMETERS;
    }
    uint8_t *em_buf = TEE_Malloc(em_len, 0);
    if (em_buf == NULL) {
        tloge("Malloc em buf failed, em_len=%u\n", em_len);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    int rc = RSA_public_decrypt(signature->size, signature_buffer, em_buf, rsa_key, RSA_NO_PADDING);
    if (rc <= BORINGSSL_ERR) {
        tloge("Rsa public decrypt failed, rc=%d\n", rc);
        TEE_Free(em_buf);
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    rc = RSA_verify_PKCS1_PSS_mgf1(rsa_key, digest_buffer, md, md, em_buf, (int)salt_len);
    TEE_Free(em_buf);
    em_buf = NULL;
    if (rc != BORINGSSL_OK) {
        tloge("Rsa pss verify failed, rc=%d\n", rc);
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    return CRYPTO_SUCCESS;
}

static int32_t soft_rsa_pss_verify_digest(uint32_t alg_type, const struct asymmetric_params_t *rsa_params,
    const struct rsa_pub_key_t *public_key, const struct memref_t *digest, const struct memref_t *signature)
{
    int hash_nid = NID_sha1;
    RSA *rsa_key = convert_rsa_pub_to_boring(public_key);
    if (rsa_key == NULL) {
        tloge("Duplicate rsa priv key failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t ret = get_hash_nid_from_algorithm(alg_type, &hash_nid);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Get hash nid from operation algorithm failed\n");
        RSA_free(rsa_key);
        return ret;
    }

    const EVP_MD *md = EVP_get_digestbynid(hash_nid);
    if (md == NULL) {
        tloge("Get digest by nid failed, hash_nid=%d\n", hash_nid);
        RSA_free(rsa_key);
        return get_soft_crypto_error(TEE_ERROR_GENERIC);
    }

    uint32_t salt_len = get_pss_salt_len(rsa_params, alg_type);
    ret = do_rsa_verify_pss(rsa_key, md, digest, signature, salt_len);
    RSA_free(rsa_key);
    return ret;
}

int32_t soft_crypto_rsa_generate_keypair(uint32_t key_size, const struct memref_t *e_value, bool crt_mode,
    struct rsa_priv_key_t *key_pair)
{
    if (e_value == NULL || key_pair == NULL) {
        tloge("bad parameters");
        return CRYPTO_BAD_PARAMETERS;
    }
    uint32_t exponent = 0;
    uint8_to_uint32((uint8_t *)(uintptr_t)(e_value->buffer), e_value->size, &exponent);
    if (exponent > 0xffffff) /* find wrong exponent */
        return CRYPTO_NOT_SUPPORTED;
    return soft_gen_rsa_key_pair(key_size, exponent, crt_mode, key_pair);
}

static int32_t do_rsa_encrypt(struct create_rsa_crypt_ctx_t *rsa_encrypt_ctx,
    const struct asymmetric_params_t *rsa_params, const struct rsa_pub_key_t *public_key,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    EVP_PKEY *evp_key = EVP_PKEY_new();
    if (evp_key == NULL) {
        tloge("Create rsa evp key failed\n");
        return get_soft_crypto_error(CRYPTO_ERROR_OUT_OF_MEMORY);
    }

    EVP_PKEY_CTX *ctx = create_rsa_encrypt_ctx(rsa_encrypt_ctx, rsa_params, public_key, evp_key);
    if (ctx == NULL) {
        tloge("Create rsa encrypt ctx failed\n");
        EVP_PKEY_free(evp_key); /* rsa_key will free together with evp_key, can not free it alone */
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    size_t data_out_size = data_out->size;
    int32_t ret = EVP_PKEY_encrypt(ctx, (uint8_t *)(uintptr_t)data_out->buffer, &data_out_size,
        (uint8_t *)(uintptr_t)data_in->buffer, data_in->size);
    EVP_PKEY_free(evp_key); /* rsa_key will free together with evp_key, can not free it alone */
    EVP_PKEY_CTX_free(ctx);
    if (ret != BORINGSSL_OK || data_out_size > UINT32_MAX) {
        tloge("Evp rsa encrypt failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    data_out->size = (uint32_t)data_out_size;
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_rsa_encrypt(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (public_key == NULL || data_in == NULL || data_out == NULL || data_in->buffer == 0 ||
        data_out->buffer == 0 || (check_params(rsa_params) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct create_rsa_crypt_ctx_t rsa_encrypt_ctx = {0};
    int32_t padding = RSA_PKCS1_PADDING;
    uint32_t hash_len = 0;
    int32_t ret = convert_rsa_padding_to_boring(alg_type, &padding, &hash_len);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Convert rsa padding to boring failed\n");
        return ret;
    }

    rsa_encrypt_ctx.alg_type = alg_type;
    rsa_encrypt_ctx.mode = ENC_MODE;
    rsa_encrypt_ctx.padding = padding;

    return do_rsa_encrypt(&rsa_encrypt_ctx, rsa_params, public_key, data_in, data_out);
}

static int32_t do_rsa_decrypt(struct create_rsa_crypt_ctx_t *rsa_decrypt_ctx,
    const struct asymmetric_params_t *rsa_params, const struct rsa_priv_key_t *private_key,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    EVP_PKEY *evp_key = EVP_PKEY_new();
    if (evp_key == NULL) {
        tloge("Create rsa evp key failed\n");
        return get_soft_crypto_error(CRYPTO_ERROR_OUT_OF_MEMORY);
    }

    EVP_PKEY_CTX *ctx = create_rsa_decrypt_ctx(rsa_decrypt_ctx, rsa_params, private_key, evp_key);
    if (ctx == NULL) {
        tloge("Create rsa decrypt ctx failed\n");
        EVP_PKEY_free(evp_key); /* rsa_key will free together with evp_key, can not free it alone */
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    size_t data_out_size = data_in->size;
    int32_t ret = EVP_PKEY_decrypt(ctx, (uint8_t *)(uintptr_t)data_out->buffer, &data_out_size,
        (uint8_t *)(uintptr_t)data_in->buffer, data_in->size);
    EVP_PKEY_free(evp_key); /* rsa_key will free together with evp_key, can not free it alone */
    EVP_PKEY_CTX_free(ctx);
    if (ret != BORINGSSL_OK || data_out_size > UINT32_MAX) {
        tloge("Evp rsa decrypt failed, ret:%d\n", ret);
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    data_out->size = (uint32_t)data_out_size;
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_rsa_decrypt(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (private_key == NULL || data_in == NULL || data_out == NULL || data_in->buffer == 0 ||
        data_out->buffer == 0 || (check_params(rsa_params) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t padding = RSA_PKCS1_PADDING;
    uint32_t hash_len = 0;
    int32_t ret  = convert_rsa_padding_to_boring(alg_type, &padding, &hash_len);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Convert rsa padding to boring failed\n");
        return ret;
    }

    ret = check_rsa_decrypt_destlen(data_out->size, padding, private_key->n_len, hash_len);
    if (ret != CRYPTO_SUCCESS) {
        tloge("dest_len is invalid");
        return CRYPTO_SHORT_BUFFER;
    }

    struct create_rsa_crypt_ctx_t rsa_decrypt_ctx = {0};
    rsa_decrypt_ctx.alg_type = alg_type;
    rsa_decrypt_ctx.mode = DEC_MODE;
    rsa_decrypt_ctx.padding = padding;

    return do_rsa_decrypt(&rsa_decrypt_ctx, rsa_params, private_key, data_in, data_out);
}

int32_t soft_crypto_rsa_sign_digest(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *digest,
    struct memref_t *signature)
{
    bool check = (private_key == NULL || digest == NULL || signature == NULL || digest->buffer == 0 ||
        signature->buffer == 0 || (check_params(rsa_params) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }
    bool is_pss_sign_algorithm = check_is_rsa_pss_sign_algorithm(alg_type);
    if (is_pss_sign_algorithm)
        return soft_rsa_pss_sign_digest(alg_type, rsa_params, private_key, digest, signature);
    else
        return soft_rsa_non_pss_sign_digest(alg_type, private_key, digest, signature);
}

int32_t soft_crypto_rsa_verify_digest(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *digest,
    const struct memref_t *signature)
{
    bool check = (public_key == NULL || digest == NULL || signature == NULL || digest->buffer == 0 ||
        signature->buffer == 0 || (check_params(rsa_params) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }

    bool is_pss_verify_algorithm = check_is_rsa_pss_sign_algorithm(alg_type);
    if (is_pss_verify_algorithm)
        return soft_rsa_pss_verify_digest(alg_type, rsa_params, public_key, digest, signature);
    else
        return soft_rsa_non_pss_verify_digest(alg_type, public_key, digest, signature);
}
