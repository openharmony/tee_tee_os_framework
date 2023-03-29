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
#include "crypto_inner_interface.h"
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <rsa/rsa_local.h>
#include <openssl/ossl_typ.h>
#include "crypto/rand.h"
#include <openssl/crypto.h>
#include <securec.h>
#include <tee_log.h>
#include <tee_defines.h>
#include <tee_trusted_storage_api.h>
#include <crypto_inner_defines.h>

#define RSA_MAX_KEY_SIZE      4096
#define OPENSSL_OK            1
#define OPENSSL_ERROR_GENERIC (-1)
#define RSA_EXPONENT          65537

struct signature_info {
    uint8_t *in;
    uint32_t in_len;
    uint8_t *signature;
    uint32_t *sig_size;
};

#define BORINGSSL_ENCRYPT     1
#define BORINGSSL_DECRYPT     0
#define TIME_OUT              5000
#define MAX_SEED_LEN          128
#define SEED_BUF_LEN          (32 + 4 + 4)

#define RSA_MAX_KEY_SIZE      4096

static char g_sfs_prefix[] = "sec_storage/authentication/cert/";
typedef struct {
    uint32_t bits;
    uint8_t huk[HASH_LEN];
    uint32_t counter;
    uint32_t offset_p;
    uint32_t offset_q;
} huk_para_st;
typedef struct {
    uint8_t seed_buf[MAX_SEED_LEN];
    uint32_t seed_len;
    uint32_t counter;
} hrand_ctx;
struct ec_key_pair_bignum_t {
    BIGNUM *bn_n;
    BIGNUM *bn_e;
    BIGNUM *bn_d;
    BIGNUM *bn_p;
    BIGNUM *bn_q;
    BIGNUM *bn_dp;
    BIGNUM *bn_dq;
    BIGNUM *bn_qinv;
};

static TEE_Result convert_big_num_to_buffer(const BIGNUM *big_num, uint8_t *out, uint32_t *out_len)
{
    bool check = (big_num == NULL) || (out == NULL) || (out_len == NULL);
    if (check) {
        tloge("Invalid param in convert big num to buffer");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t big_num_len = (uint32_t)BN_num_bytes(big_num);
    if (*out_len < big_num_len) {
        tloge("The out length is less than big num length, out_len=%u, big_num_len=%u\n", *out_len, big_num_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    tlogd("Get big num length, big_num_len=%u\n", big_num_len);
    uint32_t write_len = (uint32_t)BN_bn2bin(big_num, out);
    if (write_len != big_num_len) {
        tloge("Convert big num to buffer failed, big_num_len=%u, write_len=%u\n", big_num_len, write_len);
        return TEE_ERROR_GENERIC;
    }
    *out_len = big_num_len;
    return TEE_SUCCESS;
}

static int rsakey2buf(const RSA *rsa_key, rsa_priv_key_t *priv, rsa_pub_key_t *pub)
{
    struct ec_key_pair_bignum_t big_num = { 0 };
    bool check = false;

    RSA_get0_key(rsa_key, (const BIGNUM **)&(big_num.bn_n), (const BIGNUM **)&(big_num.bn_e),
        (const BIGNUM **)&(big_num.bn_d));
    RSA_get0_factors(rsa_key, (const BIGNUM **)&(big_num.bn_p), (const BIGNUM **)&(big_num.bn_q));
    RSA_get0_crt_params(rsa_key, (const BIGNUM **)&(big_num.bn_dp), (const BIGNUM **)&(big_num.bn_dq),
        (const BIGNUM **)&(big_num.bn_qinv));

    if (pub != NULL) {
        check = (
            (convert_big_num_to_buffer(big_num.bn_n, pub->n, &(pub->n_len)) != TEE_SUCCESS) ||
            (convert_big_num_to_buffer(big_num.bn_e, pub->e, &(pub->e_len)) != TEE_SUCCESS));
        if (check)
            return -1;
    }
    if (priv != NULL) {
        check = (
            (convert_big_num_to_buffer(big_num.bn_n, priv->n, &(priv->n_len)) != TEE_SUCCESS) ||
            (convert_big_num_to_buffer(big_num.bn_e, priv->e, &(priv->e_len)) != TEE_SUCCESS) ||
            (convert_big_num_to_buffer(big_num.bn_d, priv->d, &(priv->d_len)) != TEE_SUCCESS) ||
            (convert_big_num_to_buffer(big_num.bn_p, priv->p, &(priv->p_len)) != TEE_SUCCESS) ||
            (convert_big_num_to_buffer(big_num.bn_q, priv->q, &(priv->q_len)) != TEE_SUCCESS) ||
            (convert_big_num_to_buffer(big_num.bn_dp, priv->dp, &(priv->dp_len)) != TEE_SUCCESS) ||
            (convert_big_num_to_buffer(big_num.bn_dq, priv->dq, &(priv->dq_len)) != TEE_SUCCESS) ||
            (convert_big_num_to_buffer(big_num.bn_qinv, priv->qinv, &(priv->qinv_len)) != TEE_SUCCESS));
        if (check)
            return -1;
    }
    return 0;
}

int32_t rsa_generate_keypair(rsa_priv_key_t *priv, rsa_pub_key_t *pub, uint32_t e, uint32_t key_size)
{
    bool check = (priv == NULL || pub == NULL);
    if (check)
        return -1;

    RSA *rsa_key = RSA_new();
    if (rsa_key == NULL) {
        tloge("Generate boring rsa key failed");
        return -1;
    }
    BIGNUM *big_e = BN_new();
    if (big_e == NULL) {
        tloge("new big_e failed");
        RSA_free(rsa_key);
        return -1;
    }
    int32_t ret = BN_set_word(big_e, e);
    if (ret != 1) {
        tloge("set e failed");
        ret = -1;
        goto error;
    }

    ret = RSA_generate_key_ex(rsa_key, key_size, big_e, NULL);
    if (ret != 1) {
        tloge("rsa generate key ex failed");
        ret = -1;
        goto error;
    }

    priv->n_len     = RSA_PUB_LEN;
    priv->e_len     = RSA_PUB_LEN;
    priv->d_len     = RSA_PUB_LEN;
    priv->p_len     = RSA_PRIV_LEN;
    priv->q_len     = RSA_PRIV_LEN;
    priv->dp_len    = RSA_PRIV_LEN;
    priv->dq_len    = RSA_PRIV_LEN;
    priv->qinv_len  = RSA_PRIV_LEN;
    pub->n_len      = RSA_PUB_LEN;
    pub->e_len      = RSA_PUB_LEN;
    ret = rsakey2buf(rsa_key, priv, pub);
    if (ret != 0)
        tloge("convert rsakey to buffer failed");
error:
    BN_free(big_e);
    RSA_free(rsa_key);
#ifdef OPENSSL_ENABLE
    drbg_delete_thread_state();
    OPENSSL_thread_stop();
#endif
    return ret;
}

static int32_t set_rsa_oaep_padding_hash(int32_t hash_nid, EVP_PKEY_CTX *ctx, int32_t padding)
{
    if (padding != RSA_PKCS1_OAEP_PADDING)
        return 1;

    const EVP_MD *md = EVP_get_digestbynid(hash_nid);
    if (md == NULL) {
        tloge("Get evp digest by nid failed, hash_nid=%d\n", hash_nid);
        return -1;
    }

    int32_t rc = EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md);
    if (rc != 1) {
        tloge("Evp rsa set oaep md failed\n");
        return -1;
    }

    /* The mgf1 hash is fixed sha1 in dx, so use sha1 for compatible in here */
    rc = EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha1());
    if (rc != 1) {
        tloge("Evp rsa set mgf1 md failed\n");
        return -1;
    }

    return 1;
}
static int32_t init_evp_rsa_ctx(EVP_PKEY_CTX *ctx, int32_t padding, int32_t mode, int32_t hash_nid)
{
    int32_t rc;
    if (mode == BORINGSSL_ENCRYPT)
        rc = EVP_PKEY_encrypt_init(ctx);
    else
        rc = EVP_PKEY_decrypt_init(ctx);
    if (rc != 1) {
        tloge("evp rsa init failed");
        return rc;
    }

    rc = EVP_PKEY_CTX_set_rsa_padding(ctx, padding);
    if (rc != 1) {
        tloge("Evp set rsa ctx padding failed\n");
        return rc;
    }
    rc = set_rsa_oaep_padding_hash(hash_nid, ctx, padding);
    if (rc != 1)
        tloge("Set rsa oaep padding failed\n");

    return rc;
}

static EVP_PKEY_CTX *get_pkey_ctx(EVP_PKEY *evp_key, uint32_t padding, int32_t hash_nid, uint32_t mode)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(evp_key, NULL);
    if (ctx == NULL) {
        tloge("Create rsa evp key ctx failed\n");
        return NULL;
    }

    int32_t ret = init_evp_rsa_ctx(ctx, padding, mode, hash_nid);
    if (ret != 1) {
        tloge("create and init rsa evp ctx failed");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

struct crypto_input_data {
    uint8_t *src_data;
    uint32_t src_len;
    uint8_t *dest_data;
    uint32_t *dest_len;
};

static int32_t do_rsa_encrypt(const struct crypto_input_data *rsa_encrypt_data, EVP_PKEY_CTX *ctx,
    uint32_t padding, const RSA *rsa_key)
{
    uint32_t rsa_size = (uint32_t)RSA_size(rsa_key);
    size_t temp_out_len = *(rsa_encrypt_data->dest_len);
    int32_t ret;

    if ((padding == RSA_NO_PADDING) && (rsa_encrypt_data->src_len < rsa_size)) {
        uint8_t *tmp = TEE_Malloc(rsa_size, 0);
        if (tmp == NULL) {
            tloge("malloc temp buff failed");
            return -1;
        }

        (void)memcpy_s(tmp + (rsa_size - rsa_encrypt_data->src_len), rsa_encrypt_data->src_len,
            rsa_encrypt_data->src_data, rsa_encrypt_data->src_len);
        ret = EVP_PKEY_encrypt(ctx, rsa_encrypt_data->dest_data, &temp_out_len, (const uint8_t *)tmp, (size_t)rsa_size);
        TEE_Free(tmp);
        tmp = NULL;
    } else {
        ret = EVP_PKEY_encrypt(ctx, rsa_encrypt_data->dest_data, &temp_out_len,
            (const uint8_t *)(rsa_encrypt_data->src_data), (size_t)(rsa_encrypt_data->src_len));
    }
    if (ret != 1) {
        tloge("rsa encrypt failed");
        return -1;
    }

    *(rsa_encrypt_data->dest_len) = (uint32_t)temp_out_len;
    return 1;
}
int32_t rsa_encrypt(uint8_t *dest_data, uint32_t *dest_len, uint8_t *src_data, uint32_t src_len, rsa_pub_key_t *pub,
                    int32_t padding, int32_t hash_nid)
{
    bool check = (dest_data == NULL || dest_len == NULL || src_data == NULL || pub == NULL ||
        *dest_len == 0 || src_len == 0);
    if (check)
        return -1;

    EVP_PKEY *evp_key = EVP_PKEY_new();
    if (evp_key == NULL) {
        tloge("Create rsa evp key failed");
        return -1;
    }

    RSA *rsa_key = build_boringssl_pub_key(pub);
    if (rsa_key == NULL) {
        tloge("rsa build pub key failed");
        EVP_PKEY_free(evp_key);
        return -1;
    }

    int32_t ret = EVP_PKEY_assign_RSA(evp_key, rsa_key);
    if (ret != 1) {
        tloge("Evp assign rsa key failed\n");
        RSA_free(rsa_key);
        EVP_PKEY_free(evp_key);
        return -1;
    }

    EVP_PKEY_CTX *ctx = get_pkey_ctx(evp_key, padding, hash_nid, BORINGSSL_ENCRYPT);
    if (ctx == NULL) {
        EVP_PKEY_free(evp_key); /* do not need to free rsa_key */
        return -1;
    }

    struct crypto_input_data rsa_encrypt_data = { 0 };
    rsa_encrypt_data.src_data = src_data;
    rsa_encrypt_data.src_len = src_len;
    rsa_encrypt_data.dest_data = dest_data;
    rsa_encrypt_data.dest_len = dest_len;

    ret = do_rsa_encrypt(&rsa_encrypt_data, ctx, padding, rsa_key);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evp_key);
#ifdef OPENSSL_ENABLE
    drbg_delete_thread_state();
    OPENSSL_thread_stop();
#endif
    if (ret != 1) {
        tloge("rsa encrypt failed");
        return -1;
    }

    return 0;
}

static void free_tmp_big_num(BIGNUM *bn_1, BIGNUM *bn_2, BIGNUM *bn_3, BIGNUM *bn_4)
{
    BN_free(bn_1);
    BN_free(bn_2);
    BN_free(bn_3);
    BN_free(bn_4);
}

static int32_t compute_rsa_ed_big_num(BIGNUM *bn_p, BIGNUM *bn_q, BN_CTX *ctx, BIGNUM **bn_e, BIGNUM **bn_d)
{
    BIGNUM *tmp1     = BN_dup(bn_p);
    BIGNUM *tmp2     = BN_dup(bn_q);
    BIGNUM *tmp3     = BN_new();
    BIGNUM *gcd      = BN_new();
    bool check = (tmp1 == NULL || tmp2 == NULL || tmp3 == NULL || gcd == NULL);
    if (check) {
        tloge("Duplicate or new big num failed\n");
        goto error;
    }

    check = ((BN_sub_word(tmp1, 1) != 1) || (BN_sub_word(tmp2, 1) != 1));
    if (check) {
        tloge("Big num sub 1 failed");
        goto error;
    }

    check = ((BN_gcd(gcd, tmp1, tmp2, ctx) != 1) || (BN_div(tmp1, tmp3, tmp1, gcd, ctx) != 1) ||
        (BN_mul(tmp2, tmp2, tmp1, ctx) != 1));
    if (check) {
        tloge("compute e and d failed");
        goto error;
    }

    /* Big num tmp4 is not new allocated, can not be free */
    BIGNUM *tmp4 = BN_mod_inverse(*bn_d, *bn_e, tmp2, ctx);
    if (tmp4 == NULL) {
        tloge("Get big num d by mod inverse failed\n");
        goto error;
    }

    free_tmp_big_num(tmp1, tmp2, tmp3, gcd);
    return 1;
error:
    free_tmp_big_num(tmp1, tmp2, tmp3, gcd);
    return 0;
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
        tloge("Mul big num failed\n");
        BN_CTX_free(ctx);
        return 0;
    }

    ret = compute_rsa_ed_big_num(bn_p, bn_q, ctx, bn_e, bn_d);
    BN_CTX_free(ctx);
    if (ret != 1) {
        tloge("Compute big num e and d failed\n");
        return 0;
    }

    return 1;
}
#define P_INDEX    0
#define Q_INDEX    1
#define DP_INDEX   2
#define DQ_INDEX   3
#define QINV_INDEX 4
static TEE_Result get_rsa_crt_big_num(const rsa_priv_key_t *priv, BIGNUM *bn_array[])
{
    bn_array[P_INDEX] = BN_bin2bn(priv->p, priv->p_len, NULL);
    if (bn_array[P_INDEX] == NULL) {
        tloge("Change crt buffer num to big num failed");
        return TEE_ERROR_GENERIC;
    }

    bn_array[Q_INDEX] = BN_bin2bn(priv->q, priv->q_len, NULL);
    if (bn_array[Q_INDEX] == NULL) {
        tloge("Change crt buffer num to big num failed");
        return TEE_ERROR_GENERIC;
    }

    bn_array[DP_INDEX] = BN_bin2bn(priv->dp, priv->dp_len, NULL);
    if (bn_array[DP_INDEX] == NULL) {
        tloge("Change crt buffer num to big num failed");
        return TEE_ERROR_GENERIC;
    }

    bn_array[DQ_INDEX] = BN_bin2bn(priv->dq, priv->dq_len, NULL);
    if (bn_array[DQ_INDEX] == NULL) {
        tloge("Change crt buffer num to big num failed");
        return TEE_ERROR_GENERIC;
    }

    bn_array[QINV_INDEX] = BN_bin2bn(priv->qinv, priv->qinv_len, NULL);
    if (bn_array[QINV_INDEX] == NULL) {
        tloge("Change crt buffer num to big num failed");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}
#define RSA_P_INDEX    0
#define RSA_Q_INDEX    1
#define RSA_DP_INDEX   2
#define RSA_DQ_INDEX   3
#define RSA_QINV_INDEX 4
static RSA *set_boring_rsa_key(BIGNUM *bn_n, BIGNUM *bn_e, BIGNUM *bn_d, BIGNUM *bn_array[])
{
    RSA *rsa_key = RSA_new();
    if (rsa_key == NULL) {
        tloge("Malloc memory for rsa key failed\n");
        return NULL;
    }

    int32_t ret1 = RSA_set0_key(rsa_key, bn_n, bn_e, bn_d);
    int32_t ret2 = RSA_set0_factors(rsa_key, bn_array[RSA_P_INDEX], bn_array[RSA_Q_INDEX]);
    int32_t ret3 = RSA_set0_crt_params(rsa_key, bn_array[RSA_DP_INDEX], bn_array[RSA_DQ_INDEX],
        bn_array[RSA_QINV_INDEX]);

    bool is_abnormal = (ret1 != 1 || ret2 != 1 || ret3 != 1);
    if (is_abnormal) {
        tloge("Set rsa key failed, ret1=0x%x, ret2=0x%x, ret3=0x%x\n", ret1, ret2, ret3);
        RSA_free(rsa_key);
        return NULL;
    }

    return rsa_key;
}

static int32_t builed_rsa_key_no_crt(const rsa_priv_key_t *priv, RSA **rsa_key)
{
    BIGNUM *bn_n = BN_bin2bn(priv->n, priv->n_len, NULL);
    BIGNUM *bn_e = BN_bin2bn(priv->e, priv->e_len, NULL);
    BIGNUM *bn_d = BN_bin2bn(priv->d, priv->d_len, NULL);

    bool is_abnormal = (bn_n == NULL) || (bn_e == NULL) || (bn_d == NULL);
    if (is_abnormal) {
        tloge("New big num n or e or d failed\n");
        free_tmp_big_num(bn_n, bn_e, bn_d, NULL);
        return -1;
    }

    *rsa_key = RSA_new();
    if (*rsa_key == NULL) {
        tloge("Malloc memory for rsa key failed\n");
        free_tmp_big_num(bn_n, bn_e, bn_d, NULL);
        return -1;
    }
    int32_t rc = RSA_set0_key(*rsa_key, bn_n, bn_e, bn_d);
    if (rc != 1) {
        tloge("Set rsa key failed");
        free_tmp_big_num(bn_n, bn_e, bn_d, NULL);
        RSA_free(*rsa_key);
        return -1;
    }
    return 1;
}

static int32_t builed_rsa_key_crt(const rsa_priv_key_t *priv, RSA **rsa_key)
{
    BIGNUM *bn_n = BN_new();
    BIGNUM *bn_e = BN_bin2bn(priv->e, priv->e_len, NULL);
    BIGNUM *bn_d = BN_new();
    BIGNUM *bn_array[RSA_CRT_KEY_ATTRIBUTE_COUNT] = { 0 };

    bool is_abnormal = (bn_n == NULL) || (bn_e == NULL) || (bn_d == NULL);
    if (is_abnormal) {
        tloge("New big num n or e or d failed\n");
        free_tmp_big_num(bn_n, bn_e, bn_d, NULL);
        return -1;
    }

    int32_t ret = (int32_t)get_rsa_crt_big_num(priv, bn_array);
    if (ret != TEE_SUCCESS) {
        tloge("Change crt buffer num to big num failed");
        free_tmp_big_num(bn_n, bn_e, bn_d, bn_array[RSA_FACTOR_P_INDEX]);
        free_tmp_big_num(bn_array[RSA_FACTOR_Q_INDEX], bn_array[RSA_CRT_DMP1],
            bn_array[RSA_CRT_DMQ1], bn_array[RSA_CRT_IQMP]);
        return -1;
    }

    ret = get_rsa_ned_big_num(bn_array[RSA_FACTOR_P_INDEX], bn_array[RSA_FACTOR_Q_INDEX], &bn_n, &bn_e, &bn_d);
    if (ret != 1) {
        tloge("Get big num n, e, d failed\n");
        free_tmp_big_num(bn_n, bn_e, bn_d, bn_array[RSA_FACTOR_P_INDEX]);
        free_tmp_big_num(bn_array[RSA_FACTOR_Q_INDEX], bn_array[RSA_CRT_DMP1],
            bn_array[RSA_CRT_DMQ1], bn_array[RSA_CRT_IQMP]);
        return -1;
    }

    *rsa_key = set_boring_rsa_key(bn_n, bn_e, bn_d, bn_array);
    if (*rsa_key == NULL) {
        tloge("Set boring rsa key failed");
        free_tmp_big_num(bn_n, bn_e, bn_d, bn_array[RSA_FACTOR_P_INDEX]);
        free_tmp_big_num(bn_array[RSA_FACTOR_Q_INDEX], bn_array[RSA_CRT_DMP1],
            bn_array[RSA_CRT_DMQ1], bn_array[RSA_CRT_IQMP]);
        return -1;
    }
    return 1;
}

RSA *build_boringssl_priv_key(rsa_priv_key_t *priv)
{
    if (priv == NULL) {
        tloge("priv is NULL");
        return NULL;
    }

    RSA *rsa_key = NULL;
    int32_t ret;

    if (priv->d_len != 0)
        ret = builed_rsa_key_no_crt(priv, &rsa_key);
    else
        ret = builed_rsa_key_crt(priv, &rsa_key);

    if (ret != 1) {
        tloge("build rsa private key failed");
        return NULL;
    }
    return rsa_key;
}

static int32_t do_rsa_decrypt(const struct crypto_input_data *rsa_decrypt_data, EVP_PKEY_CTX *ctx,
    uint32_t padding, const RSA *rsa_key)
{
    size_t temp_out_len = *(rsa_decrypt_data->dest_len);
    uint32_t rsa_size = (uint32_t)RSA_size(rsa_key);
    int32_t ret;

    /* for keymaster: when do rsa nopadding sign, we should add zeros before src_data */
    if ((padding == RSA_NO_PADDING) && (rsa_decrypt_data->src_len < rsa_size)) {
        uint8_t *tmp = TEE_Malloc(rsa_size, 0);
        if (tmp == NULL) {
            tloge("Malloc failed");
            return -1;
        }
        (void)memcpy_s(tmp + (rsa_size - rsa_decrypt_data->src_len), rsa_decrypt_data->src_len,
            rsa_decrypt_data->src_data, rsa_decrypt_data->src_len);
        ret = EVP_PKEY_decrypt(ctx, rsa_decrypt_data->dest_data, &temp_out_len, (const uint8_t *)tmp, (size_t)rsa_size);
        TEE_Free(tmp);
        tmp = NULL;
    } else {
        ret = EVP_PKEY_decrypt(ctx, rsa_decrypt_data->dest_data, &temp_out_len,
            (const uint8_t *)(rsa_decrypt_data->src_data), (size_t)(rsa_decrypt_data->src_len));
    }

    if (ret != 1) {
        uint32_t boringssl_err = ERR_peek_last_error();
        tloge("do rsa decrypt failed, boringssl err %u, reason %d\n", boringssl_err, ERR_GET_REASON(boringssl_err));
        /* for keymaster vts */
        if (ERR_GET_REASON(boringssl_err) == RSA_R_DATA_TOO_LARGE_FOR_MODULUS)
            return RSA_R_DATA_TOO_LARGE_FOR_MODULUS;
        return ret;
    }

    *(rsa_decrypt_data->dest_len) = (uint32_t)temp_out_len;
    return 1;
}

int32_t rsa_decrypt(uint8_t *dest_data, uint32_t *dest_len, uint8_t *src_data, uint32_t src_len, rsa_priv_key_t *priv,
                    uint32_t padding, int32_t hash_nid)
{
    bool check = (dest_data == NULL || dest_len == NULL || src_data == NULL || priv == NULL ||
        *dest_len == 0 || src_len == 0);
    if (check)
        return -1;

    RSA *rsa_key = build_boringssl_priv_key(priv);
    if (rsa_key == NULL) {
        tloge("rsa build priv key failed");
        return -1;
    }

    EVP_PKEY *evp_key = EVP_PKEY_new();
    if (evp_key == NULL) {
        tloge("new pkey failed");
        RSA_free(rsa_key);
        return -1;
    }

    int32_t ret = EVP_PKEY_assign_RSA(evp_key, rsa_key);
    if (ret != 1) {
        tloge("Evp assign rsa key failed\n");
        RSA_free(rsa_key);
        EVP_PKEY_free(evp_key);
        return -1;
    }
    EVP_PKEY_CTX *ctx = get_pkey_ctx(evp_key, padding, hash_nid, BORINGSSL_DECRYPT);
    if (ctx == NULL) {
        EVP_PKEY_free(evp_key);
        return -1;
    }

    struct crypto_input_data rsa_decrypt_data = { 0 };
    rsa_decrypt_data.src_data = src_data;
    rsa_decrypt_data.src_len = src_len;
    rsa_decrypt_data.dest_data = dest_data;
    rsa_decrypt_data.dest_len = dest_len;

    ret = do_rsa_decrypt(&rsa_decrypt_data, ctx, padding, rsa_key);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evp_key);
#ifdef OPENSSL_ENABLE
    drbg_delete_thread_state();
    OPENSSL_thread_stop();
#endif
    if (ret != 1) {
        tloge("rsa decrypt failed");
        if (ret == RSA_R_DATA_TOO_LARGE_FOR_MODULUS)
            return ret; /* vts require this error code */
        return -1;
    }

    return 0;
}

static int32_t rsa_pss_sign_digest(RSA *rsa_key, uint32_t salt_len, int32_t hash_nid,
    struct signature_info *sig_info)
{
    const EVP_MD *md = EVP_get_digestbynid(hash_nid);
    if (md == NULL) {
        tloge("Get evp digest by nid failed\n");
        return 0;
    }
    uint32_t em_len = (uint32_t)RSA_size(rsa_key);
    if (em_len > RSA_MAX_KEY_SIZE) {
        tloge("key size is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t *em_buf = TEE_Malloc(em_len, 0);
    if (em_buf == NULL) {
        tloge("Malloc em buf failed, em_len=%u\n", em_len);
        return 0;
    }
    int rc = RSA_padding_add_PKCS1_PSS_mgf1(rsa_key, em_buf, sig_info->in, md, md, salt_len);
    if (rc != OPENSSL_OK) {
        tloge("Rsa padding add pss mgf1 failed, rc=%d\n", rc);
        TEE_Free(em_buf);
        return 0;
    }
    int out_len = RSA_private_encrypt(em_len, em_buf, sig_info->signature, rsa_key, RSA_NO_PADDING);
    TEE_Free(em_buf);
    em_buf = NULL;
    if (out_len < 0) {
        tloge("Rsa pss sign failed, rc=%d\n", out_len);
        return 0;
    }
    *(sig_info->sig_size) = out_len;

    tlogd("Soft rsa sign pss digest success\n");
    return OPENSSL_OK;
}

int32_t rsa_sign_digest(uint8_t *signature, uint32_t *sig_size, uint8_t *in, uint32_t in_len, rsa_priv_key_t *priv,
                        uint32_t salt_len, int32_t hash_nid, int32_t padding)
{
    bool check = (signature == NULL || sig_size == NULL || in == NULL || priv == NULL ||
        *sig_size == 0 || in_len == 0);
    if (check) {
        tloge("param is invalid!");
        return -1;
    }

    check = (padding == RSA_PKCS1_PSS_PADDING || padding == RSA_PKCS1_PADDING);
    if (!check) {
        tloge("padding is invalid");
        return -1;
    }

    RSA *rsa_key = build_boringssl_priv_key(priv);
    if (rsa_key == NULL) {
        tloge("rsa build priv key failed");
        return -1;
    }

    int32_t rc;
    int32_t ret;

    if (padding == RSA_PKCS1_PSS_PADDING) {
        struct signature_info sig_info = {0};
        sig_info.in = in;
        sig_info.signature = signature;
        sig_info.sig_size = sig_size;
        rc = rsa_pss_sign_digest(rsa_key, salt_len, hash_nid, &sig_info);
    } else {
        rc = RSA_sign(hash_nid, in, in_len, signature, sig_size, rsa_key);
    }
    if (rc != 1) {
        tloge("rsa sign digest failed!");
        ret = -1;
        goto error;
    }

    ret = 0;
error:
    RSA_free(rsa_key);
#ifdef OPENSSL_ENABLE
    drbg_delete_thread_state();
    OPENSSL_thread_stop();
#endif
    return ret;
}
static int32_t rsa_pss_verify_digest(RSA *rsa_key, uint32_t salt_len, int32_t hash_nid,
                                     const struct signature_info *sig_info, uint32_t sig_size)
{
    uint32_t em_len = (uint32_t)RSA_size(rsa_key);
    if (em_len > RSA_MAX_KEY_SIZE) {
        tloge("key size is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    const EVP_MD *md = EVP_get_digestbynid(hash_nid);
    if (md == NULL) {
        tloge("Get evp digest by nid failed\n");
        return 0;
    }

    uint8_t *em_buf = TEE_Malloc(em_len, 0);
    if (em_buf == NULL) {
        tloge("Malloc em buf failed, em_len=%u\n", em_len);
        return 0;
    }
    int rc = RSA_public_decrypt(sig_size, sig_info->signature, em_buf, rsa_key, RSA_NO_PADDING);
    if (rc <= 0) {
        tloge("Rsa proc failed, rc=%d\n", rc);
        TEE_Free(em_buf);
        return 0;
    }
    rc = RSA_verify_PKCS1_PSS_mgf1(rsa_key, sig_info->in, md, md, em_buf, salt_len);
    TEE_Free(em_buf);
    em_buf = NULL;
    if (rc != OPENSSL_OK) {
        tloge("Rsa pss verify failed, rc=%d\n", rc);
        return 0;
    }

    return OPENSSL_OK;
}

RSA *build_boringssl_pub_key(rsa_pub_key_t *pub)
{
    if (pub == NULL) {
        tloge("pub is NULL");
        return NULL;
    }

    int32_t ret;
    BIGNUM *bn_n = BN_bin2bn(pub->n, pub->n_len, NULL);
    BIGNUM *bn_e = BN_bin2bn(pub->e, pub->e_len, NULL);
    if ((bn_n == NULL) || (bn_e == NULL)) {
        tloge("Change pub buffer num to big num failed");
        goto error;
    }

    RSA *rsa_key = RSA_new();
    if (rsa_key == NULL) {
        tloge("Malloc memory for rsa key failed");
        goto error;
    }

    ret = RSA_set0_key(rsa_key, bn_n, bn_e, NULL);
    if (ret != 1) {
        tloge("set rsa key failed");
        RSA_free(rsa_key);
        goto error;
    }
    return rsa_key;
error:
    BN_free(bn_n);
    BN_free(bn_e);
    return NULL;
}

int32_t rsa_verify_digest(uint8_t *signature, uint32_t sig_size, uint8_t *in, uint32_t in_len, const rsa_pub_key_t *pub,
                          uint32_t salt_len, int32_t hash_nid, int32_t padding)
{
    bool check = (signature == NULL || in == NULL || pub == NULL || sig_size == 0 || in_len == 0);
    if (check) {
        tloge("param is invalid!");
        return -1;
    }

    check = (padding == RSA_PKCS1_PSS_PADDING || padding == RSA_PKCS1_PADDING);
    if (!check) {
        tloge("padding is invalid");
        return -1;
    }

    RSA *rsa_key = build_boringssl_pub_key((rsa_pub_key_t *)pub);
    if (rsa_key == NULL) {
        tloge("rsa build pub key failed");
        return -1;
    }

    int32_t rc = 0;
    int32_t ret;

    if (padding == RSA_PKCS1_PSS_PADDING) {
        struct signature_info sig_info = {0};
        sig_info.in = in;
        sig_info.signature = signature;
        rc = rsa_pss_verify_digest(rsa_key, salt_len, hash_nid, &sig_info, sig_size);
    } else if (padding == RSA_PKCS1_PADDING) {
        rc = RSA_verify(hash_nid, in, in_len, signature, sig_size, rsa_key);
    }
    if (rc != 1) {
        tloge("rsa verify digest failed!");
        ret = -1;
        goto error;
    }

    ret = 0;
error:
    RSA_free(rsa_key);
#ifdef OPENSSL_ENABLE
    drbg_delete_thread_state();
    OPENSSL_thread_stop();
#endif
    return ret;
}

static TEE_ObjectHandle __ss_file_open(const char *filename, uint32_t mode)
{
    TEE_ObjectHandle handle = NULL;
    bool check              = (filename == NULL) || (mode == 0);
    if (check)
        return NULL;

    mode |= TEE_DATA_FLAG_AES256;
    if (mode & TEE_DATA_FLAG_CREATE) {
        if (TEE_CreatePersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)filename, strlen(filename), mode,
            TEE_HANDLE_NULL, NULL, 0, &handle) != TEE_SUCCESS) {
            tloge("!!ss file create failed:%s\n", filename);
            return NULL;
        } else {
            tlogd("ss file create successfully:%s\n", filename);
        }

        if (TEE_TruncateObjectData(handle, 0) != TEE_SUCCESS) {
            tloge("ss file truncate failed:%s\n", filename);
            TEE_CloseObject(handle);
            return NULL;
        }
    } else {
        TEE_Result ret =
            TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)filename, strlen(filename), mode, &handle);
        if (ret != TEE_SUCCESS) {
            if (ret == TEE_ERROR_ITEM_NOT_FOUND)
                tloge("file: %s not exist!\n", filename);
            return NULL;
        }
    }

    return handle;
}

static int __ss_file_close(TEE_ObjectHandle handle, uint32_t mode)
{
    TEE_Result ret = TEE_SUCCESS;
    if (handle == NULL)
        return TEE_FAIL;

    if (mode & TEE_DATA_FLAG_ACCESS_WRITE) {
        ret = TEE_SyncPersistentObject(handle);
        if (ret != TEE_SUCCESS) {
            tloge("TEE_SyncPersistentObject failed\n");
            ret = TEE_FAIL;
            goto error;
        }
    }

error:
    TEE_CloseObject(handle);
    return (int)ret;
}

static int do_ss_file_write(const char *filename, const char *buf, unsigned int len)
{
    tlogd("ss file write into:%s\n", filename);

    bool check = (filename == NULL) || (buf == NULL) || (len == 0);
    if (check)
        return 0;
    uint32_t mode           = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_CREATE;
    TEE_ObjectHandle handle = __ss_file_open(filename, mode);
    int ret                 = 0;

    if (handle == NULL)
        return 0;

    if (TEE_WriteObjectData(handle, (void *)buf, len) == TEE_SUCCESS)
        ret = (int)len;
    else
        tloge("ss file write failed,  filename = %s\n", filename);

    if (__ss_file_close(handle, mode))
        return 0;
    return ret;
}
#define FILE_LEN 256
static int write_offset(const uint8_t *file_name, const huk_para_st *h)
{
    bool check = (file_name == NULL) || (h == NULL);
    if (check) {
        tloge("input invalid\n");
        return -1;
    }

    if (strlen((char *)file_name) > FILE_LEN) {
        tloge("strlen(file_name) too long");
        return -1;
    }

    uint32_t size;
    uint8_t bak_name[FILE_LEN] = { 0 };
    uint32_t storage_region    = 1;
    errno_t rc;

    if (storage_region != 0) {
        if (strlen((char *)file_name) > (FILE_LEN - 1 - strlen(g_sfs_prefix))) {
            tloge("file_name too long");
            return -1;
        }

        if (memcpy_s(bak_name, FILE_LEN, g_sfs_prefix, strlen(g_sfs_prefix)) != EOK) {
            tloge("memcpy_s failed");
            return -1;
        }

        rc = memcpy_s(bak_name + strlen(g_sfs_prefix), FILE_LEN - strlen(g_sfs_prefix), file_name,
                      strlen((char *)file_name));
        if (rc != EOK) {
            tloge("memcpy_s failed");
            return -1;
        }

        size = (uint32_t)do_ss_file_write((char *)bak_name, (char *)h, sizeof(*h));
        if (size != sizeof(*h)) {
            tloge("do_ss_file_write failed");
            return -1;
        }
    }
    return 0;
}
#define MSB_VALUE 0xc0
#define SEED_LEN  32
static void key_convert(rsa_priv_key_t *rsa, const RSA *rsa_ctx)
{
    if ((rsa == NULL) || (rsa_ctx == NULL))
        return;

    rsa->n_len    = RSA_PUB_LEN;
    rsa->e_len    = RSA_PUB_LEN;
    rsa->d_len    = RSA_PUB_LEN;
    rsa->p_len    = RSA_PRIV_LEN;
    rsa->q_len    = RSA_PRIV_LEN;
    rsa->dp_len   = RSA_PRIV_LEN;
    rsa->dq_len   = RSA_PRIV_LEN;
    rsa->qinv_len = RSA_PRIV_LEN;

    if (convert_big_num_to_buffer(rsa_ctx->n, rsa->n, &(rsa->n_len)) != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "n to buffer fail");
        return;
    }
    if (convert_big_num_to_buffer(rsa_ctx->e, rsa->e, &(rsa->e_len)) != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "n to buffer fail");
        return;
    }
    if (convert_big_num_to_buffer(rsa_ctx->d, rsa->d, &(rsa->d_len)) != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "n to buffer fail");
        return;
    }
    if (convert_big_num_to_buffer(rsa_ctx->p, rsa->p, &(rsa->p_len)) != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "n to buffer fail");
        return;
    }
    if (convert_big_num_to_buffer(rsa_ctx->q, rsa->q, &(rsa->q_len)) != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "n to buffer fail");
        return;
    }
    if (convert_big_num_to_buffer(rsa_ctx->dmp1, rsa->dp, &(rsa->dp_len)) != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "n to buffer fail");
        return;
    }
    if (convert_big_num_to_buffer(rsa_ctx->dmq1, rsa->dq, &(rsa->dq_len)) != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "n to buffer fail");
        return;
    }
    if (convert_big_num_to_buffer(rsa_ctx->iqmp, rsa->qinv, &(rsa->qinv_len)) != TEE_SUCCESS) {
        tloge("soft_enine: %s\n", "n to buffer fail");
        return;
    }
}

static RSA *generate_rsa_key(BIGNUM *big_e, uint32_t nbits)
{
    RSA *rsa_priv = RSA_new();
    if (rsa_priv == NULL) {
        tloge("rsa new failed");
        return NULL;
    }

    big_e = BN_new();
    if (big_e == NULL) {
        tloge("new big_e failed");
        RSA_free(rsa_priv);
        return NULL;
    }

    int32_t ret = BN_set_word(big_e, RSA_EXPONENT);
    if (ret != OPENSSL_OK) {
        tloge("set pub failed\n");
        BN_free(big_e);
        RSA_free(rsa_priv);
        return NULL;
    }

    ret = RSA_generate_key_ex(rsa_priv, nbits, big_e, NULL);
    BN_free(big_e);
    big_e = NULL;
    if (ret != 1) {
        tloge("RSA_generate_key_ex failed");
        RSA_free(rsa_priv);
        return NULL;
    }
    return rsa_priv;
}
int generate_rsa_from_secret(rsa_priv_key_t *rsa, uint32_t nbits, uint8_t *secret, uint32_t secret_len,
    const uint8_t *file_name)
{
    bool check = (rsa == NULL || secret == NULL || secret_len != HASH_LEN);
    if (check) {
        tloge("param is invalid");
        return -1;
    }

    BIGNUM *big_e = NULL;
    RSA *rsa_priv = generate_rsa_key(big_e, nbits);
    if (rsa_priv == NULL) {
        tloge("genearte rsa key failed");
        return -1;
    }
    huk_para_st h;
    h.bits     = nbits;
    errno_t rc = memcpy_s(h.huk, HASH_LEN, secret, secret_len);
    if (rc != EOK) {
        tloge("memcpy failed");
        BN_free(big_e);
        RSA_free(rsa_priv);
        return -1;
    }
    h.counter  = 1;
    h.offset_p = nbits / CRYPTO_NUMBER_TWO;
    h.offset_q = nbits / CRYPTO_NUMBER_TWO;

    if (file_name != NULL) {
        if (write_offset(file_name, &h) != 0) {
            tloge("write_rsa_file failed\n");
            BN_free(big_e);
            RSA_free(rsa_priv);
            return -1;
        }
    }
    key_convert(rsa, rsa_priv);
    BN_free(big_e);
    RSA_free(rsa_priv);
#ifdef OPENSSL_ENABLE
    drbg_delete_thread_state();
    OPENSSL_thread_stop();
#endif
    return 1;
}

int rsa_import_priv(rsa_priv_key_t *priv, const uint8_t *in, uint32_t in_len)
{
    if (priv == NULL || in == NULL) {
        tloge("param is NULL");
        return -1;
    }

    EVP_PKEY *evp_key = NULL;
    evp_key = d2i_PrivateKey(EVP_PKEY_RSA, &evp_key, &in, in_len);
    if (evp_key == NULL) {
        tloge("get evp key fail");
        return -1;
    }

    RSA *rsa_priv = EVP_PKEY_get0_RSA(evp_key);
    if (rsa_priv == NULL) {
        tloge("get rsa key fail");
        return -1;
    }

    priv->n_len     = RSA_PUB_LEN;
    priv->e_len     = RSA_PUB_LEN;
    priv->d_len     = RSA_PUB_LEN;
    priv->p_len     = RSA_PRIV_LEN;
    priv->q_len     = RSA_PRIV_LEN;
    priv->dp_len    = RSA_PRIV_LEN;
    priv->dq_len    = RSA_PRIV_LEN;
    priv->qinv_len  = RSA_PRIV_LEN;

    int32_t ret = rsakey2buf(rsa_priv, priv, NULL);
    if (ret != 0)
        tloge("key to buffer failed");

    EVP_PKEY_free(evp_key);
#ifdef OPENSSL_ENABLE
    drbg_delete_thread_state();
    OPENSSL_thread_stop();
#endif
    return ret;
}
int32_t rsa_export_pub_sp(uint8_t *out, uint32_t out_size, rsa_pub_key_t *pub)
{
    if (out == NULL || pub == NULL) {
        tloge("param is NULL");
        return -1;
    }

    RSA *boring_rsa = build_boringssl_pub_key(pub);
    if (boring_rsa == NULL) {
        tloge("build boringssl pub_key fail");
        return -1;
    }
    EVP_PKEY *evp_key = EVP_PKEY_new();
    if (evp_key == NULL) {
        tloge("Create rsa evp key failed\n");
        RSA_free(boring_rsa);
        return -1;
    }
    int32_t rc = EVP_PKEY_assign_RSA(evp_key, boring_rsa);
    if (rc != 1) {
        tloge("Evp assign rsa key failed\n");
        RSA_free(boring_rsa);
        EVP_PKEY_free(evp_key);
        return -1;
    }
    int32_t len = i2d_PUBKEY(evp_key, (unsigned char **)NULL);
    if (len > (int32_t)out_size) {
        tloge("invalid out_size size, %u", out_size);
        EVP_PKEY_free(evp_key);
        return -1;
    }
    uint8_t *tmp_out = out;
    len              = i2d_PUBKEY(evp_key, &tmp_out);
    EVP_PKEY_free(evp_key);
#ifdef OPENSSL_ENABLE
    drbg_delete_thread_state();
    OPENSSL_thread_stop();
#endif
    return len;
}
