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
#include "tee_elf_verify_openssl.h"
#include "tee_log.h"
#include "securec.h"
#include "ta_load_key.h"
#include "tee_v3_elf_verify.h"
#include "wb_aes_decrypt.h"
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <evp/evp_local.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/ecdh.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include "tee_load_key_ops.h"
#include <tee_crypto_signature_verify.h>
#include "wb_tool_root_key.h"

static const char *g_ecies_hmac_salt = "salt for ecies kdf";

TEE_Result tee_secure_img_decrypt_cipher_layer(const uint8_t *cipher_layer, uint32_t cipher_size,
    uint8_t *plaintext_layer, uint32_t *plaintext_size)
{
    bool check = (cipher_layer == NULL || cipher_size == 0 || plaintext_layer == NULL ||
        plaintext_size == NULL || *plaintext_size < cipher_size);
    if (check)
        return TEE_ERROR_BAD_PARAMETERS;

    enum ta_type type = V3_TYPE_2048;
    if (judge_rsa_key_type(cipher_size, &type) != TEE_SUCCESS)
        return TEE_ERROR_BAD_PARAMETERS;

    RSA *ta_load_priv_key = NULL;

    ta_load_priv_key = get_private_key(CIPHER_LAYER_VERSION, type);
    if (ta_load_priv_key == NULL)
        return TEE_ERROR_GENERIC;
    /* key size 2048, RSA OAEP mode */
    int32_t out_len = RSA_private_decrypt(cipher_size, (const uint8_t *)cipher_layer, (uint8_t *)plaintext_layer,
                                          ta_load_priv_key, RSA_PKCS1_OAEP_PADDING);

    free_private_key(ta_load_priv_key);
    ta_load_priv_key = NULL;

    if (out_len < 0) {
        tloge("Failed to decrypt cipher layer of TA image: cipher len=%u\n", get_v3_cipher_layer_len());
        return TEE_ERROR_GENERIC;
    }

    *plaintext_size = (uint32_t)out_len;
    return TEE_SUCCESS;
}

void print_ta_sign_algorithm_info(const struct sign_config_t *config)
{
    if (config == NULL)
        return;

    ta_cipher_layer_t *ta_cipher_layer = get_ta_cipher_layer();

    tloge("sec config info:sign_alg=0x%x, key_len=%u, hash_size=%zu, hash_padding=%s, key_style=%s\n",
        ta_cipher_layer->cipher_hdr.signature_alg, config->key_len, config->hash_size,
        config->padding == RSA_PKCS1_PSS_PADDING ? "PKCS1_PSS" : "PKCS1",
        config->key_style == PUB_KEY_RELEASE ? "release" : "debug");
}

static void free_rsa_bn_n(BIGNUM *bn_n, BIGNUM *bn_e, BIGNUM *bn_d, BIGNUM *bn_p)
{
    BN_free(bn_n);
    BN_free(bn_e);
    BN_free(bn_d);
    BN_free(bn_p);
}

static void free_rsa_bn_q(BIGNUM *bn_q, BIGNUM *bn_dp, BIGNUM *bn_dq, BIGNUM *bn_qinv)
{
    BN_free(bn_q);
    BN_free(bn_dp);
    BN_free(bn_dq);
    BN_free(bn_qinv);
}

static int32_t compute_rsa_big_num_ed(const BIGNUM *bn_p, const BIGNUM *bn_q, BN_CTX *ctx, BIGNUM **bn_e,
                                      BIGNUM **bn_d)
{
    BIGNUM *tmp1 = BN_dup(bn_p);
    BIGNUM *tmp2 = BN_dup(bn_q);
    BIGNUM *tmp3 = BN_new();
    BIGNUM *gcd = BN_new();
    bool is_abnormal = (tmp1 == NULL) || (tmp2 == NULL) || (tmp3 == NULL) || (gcd == NULL);
    if (is_abnormal) {
        tloge("Duplicate or new big num failed\n");
        goto error;
    }

    int32_t ret1 = BN_sub_word(tmp1, 1);
    int32_t ret2 = BN_sub_word(tmp2, 1);
    is_abnormal = (ret1 != 1) || (ret2 != 1);
    if (is_abnormal) {
        tloge("Big num sub 1 failed, ret1=%d, ret2=%d\n", ret1, ret2);
        goto error;
    }

    ret1 = BN_gcd(gcd, tmp1, tmp2, ctx);
    ret2 = BN_div(tmp1, tmp3, tmp1, gcd, ctx);
    is_abnormal = (ret1 != 1) || (ret2 != 1);
    if (is_abnormal) {
        tloge("Big num gcd div failed, ret1=%d, ret2=%d\n", ret1, ret2);
        goto error;
    }
    ret1 = BN_set_word(*bn_e, RSA_F4);
    ret2 = BN_mul(tmp2, tmp2, tmp1, ctx);
    is_abnormal = (ret1 != 1) || (ret2 != 1);
    if (is_abnormal) {
        tloge("compute e and d failed, ret1=%d, ret2=%d\n", ret1, ret2);
        goto error;
    }
    /* BN_mod_inverse return value is not new allocated, can not be free */
    if (BN_mod_inverse(*bn_d, *bn_e, tmp2, ctx) == NULL) {
        tloge("Get big num d by mod inverse failed\n");
        goto error;
    }

    free_rsa_bn_n(tmp1, tmp2, tmp3, gcd);
    return 1;
error:
    free_rsa_bn_n(tmp1, tmp2, tmp3, gcd);
    return 0;
}

static int32_t get_rsa_big_num_ned(const BIGNUM *bn_p, const BIGNUM *bn_q, BIGNUM **bn_n, BIGNUM **bn_e,
                                   BIGNUM **bn_d)
{
    BN_CTX *ctx = BN_CTX_new();
    if (ctx == NULL) {
        tloge("New bn ctx fail\n");
        return 0;
    }

    int32_t ret = BN_mul(*bn_n, bn_p, bn_q, ctx);
    if (ret != 1) {
        tloge("Mul big num fail\n");
        BN_CTX_free(ctx);
        return 0;
    }

    ret = compute_rsa_big_num_ed(bn_p, bn_q, ctx, bn_e, bn_d);
    BN_CTX_free(ctx);
    if (ret != 1) {
        tloge("Compute big num e and d failed\n");
        return 0;
    }

    return 1;
}

static int32_t get_rsa_big_num_n(BIGNUM *bn_p, BIGNUM *bn_q, BIGNUM **bn_n)
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

    BN_CTX_free(ctx);

    return 1;
}

struct boringssl_priv_key_st {
    BIGNUM *bn_n;
    BIGNUM *bn_e;
    BIGNUM *bn_d;
    BIGNUM *bn_p;
    BIGNUM *bn_q;
    BIGNUM *bn_dp;
    BIGNUM *bn_dq;
    BIGNUM *bn_qinv;
};

static TEE_Result rsa_priv_key_transform(const struct rsa_priv_key *priv_key, struct boringssl_priv_key_st *key)
{
    key->bn_n = BN_new();
    key->bn_e = BN_new();
    key->bn_d = BN_new();
    bool is_abnormal = (key->bn_n == NULL) || (key->bn_e == NULL) || (key->bn_d == NULL);
    if (is_abnormal) {
        tloge("New big num n or e or d failed\n");
        free_rsa_bn_n(key->bn_n, key->bn_e, key->bn_d, NULL);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    key->bn_p = BN_bin2bn(priv_key->p, get_effective_size(priv_key->p, priv_key->p_size), NULL);
    key->bn_q = BN_bin2bn(priv_key->q, get_effective_size(priv_key->q, priv_key->q_size), NULL);
    key->bn_dq = BN_bin2bn(priv_key->dq, get_effective_size(priv_key->dq, priv_key->dq_size), NULL);
    key->bn_dp = BN_bin2bn(priv_key->dp, get_effective_size(priv_key->dp, priv_key->dp_size), NULL);
    key->bn_qinv = BN_bin2bn(priv_key->qinv, get_effective_size(priv_key->qinv, priv_key->qinv_size), NULL);
    is_abnormal =
        (key->bn_p == NULL || key->bn_q == NULL || key->bn_dp == NULL || key->bn_dq == NULL || key->bn_qinv == NULL);
    if (is_abnormal) {
        tloge("change buffer to BIGNUM is error!");
        free_rsa_bn_n(key->bn_n, key->bn_e, key->bn_d, key->bn_p);
        free_rsa_bn_q(key->bn_q, key->bn_dp, key->bn_dq, key->bn_qinv);
        return TEE_ERROR_GENERIC;
    }

    int32_t result = get_rsa_big_num_ned(key->bn_p, key->bn_q, &key->bn_n, &key->bn_e, &key->bn_d);
    if (result != 1) {
        tloge("get rsa key error!");
        free_rsa_bn_n(key->bn_n, key->bn_e, key->bn_d, key->bn_p);
        free_rsa_bn_q(key->bn_q, key->bn_dp, key->bn_dq, key->bn_qinv);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static RSA *proc_build_rsa_key(struct boringssl_priv_key_st *key)
{
    RSA *rsa_key = RSA_new();
    if (rsa_key == NULL) {
        tloge("Malloc memory for rsa key failed\n");
        free_rsa_bn_n(key->bn_n, key->bn_e, key->bn_d, key->bn_p);
        free_rsa_bn_q(key->bn_q, key->bn_dp, key->bn_dq, key->bn_qinv);
        return NULL;
    }

    int32_t result = RSA_set0_key(rsa_key, key->bn_n, key->bn_e, key->bn_d);
    if (result != 1) {
        tloge("RSA_set0_key failed\n");
        free_rsa_bn_n(key->bn_n, key->bn_e, key->bn_d, key->bn_p);
        free_rsa_bn_q(key->bn_q, key->bn_dp, key->bn_dq, key->bn_qinv);
        RSA_free(rsa_key);
        return NULL;
    }

    result = RSA_set0_factors(rsa_key, key->bn_p, key->bn_q);
    if (result != 1) {
        tloge("RSA_set0_factors failed\n");
        free_rsa_bn_n(NULL, NULL, NULL, key->bn_p);
        free_rsa_bn_q(key->bn_q, key->bn_dp, key->bn_dq, key->bn_qinv);
        RSA_free(rsa_key);
        return NULL;
    }
    result = RSA_set0_crt_params(rsa_key, key->bn_dp, key->bn_dq, key->bn_qinv);
    if (result != 1) {
        tloge("RSA_set0_crt_params\n");
        free_rsa_bn_q(NULL, key->bn_dp, key->bn_dq, key->bn_qinv);
        RSA_free(rsa_key);
        return NULL;
    }
    return rsa_key;
}

static RSA *rsa_build_key(const struct rsa_priv_key *priv_key)
{
    struct boringssl_priv_key_st key = {0};

    TEE_Result ret = rsa_priv_key_transform(priv_key, &key);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to transform private key to boringssl format!");
        return NULL;
    }

    return proc_build_rsa_key(&key);
}

static TEE_Result rsa_priv_key_transform_with_ed(const struct rsa_priv_key *priv_key,
                                                 struct boringssl_priv_key_st *key)
{
    key->bn_n = BN_new();
    bool is_abnormal = (key->bn_n == NULL);
    if (is_abnormal) {
        tloge("New big num n or e or d failed\n");
        free_rsa_bn_n(key->bn_n, NULL, NULL, NULL);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    key->bn_p = BN_bin2bn(priv_key->p, get_effective_size(priv_key->p, priv_key->p_size), NULL);
    key->bn_q = BN_bin2bn(priv_key->q, get_effective_size(priv_key->q, priv_key->q_size), NULL);
    key->bn_dq = BN_bin2bn(priv_key->dq, get_effective_size(priv_key->dq, priv_key->dq_size), NULL);
    key->bn_dp = BN_bin2bn(priv_key->dp, get_effective_size(priv_key->dp, priv_key->dp_size), NULL);
    key->bn_qinv = BN_bin2bn(priv_key->qinv, get_effective_size(priv_key->qinv, priv_key->qinv_size), NULL);
    key->bn_d = BN_bin2bn(priv_key->d, get_effective_size(priv_key->d, priv_key->d_size), NULL);
    key->bn_e = BN_bin2bn(priv_key->e, get_effective_size(priv_key->e, priv_key->e_size), NULL);
    is_abnormal  = (key->bn_p == NULL || key->bn_q == NULL || key->bn_dp == NULL || key->bn_dq == NULL ||
                   key->bn_qinv == NULL || key->bn_d == NULL || key->bn_e == NULL);
    if (is_abnormal) {
        tloge("change buffer to BIGNUM is error!");
        free_rsa_bn_n(key->bn_n, key->bn_e, key->bn_d, key->bn_p);
        free_rsa_bn_q(key->bn_q, key->bn_dp, key->bn_dq, key->bn_qinv);
        return TEE_ERROR_GENERIC;
    }

    int32_t result = get_rsa_big_num_n(key->bn_p, key->bn_q, &key->bn_n);
    if (result != 1) {
        tloge("get rsa key error!");
        free_rsa_bn_n(key->bn_n, key->bn_e, key->bn_d, key->bn_p);
        free_rsa_bn_q(key->bn_q, key->bn_dp, key->bn_dq, key->bn_qinv);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static RSA *rsa_build_key_with_ed(const struct rsa_priv_key *priv_key)
{
    struct boringssl_priv_key_st key = {0};

    TEE_Result ret = rsa_priv_key_transform_with_ed(priv_key, &key);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to transform private key to boringssl format!");
        return NULL;
    }

    return proc_build_rsa_key(&key);
}

struct ecies_kem_data_st {
    BIGNUM *d;
    EC_KEY *ec1;
    EC_KEY *ec2;
    EC_POINT *ecp;
    EC_GROUP *group;
    uint8_t secret[AES_KEY_LEN];
};

static void ecies_kem_cleanup(struct ecies_kem_data_st *ctx)
{
    BN_clear_free(ctx->d);
    EC_POINT_free(ctx->ecp);
    EC_GROUP_free(ctx->group);
    EC_KEY_free(ctx->ec1);
    EC_KEY_free(ctx->ec2);
}

static TEE_Result ecies_kem_init(const struct ecc_derive_data_st *ecc_data, struct ecies_kem_data_st *ctx)
{
    ctx->ec1 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    ctx->ec2 = EC_KEY_new();
    ctx->group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    bool check = (ctx->ec1 == NULL || ctx->ec2 == NULL || ctx->group == NULL);
    if (check) {
        ecies_kem_cleanup(ctx);
        tloge("new ec key failed\n");
        return TEE_ERROR_GENERIC;
    }

    ctx->d = BN_bin2bn(ecc_data->ec1_priv, ECIES_PRIV_LEN, ctx->d);
    if (ctx->d == NULL) {
        tloge("bin2bn failed\n");
        ecies_kem_cleanup(ctx);
        return TEE_ERROR_GENERIC;
    }

    int32_t ret = EC_KEY_set_private_key(ctx->ec1, ctx->d);
    if (ret == 0) {
        tloge("set private key failed\n");
        ecies_kem_cleanup(ctx);
        return TEE_ERROR_GENERIC;
    }

    ret = EC_KEY_set_group(ctx->ec2, ctx->group);
    if (ret == 0) {
        tloge("set ec group failed\n");
        ecies_kem_cleanup(ctx);
        return TEE_ERROR_GENERIC;
    }

    ctx->ecp = EC_POINT_new(ctx->group);
    if (ctx->ecp == NULL) {
        tloge("new ec point failed\n");
        ecies_kem_cleanup(ctx);
        return TEE_ERROR_GENERIC;
    }

    ret = EC_POINT_oct2point(ctx->group, ctx->ecp, ecc_data->ec2_pub, ecc_data->ec2_len, NULL);
    if (ret == 0) {
        tloge("ec oct2point failed\n");
        ecies_kem_cleanup(ctx);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

/* generate a 256 bytes AES key with ECDH + HMAC */
int32_t ecies_kem_decrypt(const struct ecc_derive_data_st *ecc_data, uint8_t *key, uint32_t key_len)
{
    struct ecies_kem_data_st ctx = {0};
    uint8_t *hmac = NULL;

    bool check = (ecc_data == NULL || key == NULL || ecc_data->ec1_len != ECIES_PRIV_LEN
        || ecc_data->ec2_len != ECIES_PUB_LEN);
    if (check) {
        tloge("key len invalid, %u/%u\n", ecc_data->ec1_len, ecc_data->ec2_len);
        return -1;
    }

    TEE_Result ret = ecies_kem_init(ecc_data, &ctx);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to initialize ctx\n");
        return -1;
    }

    int32_t result = ECDH_compute_key(ctx.secret, sizeof(ctx.secret), ctx.ecp, ctx.ec1, NULL);
    if (result <= 0) {
        tloge("ecdh compute failed\n");
        ecies_kem_cleanup(&ctx);
        return -1;
    }

    hmac = HMAC(EVP_sha256(), ctx.secret, sizeof(ctx.secret), (uint8_t *)g_ecies_hmac_salt,
                strlen(g_ecies_hmac_salt) + 1, key, &key_len);
    ecies_kem_cleanup(&ctx);
    if (hmac == NULL) {
        tloge("hkdf failed\n");
        return -1;
    }

    return 0;
}

int32_t aes_cbc_256_decrypt(const uint8_t *key, const uint8_t *iv,
    const uint8_t *in, uint32_t in_len, uint8_t *out)
{
    EVP_CIPHER_CTX ctx = {0};
    int32_t len, len2;

    if (key == NULL || iv == NULL || in == NULL || out == NULL)
        goto clean;

    int32_t ret = EVP_DecryptInit(&ctx, EVP_aes_256_cbc(), key, iv);
    if (ret == 0) {
        tloge("decrypt init failed\n");
        goto clean;
    }

    ret = EVP_DecryptUpdate(&ctx, out, &len, in, in_len);
    if (ret == 0) {
        tloge("decrypt update failed\n");
        goto clean;
    }

    ret = EVP_DecryptFinal_ex(&ctx, out + len, &len2);
    if (ret == 0) {
        tloge("decrypt final failed\n");
        goto clean;
    }

    bool check = (len < 0 || len2 < 0);
    if (check) {
        tloge("error decrypt len,update:%d, final:%d\n", len, len2);
        goto clean;
    }

    if (len + len2 < len) {
        tloge("len and len2's addition may overflow\n");
        goto clean;
    }
    EVP_CIPHER_CTX_reset(&ctx);
    return len + len2;
clean:
    EVP_CIPHER_CTX_reset(&ctx);
    return -1;
}

static RSA *get_private_key_ecies(int32_t img_version, enum ta_type type)
{
    uint8_t aes_key[AES_KEY_LEN];
    const struct ecies_key_struct *ecies_key_data = NULL;
    struct rsa_priv_key *priv_key = NULL;
    RSA *ret_key = NULL;

    ecies_key_data = get_ecies_key_data(img_version, type);
    if (ecies_key_data == NULL) {
        tloge("Failed to get ecies key data\n");
        return NULL;
    }

    TEE_Result ret = get_rsa_priv_aes_key(ecies_key_data, aes_key, sizeof(aes_key));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to get AES key to decrypt RSA private components\n");
        return NULL;
    }

    priv_key = TEE_Malloc(sizeof(struct rsa_priv_key), 0);
    if (priv_key == NULL)
        return NULL;

    ret = aes_decrypt_rsa_private(ecies_key_data, aes_key, sizeof(aes_key), priv_key);
    (void)memset_s(aes_key, sizeof(aes_key), 0, sizeof(aes_key));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to decrypt RSA private components\n");
        TEE_Free(priv_key);
        return NULL;
    }

    ret_key = rsa_build_key_with_ed(priv_key);
    (void)memset_s(priv_key, sizeof(*priv_key), 0, sizeof(*priv_key));
    TEE_Free(priv_key);
    return ret_key;
}

static struct wb_key_struct *get_wb_key_data(int32_t img_version, enum ta_type type)
{
    TEE_Result ret;
    struct key_data key_data = {
        .pro_type = WB_KEY,
        .ta_type = type,
        .key = NULL,
        .key_len = 0,
    };

    ret = get_key_data(img_version, &key_data);
    if (ret != TEE_SUCCESS) {
        tloge("get wb key failed for version:%d\n", img_version);
        return NULL;
    }

    if (key_data.key_len != sizeof(struct wb_key_struct)) {
        tloge("get wb key len error\n");
        return NULL;
    }

    return (struct wb_key_struct *)key_data.key;
}

static TEE_Result get_wb_tool_internal_key(int32_t img_version, struct wb_tool_inter_key *inter_key)
{
    struct wb_tool_key tool_key = {0};

    tool_key.tool_ver = WB_TOOL_KEY_128;

    /* Only v3 use new white box table2 key. */
    if (img_version == CIPHER_LAYER_VERSION)
        tool_key.tool_ver = WB_TOOL_KEY_256;

    if (get_wb_tool_key(&tool_key) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    inter_key->iv = tool_key.iv;
    inter_key->table2 = tool_key.table2;
    inter_key->round_num = tool_key.round_num;

    return TEE_SUCCESS;
}

static RSA *get_white_box_private_key(int32_t img_version, enum ta_type type)
{
    RSA *ret_key = NULL;
    struct rsa_priv_key *priv_key = NULL;
    struct wb_key_struct *wb_key = NULL;
    struct wb_tool_inter_key inter_key = {0};

    wb_key = get_wb_key_data(img_version, type);
    if (wb_key == NULL) {
        tloge("get wb key data failed\n");
        return NULL;
    }

    if (get_wb_tool_internal_key(img_version, &inter_key) != TEE_SUCCESS)
        return NULL;

    priv_key = TEE_Malloc(sizeof(struct rsa_priv_key), 0);
    if (priv_key == NULL)
        return NULL;

    bool temp_check =
        (wb_aes_decrypt_cbc(&inter_key, wb_key->wb_rsa_priv_p,
            wb_key->wb_rsa_priv_p_len, priv_key->p, &priv_key->p_size) != 0) ||
        (wb_aes_decrypt_cbc(&inter_key, wb_key->wb_rsa_priv_q,
            wb_key->wb_rsa_priv_q_len, priv_key->q, &priv_key->q_size) != 0) ||
        (wb_aes_decrypt_cbc(&inter_key, wb_key->wb_rsa_priv_dp,
            wb_key->wb_rsa_priv_dp_len, priv_key->dp, &priv_key->dp_size) != 0) ||
        (wb_aes_decrypt_cbc(&inter_key, wb_key->wb_rsa_priv_dq,
            wb_key->wb_rsa_priv_dq_len, priv_key->dq, &priv_key->dq_size) != 0) ||
        (wb_aes_decrypt_cbc(&inter_key, wb_key->wb_rsa_priv_qinv,
            wb_key->wb_rsa_priv_qinv_len, priv_key->qinv, &priv_key->qinv_size) != 0);
    if (temp_check) {
        tloge("whitebox generate private key failed\n");
        TEE_Free(priv_key);
        return NULL;
    }

    temp_check = (priv_key->p_size > sizeof(wb_key->wb_rsa_priv_p) ||
                  priv_key->q_size > sizeof(wb_key->wb_rsa_priv_q) ||
                  priv_key->dp_size > sizeof(wb_key->wb_rsa_priv_dp) ||
                  priv_key->dq_size > sizeof(wb_key->wb_rsa_priv_dq) ||
                  priv_key->qinv_size > sizeof(wb_key->wb_rsa_priv_qinv));
    if (temp_check) {
        tloge("generate private key len failed\n");
        TEE_Free(priv_key);
        return NULL;
    }

    ret_key = rsa_build_key(priv_key);
    (void)memset_s(priv_key, sizeof(*priv_key), 0, sizeof(*priv_key));
    TEE_Free(priv_key);
    return ret_key;
}

static RSA *get_private_key_v2(int32_t img_version, enum ta_type type)
{
    bool is_wb_key = is_wb_protecd_ta_key();
    if (is_wb_key)
        return get_white_box_private_key(img_version, type);
    else
        return get_private_key_ecies(img_version, type);
}

static void fill_priv_key_size(struct rsa_priv_key *priv_key)
{
    priv_key->p_size = WITHOUT_ZERO;
    priv_key->q_size = WITHOUT_ZERO;
    priv_key->dp_size = WITHOUT_ZERO;
    priv_key->dq_size = WITHOUT_ZERO;
    priv_key->qinv_size = WITHOUT_ZERO;
}

static TEE_Result convert_v1_key(const uint8_t *key_buffer, uint32_t key_len, struct rsa_priv_key *priv_key)
{
    errno_t eret;
    uint32_t off_set = 0;

    if (key_len < RESULT1)
        return TEE_ERROR_BAD_PARAMETERS;

    /* WITH_ZERO = WITHOUT_ZERO + 1, makesure cpy never overflow */
    eret = memcpy_s(priv_key->p, sizeof(priv_key->p), key_buffer + off_set, WITHOUT_ZERO);
    if (eret != EOK)
        return TEE_ERROR_SECURITY;
    off_set += WITHOUT_ZERO;

    eret = memcpy_s(priv_key->q, sizeof(priv_key->q), key_buffer + off_set, WITHOUT_ZERO);
    if (eret != EOK)
        return TEE_ERROR_SECURITY;
    off_set += WITHOUT_ZERO;

    eret = memcpy_s(priv_key->dp, sizeof(priv_key->dp), key_buffer + off_set, WITHOUT_ZERO);
    if (eret != EOK)
        return TEE_ERROR_SECURITY;
    off_set += WITHOUT_ZERO;

    eret = memcpy_s(priv_key->dq, sizeof(priv_key->dq), key_buffer + off_set, WITHOUT_ZERO);
    if (eret != EOK)
        return TEE_ERROR_SECURITY;
    off_set += WITHOUT_ZERO;

    eret = memcpy_s(priv_key->qinv, sizeof(priv_key->qinv), key_buffer + off_set, WITHOUT_ZERO);
    if (eret != EOK)
        return TEE_ERROR_SECURITY;

    fill_priv_key_size(priv_key);
    return TEE_SUCCESS;
}

#define V1_WB_KEY_LEN 336U
static RSA *get_private_key_v1(void)
{
    RSA *ret_key = NULL;
    struct rsa_priv_key *priv_key = NULL;
    uint8_t key_buffer[RESULT1] = {0};
    uint32_t key_len = 0;
    struct wb_tool_inter_key inter_key = {0};
    struct key_data key_data = {
        .pro_type = WB_KEY,
        .ta_type = V1_TYPE,
        .key = NULL,
        .key_len = 0,
    };

    if (get_ta_load_key(&key_data) != TEE_SUCCESS || key_data.key_len != V1_WB_KEY_LEN || key_data.key == NULL) {
        tloge("get v1 key failed, wb key len is %zu\n", key_data.key_len);
        return NULL;
    }

    if (get_wb_tool_internal_key(TA_SIGN_VERSION, &inter_key) != TEE_SUCCESS)
        return NULL;

    int32_t iret = wb_aes_decrypt_cbc(&inter_key, key_data.key, key_data.key_len, key_buffer, &key_len);
    if (iret != 0 || key_len > key_data.key_len) {
        tloge("Whitebox Generate PrivateKey failed:%d, or decrypt len error:%u", iret, key_len);
        return NULL;
    }

    priv_key = TEE_Malloc(sizeof(struct rsa_priv_key), 0);
    if (priv_key == NULL)
        return NULL;

    if (convert_v1_key(key_buffer, key_len, priv_key) != TEE_SUCCESS) {
        (void)memset_s(key_buffer, sizeof(key_buffer), 0, sizeof(key_buffer));
        TEE_Free(priv_key);
        return NULL;
    }
    (void)memset_s(key_buffer, sizeof(key_buffer), 0, sizeof(key_buffer));

    /* get the RSA private key  */
    ret_key = rsa_build_key(priv_key);
    (void)memset_s(priv_key, sizeof(*priv_key), 0, sizeof(*priv_key));
    TEE_Free(priv_key);
    return ret_key;
}

RSA *get_private_key(int32_t img_version, enum ta_type type)
{
    switch (img_version) {
    case TA_SIGN_VERSION:
        return get_private_key_v1();
    case TA_RSA2048_VERSION:
    case CIPHER_LAYER_VERSION:
        return get_private_key_v2(img_version, type);
    default:
        tloge("Unsupported secure image version!\n");
        return NULL;
    }
}

void free_private_key(RSA *priv_key)
{
    if (priv_key != NULL)
        RSA_free(priv_key);
}

RSA *get_ta_verify_key(void)
{
    struct ta_verify_key verify_key = { PUB_KEY_2048_BITS, PUB_KEY_RELEASE, NULL};

    TEE_Result ret = get_ta_verify_pubkey(&verify_key);
    if (ret != TEE_SUCCESS || verify_key.key == NULL)
        return NULL;

    return rsa_build_public_key(verify_key.key);
}
