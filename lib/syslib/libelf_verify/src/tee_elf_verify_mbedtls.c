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
#include <mbedtls/cipher.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/rsa.h>
#include <mbedtls/md.h>
#include <mbedtls/bignum.h>
#include "tee_log.h"
#include "securec.h"
#include "tee_v3_elf_verify.h"
#include <tee_crypto_signature_verify.h>

static const char *g_ecies_hmac_salt = "salt for ecies kdf";

static inline int32_t mbd_rand(void *rng_state, unsigned char *out, size_t len)
{
    (void)rng_state;
    TEE_GenerateRandom(out, len);
    return 0;
}

static int32_t rsa_build_key_with_ed(struct rsa_priv_key *priv_key, mbedtls_rsa_context *ctx)
{
    int32_t rc;
    rc = mbedtls_mpi_read_binary(&ctx->P, priv_key->p, get_effective_size(priv_key->p, priv_key->p_size));
    rc |= mbedtls_mpi_read_binary(&ctx->Q, priv_key->q, get_effective_size(priv_key->q, priv_key->q_size));
    rc |= mbedtls_mpi_read_binary(&ctx->DQ, priv_key->dq, get_effective_size(priv_key->dq, priv_key->dq_size));
    rc |= mbedtls_mpi_read_binary(&ctx->DP, priv_key->dp, get_effective_size(priv_key->dp, priv_key->dp_size));
    rc |= mbedtls_mpi_read_binary(&ctx->QP, priv_key->qinv, get_effective_size(priv_key->qinv, priv_key->qinv_size));
    rc |= mbedtls_mpi_read_binary(&ctx->D, priv_key->d, get_effective_size(priv_key->d, priv_key->d_size));
    rc |= mbedtls_mpi_read_binary(&ctx->E, priv_key->e, get_effective_size(priv_key->e, priv_key->e_size));
    if (rc != 0) {
        tloge("write binary fail, rc:%d", rc);
        return rc;
    }

    rc = mbedtls_mpi_mul_mpi(&ctx->N, &ctx->P, &ctx->Q);
    if (rc != 0) {
        tloge("read mul fail, rc:%d", rc);
        return rc;
    }

    ctx->len = mbedtls_mpi_size(&ctx->N);

    rc = mbedtls_rsa_complete(ctx);
    if (rc != 0)
        tloge("mbedtls rsa complete fail, rc:%d", rc);

    return rc;
}

TEE_Result get_private_key(int32_t img_version, enum ta_type type, mbedtls_rsa_context *ctx)
{
    uint8_t aes_key[AES_KEY_LEN];
    const struct ecies_key_struct *ecies_key_data = NULL;
    struct rsa_priv_key priv_key;

    if (ctx == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    ecies_key_data = get_ecies_key_data(img_version, type);
    if (ecies_key_data == NULL) {
        tloge("Failed to get ecies key data\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = get_rsa_priv_aes_key(ecies_key_data, aes_key, sizeof(aes_key));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to get AES key to decrypt RSA private components\n");
        return ret;
    }

    (void)memset_s(&priv_key, sizeof(priv_key), 0, sizeof(priv_key));
    ret = aes_decrypt_rsa_private(ecies_key_data, aes_key, sizeof(aes_key), &priv_key);
    (void)memset_s(aes_key, sizeof(aes_key), 0, sizeof(aes_key));
    if (ret != TEE_SUCCESS) {
        tloge("Failed to decrypt RSA private components\n");
        return ret;
    }

    int32_t rc = rsa_build_key_with_ed(&priv_key, ctx);
    if (rc != 0)
        return TEE_ERROR_GENERIC;

    (void)memset_s(&priv_key, sizeof(priv_key), 0, sizeof(priv_key));
    return TEE_SUCCESS;
}

TEE_Result tee_secure_img_decrypt_cipher_layer(const uint8_t *cipher_layer, uint32_t cipher_size,
    uint8_t *plaintext_layer, uint32_t *plaintext_size)
{
    TEE_Result ret;
    bool check = (cipher_layer == NULL || cipher_size == 0 || plaintext_layer == NULL ||
        plaintext_size == NULL || *plaintext_size < cipher_size);
    if (check)
        return TEE_ERROR_BAD_PARAMETERS;

    enum ta_type type = V3_TYPE_2048;
    if (judge_rsa_key_type(cipher_size, &type) != TEE_SUCCESS)
        return TEE_ERROR_BAD_PARAMETERS;

    mbedtls_rsa_context ctx;
    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
    ret = get_private_key(CIPHER_LAYER_VERSION, type, &ctx);
    if (ret != TEE_SUCCESS) {
        tloge("get private key fail!");
        goto clean;
    }

    size_t out_len = *plaintext_size;
    int32_t rc = mbedtls_rsa_rsaes_oaep_decrypt(&ctx, mbd_rand, NULL, MBEDTLS_RSA_PRIVATE, NULL, 0, &out_len,
        cipher_layer, plaintext_layer, *plaintext_size);
    if (rc != 0) {
        tloge("rsa decrypt fail, rc:%d", rc);
        ret = TEE_ERROR_GENERIC;
        goto clean;
    }
    *plaintext_size = out_len;
    ret = TEE_SUCCESS;
clean:
    mbedtls_rsa_free(&ctx);
    return ret;
}

static TEE_Result ecies_kem_init(const struct ecc_derive_data_st *ecc_data,
    mbedtls_ecp_group *grp, mbedtls_ecp_point *q, mbedtls_mpi *d)
{
    int32_t rc = mbedtls_mpi_read_binary(d, ecc_data->ec1_priv, ECIES_PRIV_LEN);
    if (rc != 0) {
        tloge("read binary failed\n");
        return TEE_ERROR_GENERIC;
    }

    mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1);
    rc = mbedtls_ecp_point_read_binary(grp, q, ecc_data->ec2_pub, ecc_data->ec2_len);
    if (rc != 0) {
        tloge("ecp point read binary failed\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static bool check_ecc_params_invalid(const struct ecc_derive_data_st *ecc_data, uint8_t *key)
{
    if (ecc_data == NULL || key == NULL)
        return true;

    return (ecc_data->ec1_len != ECIES_PRIV_LEN || ecc_data->ec2_len != ECIES_PUB_LEN);
}

/* generate a 256 bytes AES key with ECDH + HMAC */
int32_t ecies_kem_decrypt(const struct ecc_derive_data_st *ecc_data, uint8_t *key, uint32_t key_len)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi d, z;
    int32_t rc;

    if (check_ecc_params_invalid(ecc_data, key) || key_len < SHA256_LEN) {
        tloge("key len invalid\n");
        return -1;
    }

    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);

    if (ecies_kem_init(ecc_data, &grp, &q, &d) != TEE_SUCCESS) {
        tloge("Failed to initialize ctx\n");
        rc = -1;
        goto clean;
    }

    rc = mbedtls_ecdh_compute_shared(&grp, &z, &q, &d, NULL, NULL);
    if (rc != 0) {
        tloge("ecdh compute shared fail!! rc:%d", rc);
        goto clean;
    }
    uint8_t secret[AES_KEY_LEN];
    mbedtls_mpi_write_binary(&z, secret, sizeof(secret));
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) {
        tloge("hmac md is NULL");
        rc = -1;
        goto clean;
    }

    rc = mbedtls_md_hmac(md_info, secret, sizeof(secret),
        (uint8_t *)g_ecies_hmac_salt, strlen(g_ecies_hmac_salt) + 1, key);
    if (rc != 0)
        tloge("hmac failed\n");

clean:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&q);
    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&z);
    return rc;
}

#define BYTE2BIT 8
#define IV_LEN 16
int32_t aes_cbc_256_decrypt(const uint8_t *key, const uint8_t *iv,
    const uint8_t *in, uint32_t in_len, uint8_t *out)
{
    mbedtls_cipher_context_t cipher_ctx;

    if (key == NULL || iv == NULL || in == NULL || out == NULL)
        return -1;

    mbedtls_cipher_init(&cipher_ctx);
    const mbedtls_cipher_info_t *cipher_info = NULL;
    cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
    if (cipher_info == NULL) {
        tloge("cipher_info is invalid");
        goto clean;
    }

    int32_t rc = mbedtls_cipher_setup(&cipher_ctx, cipher_info);
    if (rc != 0) {
        tloge("aes cipher setup failed,rc:%d", rc);
        goto clean;
    }

    rc = mbedtls_cipher_setkey(&cipher_ctx, key, AES_KEY_LEN * BYTE2BIT, MBEDTLS_DECRYPT);
    if (rc != 0) {
        tloge("aes cipher setkey failed,rc:%d\n", rc);
        goto clean;
    }

    rc = mbedtls_cipher_set_iv(&cipher_ctx, iv, IV_LEN);
    if (rc != 0) {
        tloge("aes cipher set iv failed,rc:%d\n", rc);
        goto clean;
    }

    size_t update_len;
    size_t olen;
    rc = mbedtls_cipher_update(&cipher_ctx, in, in_len, out, &update_len);
    if (rc != 0) {
        tloge("aes cipher update failed,rc:%d\n", rc);
        goto clean;
    }

    rc = mbedtls_cipher_finish(&cipher_ctx, out + update_len, &olen);
    if (rc != 0) {
        tloge("aes cipher finish failed,rc:%d\n", rc);
        goto clean;
    }

    mbedtls_cipher_free(&cipher_ctx);
    return (uint32_t)(update_len + olen);

clean:
    mbedtls_cipher_free(&cipher_ctx);
    return -1;
}
