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
#include <mbedtls/bignum.h>
#include <mbedtls/rsa.h>
#include <securec.h>
#include <tee_log.h>
#include <tee_defines.h>
#include "tee_mem_mgmt_api.h"

int32_t rsa_generate_keypair(rsa_priv_key_t *priv, rsa_pub_key_t *pub, uint32_t e, uint32_t key_size)
{
    (void)priv;
    (void)pub;
    (void)e;
    (void)key_size;
    return -1;
}

int32_t rsa_encrypt(uint8_t *dest_data, uint32_t *dest_len, uint8_t *src_data, uint32_t src_len, rsa_pub_key_t *pub,
                    int32_t padding, int32_t hash_nid)
{
    (void)dest_data;
    (void)dest_len;
    (void)src_data;
    (void)src_len;
    (void)pub;
    (void)padding;
    (void)hash_nid;
    return -1;
}

int32_t rsa_decrypt(uint8_t *dest_data, uint32_t *dest_len, uint8_t *src_data, uint32_t src_len, rsa_priv_key_t *priv,
                    uint32_t padding, int32_t hash_nid)
{
    (void)dest_data;
    (void)dest_len;
    (void)src_data;
    (void)src_len;
    (void)priv;
    (void)padding;
    (void)hash_nid;
    return -1;
}

int32_t rsa_sign_digest(uint8_t *signature, uint32_t *sig_size, uint8_t *in, uint32_t in_len, rsa_priv_key_t *priv,
                        uint32_t salt_len, int32_t hash_nid, int32_t padding)
{
    (void)signature;
    (void)sig_size;
    (void)in;
    (void)in_len;
    (void)priv;
    (void)salt_len;
    (void)hash_nid;
    (void)padding;
    return -1;
}

#define MAX_OUTPUT_LEN 256
static int32_t rsa_pss_verify_digest(mbedtls_rsa_context *ctx, uint8_t *signature, uint32_t sig_size,
    uint8_t *in, uint32_t in_len, uint32_t salt_len, int32_t hash_nid)
{
    (void)sig_size;
    const size_t output_max_len = MAX_OUTPUT_LEN;
    size_t olen;
    uint8_t *em_buf = TEE_Malloc(output_max_len, 0);
    if (em_buf == NULL) {
        tloge("malloc buf failed, len=%u\n", output_max_len);
        return -1;
    }

    int32_t rc = mbedtls_rsa_pkcs1_decrypt(ctx, NULL, NULL, MBEDTLS_RSA_PUBLIC, &olen,
        signature, em_buf, output_max_len);
    if (rc != 0) {
        tloge("rsa decrypt fail, rc:%d", rc);
        TEE_Free(em_buf);
        return -1;
    }

    rc = mbedtls_rsa_rsassa_pss_verify_ext(ctx, NULL, NULL, MBEDTLS_RSA_PUBLIC,
        hash_nid, in_len, in, hash_nid, salt_len, em_buf);
    TEE_Free(em_buf);
    return rc;
}

int32_t rsa_verify_digest(uint8_t *signature, uint32_t sig_size, uint8_t *in, uint32_t in_len, const rsa_pub_key_t *pub,
                          uint32_t salt_len, int32_t hash_nid, int32_t padding)
{
    mbedtls_mpi mpi_n, mpi_e;
    mbedtls_rsa_context ctx;
    bool check = (signature == NULL || in == NULL || pub == NULL || sig_size == 0 || in_len == 0);
    if (check) {
        tloge("param is invalid!");
        return -1;
    }

    mbedtls_rsa_init(&ctx, padding, hash_nid);
    mbedtls_mpi_init(&mpi_n);
    mbedtls_mpi_init(&mpi_e);
    int32_t rc = mbedtls_mpi_read_binary(&mpi_n, pub->n, pub->n_len);
    rc |= mbedtls_mpi_read_binary(&mpi_e, pub->e, pub->e_len);
    if (rc != 0) {
        tloge("pub buffer to big num failed, rc:%d", rc);
        goto clean;
    }

    rc = mbedtls_rsa_import(&ctx, &mpi_n, NULL, NULL, NULL, &mpi_e);
    if (rc != 0) {
        tloge("rsa import fail, rc:%d", rc);
        goto clean;
    }

    rc = mbedtls_rsa_complete(&ctx);
    if (rc != 0) {
        tloge("rsa complete fail, rc:%d", rc);
        goto clean;
    }

    if (padding == MBEDTLS_RSA_PKCS_V21) {
        rc = rsa_pss_verify_digest(&ctx, signature, sig_size, in, in_len, salt_len, hash_nid);
    } else if (padding == MBEDTLS_RSA_PKCS_V15) {
        rc = mbedtls_rsa_pkcs1_verify(&ctx, NULL, NULL, MBEDTLS_RSA_PUBLIC, hash_nid, in_len, in, signature);
    }
    if (rc != 0)
        tloge("rsa verify digest failed!, rc:%d", rc);

clean:
    mbedtls_mpi_free(&mpi_n);
    mbedtls_mpi_free(&mpi_e);
    mbedtls_rsa_free(&ctx);
    return rc;
}

int generate_rsa_from_secret(rsa_priv_key_t *rsa, uint32_t nbits, uint8_t *secret, uint32_t secret_len,
                             const uint8_t *file_name)
{
    (void)rsa;
    (void)nbits;
    (void)secret;
    (void)secret_len;
    (void)file_name;
    return -1;
}

int rsa_import_priv(rsa_priv_key_t *priv, const uint8_t *in, uint32_t in_len)
{
    (void)priv;
    (void)in;
    (void)in_len;
    return -1;
}

int32_t rsa_export_pub_sp(uint8_t *out, uint32_t out_size, rsa_pub_key_t *pub)
{
    (void)out;
    (void)out_size;
    (void)pub;
    return -1;
}
