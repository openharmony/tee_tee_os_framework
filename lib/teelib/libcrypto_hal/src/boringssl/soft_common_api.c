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

#include "soft_common_api.h"
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#ifdef CONFIG_CRYPTO_SUPPORT_SIPHASH
#include <crypto/siphash.h>
#include <siphash/siphash_local.h>
#endif
#include <openssl/rand.h>
#include <securec.h>
#include <tee_log.h>
#include "soft_gmssl.h"
#include "soft_err.h"
#include "crypto/rand.h"
#include "openssl/crypto.h"

int32_t check_params(const struct asymmetric_params_t *params)
{
    if ((params != NULL) && (params->param_count > TEE_PARAM_MAX)) {
        tloge("the param_count is too big param_count = %u", params->param_count);
        return CRYPTO_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

int32_t check_valid_algorithm(uint32_t algorithm, const uint32_t *array, uint32_t array_size)
{
    if (array == NULL || array_size > MAX_VALID_ALGO_SIZE)
        return CRYPTO_BAD_PARAMETERS;
    uint32_t index;
    for (index = 0; index < array_size; index++) {
        if (algorithm == array[index])
            return CRYPTO_SUCCESS;
    }
    return CRYPTO_NOT_SUPPORTED;
}

uint32_t get_hash_context_size(uint32_t algorithm)
{
    switch (algorithm) {
    case CRYPTO_TYPE_DIGEST_MD5:
        return sizeof(MD5_CTX);
    case CRYPTO_TYPE_DIGEST_SHA1:
        return sizeof(SHA_CTX);
    case CRYPTO_TYPE_DIGEST_SHA224:
        return sizeof(SHA256_CTX);
    case CRYPTO_TYPE_DIGEST_SHA256:
        return sizeof(SHA256_CTX);
    case CRYPTO_TYPE_DIGEST_SHA384:
        return sizeof(SHA512_CTX);
    case CRYPTO_TYPE_DIGEST_SHA512:
        return sizeof(SHA512_CTX);
    default:
        break;
    }

    return 0;
}

void free_cipher_context(uint64_t *ctx)
{
    if (ctx == NULL || *ctx == 0)
        return;
    EVP_CIPHER_CTX_free((void *)(uintptr_t)*ctx);
    *ctx = 0;
}

void free_hmac_context(uint64_t *ctx)
{
    if (ctx == NULL || *ctx == 0)
        return;
    HMAC_CTX_free((void *)(uintptr_t)*ctx);
    *ctx = 0;
}

static int32_t soft_copy_aes_des_info(struct ctx_handle_t *dest, const struct ctx_handle_t *src)
{
    if (dest->ctx_buffer != 0) {
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)(uintptr_t)(dest->ctx_buffer));
        dest->ctx_buffer = 0;
    }
    if (src->ctx_buffer == 0)
        return CRYPTO_SUCCESS;

    EVP_CIPHER_CTX *new_ctx = EVP_CIPHER_CTX_new();
    if (new_ctx == NULL) {
        tloge("Aes ctx copy failed");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    int32_t ret = EVP_CIPHER_CTX_copy(new_ctx, (EVP_CIPHER_CTX *)(uintptr_t)(src->ctx_buffer));
    if (ret != BORINGSSL_OK) {
        tloge("Aes ctx copy failed");
        EVP_CIPHER_CTX_free(new_ctx);
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    dest->ctx_buffer = (uint64_t)(uintptr_t)new_ctx;

    return CRYPTO_SUCCESS;
}

static int32_t soft_copy_cmac_info(struct ctx_handle_t *dest, const struct ctx_handle_t *src)
{
    if (dest->ctx_buffer != 0) {
        CMAC_CTX_free((CMAC_CTX *)(uintptr_t)(dest->ctx_buffer));
        dest->ctx_buffer = 0;
    }
    if (src->ctx_buffer == 0)
        return CRYPTO_SUCCESS;

    CMAC_CTX *new_ctx = CMAC_CTX_new();
    if (new_ctx == NULL) {
        tloge("New aes cmac ctx failed\n");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    int32_t ret = CMAC_CTX_copy(new_ctx, (CMAC_CTX *)(uintptr_t)(src->ctx_buffer));
    if (ret != BORINGSSL_OK) {
        tloge("Copy aes ctx failed");
        CMAC_CTX_free(new_ctx);
        return CRYPTO_BAD_PARAMETERS;
    }
    dest->ctx_buffer = (uint64_t)(uintptr_t)new_ctx;

    return CRYPTO_SUCCESS;
}

static int32_t soft_copy_digest_info(struct ctx_handle_t *dest, const struct ctx_handle_t *src)
{
    TEE_Free((void *)(uintptr_t)(dest->ctx_buffer));
    dest->ctx_buffer = 0;

    if (src->ctx_buffer == 0)
        return CRYPTO_SUCCESS;

    uint32_t hash_size = get_hash_context_size(src->alg_type);
    if (hash_size == 0) {
        tloge("algorithm is incorrect!");
        return CRYPTO_BAD_PARAMETERS;
    }

    dest->ctx_buffer = (uintptr_t)TEE_Malloc(hash_size, 0);
    if (dest->ctx_buffer == 0) {
        tloge("hash new ctx failed");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    errno_t rc = memcpy_s((void *)(uintptr_t)(dest->ctx_buffer), hash_size,
        (void *)(uintptr_t)(src->ctx_buffer), src->ctx_size);
    if (rc != EOK) {
        tloge("Copy digest ctx failed, rc %x", rc);
        TEE_Free((void *)(uintptr_t)(dest->ctx_buffer));
        dest->ctx_buffer = 0;
        return CRYPTO_ERROR_SECURITY;
    }
    dest->ctx_size = src->ctx_size;

    return CRYPTO_SUCCESS;
}

static int32_t soft_copy_hmac_info(struct ctx_handle_t *dest, const struct ctx_handle_t *src)
{
    free_hmac_context(&(dest->ctx_buffer));
    if (src->ctx_buffer == 0)
        return CRYPTO_SUCCESS;

    dest->ctx_buffer = (uint64_t)(uintptr_t)HMAC_CTX_new();
    if (dest->ctx_buffer == 0) {
        tloge("hmac new ctx failed");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    int32_t rc = HMAC_CTX_copy((HMAC_CTX *)(uintptr_t)(dest->ctx_buffer), (HMAC_CTX *)(uintptr_t)(src->ctx_buffer));
    if (rc != BORINGSSL_OK) {
        tloge("Copy hmac ctx failed");
        HMAC_CTX_free((void *)(uintptr_t)(dest->ctx_buffer));
        dest->ctx_buffer = 0;
        return get_soft_crypto_error(CRYPTO_ERROR_SECURITY);
    }

    return CRYPTO_SUCCESS;
}

#ifdef CONFIG_CRYPTO_SUPPORT_SIPHASH
static int32_t soft_copy_siphash_info(struct ctx_handle_t *dest, const struct ctx_handle_t *src)
{
    TEE_Free((void *)(uintptr_t)(dest->ctx_buffer));
    if (src->ctx_buffer == 0)
        return CRYPTO_SUCCESS;

    dest->ctx_buffer = (uint64_t)(uintptr_t)TEE_Malloc(sizeof(SIPHASH), 0);
    if (dest->ctx_buffer == 0) {
        tloge("siphash new ctx failed");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    int32_t rc = memcpy_s((void *)(uintptr_t)(dest->ctx_buffer), sizeof(SIPHASH),
        (void *)(uintptr_t)(src->ctx_buffer), src->ctx_size);
    if (rc != EOK) {
        tloge("Copy siphash ctx failed, rc = %d", rc);
        TEE_Free((void *)(uintptr_t)(dest->ctx_buffer));
        dest->ctx_buffer = 0;
        return get_soft_crypto_error(CRYPTO_ERROR_SECURITY);
    }

    return CRYPTO_SUCCESS;
}
#endif

typedef int32_t (*copy_ctx_func)(struct ctx_handle_t *dest, const struct ctx_handle_t *src);
struct soft_ctx_copy {
    uint32_t algorithm;
    copy_ctx_func copy_call_back;
};

static struct soft_ctx_copy g_soft_copy_ctx[] = {
    { CRYPTO_TYPE_DIGEST_SM3, soft_copy_gmssl_info },
    { CRYPTO_TYPE_DIGEST_MD5, soft_copy_digest_info },
    { CRYPTO_TYPE_DIGEST_SHA1, soft_copy_digest_info },
    { CRYPTO_TYPE_DIGEST_SHA224, soft_copy_digest_info },
    { CRYPTO_TYPE_DIGEST_SHA256, soft_copy_digest_info },
    { CRYPTO_TYPE_DIGEST_SHA384, soft_copy_digest_info },
    { CRYPTO_TYPE_DIGEST_SHA512, soft_copy_digest_info },
    { CRYPTO_TYPE_HMAC_SM3, soft_copy_gmssl_info },
    { CRYPTO_TYPE_HMAC_MD5, soft_copy_hmac_info },
    { CRYPTO_TYPE_HMAC_SHA1, soft_copy_hmac_info },
    { CRYPTO_TYPE_HMAC_SHA224, soft_copy_hmac_info },
    { CRYPTO_TYPE_HMAC_SHA256, soft_copy_hmac_info },
    { CRYPTO_TYPE_HMAC_SHA384, soft_copy_hmac_info },
    { CRYPTO_TYPE_HMAC_SHA512, soft_copy_hmac_info },
#ifdef CONFIG_CRYPTO_SUPPORT_SIPHASH
    { CRYPTO_TYPE_SIP_HASH, soft_copy_siphash_info },
#endif
    { CRYPTO_TYPE_SM4_ECB, soft_copy_gmssl_info },
    { CRYPTO_TYPE_SM4_CBC, soft_copy_gmssl_info },
    { CRYPTO_TYPE_SM4_CBC_PKCS7, soft_copy_gmssl_info },
    { CRYPTO_TYPE_SM4_CTR, soft_copy_gmssl_info },
    { CRYPTO_TYPE_SM4_CFB128, soft_copy_gmssl_info },
    { CRYPTO_TYPE_SM4_GCM, soft_copy_gmssl_info },
    { CRYPTO_TYPE_AES_ECB_NOPAD, soft_copy_aes_des_info },
    { CRYPTO_TYPE_AES_ECB_PKCS5, soft_copy_aes_des_info },
    { CRYPTO_TYPE_AES_CBC_PKCS5, soft_copy_aes_des_info },
    { CRYPTO_TYPE_AES_CBC_NOPAD, soft_copy_aes_des_info },
    { CRYPTO_TYPE_DES_ECB_NOPAD, soft_copy_aes_des_info },
    { CRYPTO_TYPE_DES_CBC_NOPAD, soft_copy_aes_des_info },
    { CRYPTO_TYPE_DES3_ECB_NOPAD, soft_copy_aes_des_info },
    { CRYPTO_TYPE_DES3_CBC_NOPAD, soft_copy_aes_des_info },
    { CRYPTO_TYPE_AES_CTR, soft_copy_aes_des_info },
    { CRYPTO_TYPE_AES_XTS, soft_copy_aes_des_info },
    { CRYPTO_TYPE_AES_CBC_MAC_NOPAD, soft_copy_aes_des_info },
    { CRYPTO_TYPE_AES_CMAC, soft_copy_cmac_info },
    { CRYPTO_TYPE_AES_CCM, soft_copy_aes_des_info },
    { CRYPTO_TYPE_AES_GCM, soft_copy_aes_des_info },

};

int32_t soft_crypto_ctx_copy(const struct ctx_handle_t *src_ctx, struct ctx_handle_t *dest_ctx)
{
    if (src_ctx == NULL || dest_ctx == NULL) {
        tloge("The src ctx or dest ctx is null\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t i = 0;
    for (; i < ARRAY_NUM(g_soft_copy_ctx); i++) {
        if (src_ctx->alg_type == g_soft_copy_ctx[i].algorithm)
            return g_soft_copy_ctx[i].copy_call_back(dest_ctx, src_ctx);
    }

    return CRYPTO_SUCCESS;
}

int32_t get_boring_nid_by_tee_curve(uint32_t tee_domain, uint32_t *nid)
{
    uint32_t index = 0;
    if (nid == NULL) {
        tloge("nid is null");
        return CRYPTO_BAD_PARAMETERS;
    }
    crypto_uint2uint domain_to_curve[] = {
        { ECC_CURVE_NIST_P192, NID_X9_62_prime192v1 },
        { ECC_CURVE_NIST_P224, NID_secp224r1 },
        { ECC_CURVE_NIST_P256, NID_X9_62_prime256v1 },
        { ECC_CURVE_NIST_P384, NID_secp384r1 },
        { ECC_CURVE_NIST_P521, NID_secp521r1 },
    };
    for (; index < sizeof(domain_to_curve) / sizeof(crypto_uint2uint); index++) {
        if (tee_domain == domain_to_curve[index].src) {
            *nid = domain_to_curve[index].dest;
            return CRYPTO_SUCCESS;
        }
    }

    tloge("invalid tee_domain 0x%x\n", tee_domain);
    return CRYPTO_BAD_PARAMETERS;
}

int32_t get_openssl_rand(unsigned char *buf, int num)
{
    if (num == 0 || num > INT32_MAX)
        return CRYPTO_BAD_PARAMETERS;
    int32_t ret = RAND_priv_bytes(buf, num);
    free_openssl_drbg_mem();
    return ret;
}

void free_openssl_drbg_mem(void)
{
    drbg_delete_thread_state();
    OPENSSL_thread_stop();
}
