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
#include "soft_hmac.h"
#include <openssl/hmac.h>
#include <crypto/siphash.h>
#include <siphash/siphash_local.h>
#include <tee_log.h>
#include "soft_gmssl.h"
#include "soft_common_api.h"
#include "soft_err.h"

static const uint32_t g_algorithm_hmac[] = {
    CRYPTO_TYPE_HMAC_MD5,
    CRYPTO_TYPE_HMAC_SHA1,
    CRYPTO_TYPE_HMAC_SHA224,
    CRYPTO_TYPE_HMAC_SHA256,
    CRYPTO_TYPE_HMAC_SHA384,
    CRYPTO_TYPE_HMAC_SHA512,
    CRYPTO_TYPE_HMAC_SM3,
    CRYPTO_TYPE_SIP_HASH,
};

struct hamc_evp {
    uint32_t algorithm;
    const EVP_MD *(*hmac_api)(void);
};
static const EVP_MD *get_hmac_evp(uint32_t algorithm)
{
    struct hamc_evp g_hmac_config[] = {
        { CRYPTO_TYPE_HMAC_MD5, EVP_md5 },
        { CRYPTO_TYPE_HMAC_SHA1, EVP_sha1 },
        { CRYPTO_TYPE_HMAC_SHA224, EVP_sha224 },
        { CRYPTO_TYPE_HMAC_SHA256, EVP_sha256 },
        { CRYPTO_TYPE_HMAC_SHA384, EVP_sha384 },
        { CRYPTO_TYPE_HMAC_SHA512, EVP_sha512 },
    };

    for (size_t i = 0; i < sizeof(g_hmac_config) / sizeof(g_hmac_config[0]); i++) {
        if (algorithm == g_hmac_config[i].algorithm)
            return g_hmac_config[i].hmac_api();
    }

    return NULL;
}

static int32_t sip_hash_mac_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key)
{
    if (key->key_size != SIPHASH_KEY_SIZE) {
        tloge("key_size error! key_size = %d", key->key_size);
        return CRYPTO_BAD_PARAMETERS;
    }

    SIPHASH *siphash_ctx = TEE_Malloc(sizeof(*siphash_ctx), 0);
    if (siphash_ctx == NULL) {
        tloge("siphash_ctx malloc failed!");
        return CRYPTO_ERROR_SECURITY;
    }

    int ret = SipHash_set_hash_size(siphash_ctx, SIP_HASH_OUTPUT_LEN);
    if (ret != BORINGSSL_OK) {
        tloge("hash size invalid! hash size = %d", SIP_HASH_OUTPUT_LEN);
        TEE_Free((void *)siphash_ctx);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = SipHash_Init(siphash_ctx, (const uint8_t *)(uintptr_t)(key->key_buffer), 0, 0);
    if (ret != BORINGSSL_OK) {
        tloge("sip hash initialize failed!");
        TEE_Free((void *)siphash_ctx);
        return get_soft_crypto_error(CRYPTO_BAD_STATE);
    }
    ctx->ctx_buffer = (uint64_t)(uintptr_t)siphash_ctx;
    ctx->ctx_size = sizeof(*siphash_ctx);

    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_hmac_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key)
{
    bool check = (ctx == NULL || key == NULL || key->key_buffer == 0 || key->key_size == 0);
    if (check) {
        tloge("invalid params");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (ctx->alg_type == CRYPTO_TYPE_HMAC_SM3)
        return sm3_mac_init(ctx, key);

    if (ctx->alg_type == CRYPTO_TYPE_SIP_HASH)
        return sip_hash_mac_init(ctx, key);

    int32_t rc = check_valid_algorithm(ctx->alg_type, g_algorithm_hmac, ARRAY_NUM(g_algorithm_hmac));
    if (rc != CRYPTO_SUCCESS) {
        tloge("algorithm 0x%x is incorrect", ctx->alg_type);
        return rc;
    }

    const EVP_MD *md = get_hmac_evp(ctx->alg_type);
    if (md == NULL) {
        tloge("hmac md is NULL");
        return CRYPTO_BAD_PARAMETERS;
    }

    void *hmac_ctx = HMAC_CTX_new();
    if (hmac_ctx == NULL) {
        tloge("hmac ctx is NULL");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint8_t *key_buffer = (uint8_t *)(uintptr_t)key->key_buffer;
    rc = HMAC_Init(hmac_ctx, key_buffer, key->key_size, md);
    if (rc != BORINGSSL_OK) {
        tloge("hmac init failed! ret = %d\n", rc);
        HMAC_CTX_free(hmac_ctx);
        return get_soft_crypto_error(CRYPTO_MAC_INVALID);
    }

    ctx->ctx_buffer = (uint64_t)(uintptr_t)hmac_ctx;
    ctx->free_context = free_hmac_context;
    return CRYPTO_SUCCESS;
}

static int32_t sip_hash_mac_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    if (data_in->size == 0) {
        tloge("invalid params. data_in size is 0");
        TEE_Free((void *)(uintptr_t)ctx->ctx_buffer);
        ctx->ctx_buffer = 0;
        return CRYPTO_BAD_PARAMETERS;
    }

    SipHash_Update((SIPHASH *)(uintptr_t)ctx->ctx_buffer, (const uint8_t *)(uintptr_t)data_in->buffer, data_in->size);

    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_hmac_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    bool check = (ctx == NULL || ctx->ctx_buffer == 0 || data_in == NULL || data_in->buffer == 0);
    if (check) {
        tloge("invalid params");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (ctx->alg_type == CRYPTO_TYPE_HMAC_SM3)
        return sm3_mac_update(ctx, data_in);

    if (ctx->alg_type == CRYPTO_TYPE_SIP_HASH)
        return sip_hash_mac_update(ctx, data_in);

    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    int32_t rc = HMAC_Update((HMAC_CTX *)(uintptr_t)(ctx->ctx_buffer), in_buffer, data_in->size);
    if (rc != BORINGSSL_OK) {
        tloge("HMAC_Update failed!");
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

static int32_t sip_hash_mac_computefinal(struct ctx_handle_t *ctx, struct memref_t *data_out)
{
    if (data_out->size < SIP_HASH_OUTPUT_LEN) {
        tloge("data out size is too short");
        TEE_Free((void *)(uintptr_t)ctx->ctx_buffer);
        ctx->ctx_buffer = 0;
        return CRYPTO_BAD_PARAMETERS;
    }

    SIPHASH *siphash_ctx = (SIPHASH *)(uintptr_t)ctx->ctx_buffer;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;
    uint32_t mac_len_temp = SIP_HASH_OUTPUT_LEN;

    int32_t rc = SipHash_Final(siphash_ctx, out_buffer, mac_len_temp);
    if (rc != BORINGSSL_OK) {
        tloge("sip hash mac final failed!");
        TEE_Free((void *)(uintptr_t)ctx->ctx_buffer);
        ctx->ctx_buffer = 0;
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    data_out->size = mac_len_temp;
    TEE_Free((void *)(uintptr_t)ctx->ctx_buffer);
    ctx->ctx_buffer = 0;
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_hmac_dofinal(struct ctx_handle_t *ctx, struct memref_t *data_out)
{
    bool check = (ctx == NULL || ctx->ctx_buffer == 0);
    if (check) {
        tloge("invalid params");
        return CRYPTO_BAD_PARAMETERS;
    }

    check = (data_out == NULL || data_out->buffer == 0);
    if (check) {
        tloge("invalid params");
        free_hmac_context(&(ctx->ctx_buffer));
        return CRYPTO_BAD_PARAMETERS;
    }

    if (ctx->alg_type == CRYPTO_TYPE_HMAC_SM3)
        return sm3_mac_computefinal(ctx, data_out);

    if (ctx->alg_type == CRYPTO_TYPE_SIP_HASH)
        return sip_hash_mac_computefinal(ctx, data_out);

    uint32_t mac_len_temp = data_out->size;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;

    int32_t rc = HMAC_Final((HMAC_CTX *)(uintptr_t)(ctx->ctx_buffer), out_buffer, &mac_len_temp);
    if (rc != BORINGSSL_OK) {
        tloge("hmac final failed!");
        free_hmac_context(&(ctx->ctx_buffer));
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    data_out->size = mac_len_temp;
    free_hmac_context(&(ctx->ctx_buffer));
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_hmac(uint32_t alg_type, const struct symmerit_key_t *key,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    if (alg_type == CRYPTO_TYPE_HMAC_SM3)
        return crypto_sm3_hmac(key, data_in, data_out);

    bool check = (key == NULL || data_in == NULL || data_out == NULL || data_in->buffer == 0 || data_out->buffer == 0);
    if (check) {
        tloge("param is Invalid");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t out_len = data_out->size;
    const EVP_MD *md = get_hmac_evp(alg_type);
    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;
    uint8_t *key_buffer = (uint8_t *)(uintptr_t)key->key_buffer;

    out_buffer = HMAC(md, key_buffer, key->key_size, in_buffer,
        data_in->size, out_buffer, &out_len);
    if (data_out->buffer == 0) {
        tloge("hmac failed");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    data_out->size = out_len;
    return CRYPTO_SUCCESS;
}
