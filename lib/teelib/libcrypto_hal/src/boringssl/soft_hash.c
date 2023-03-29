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
#include "soft_hash.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <tee_log.h>
#include "soft_gmssl.h"
#include "soft_common_api.h"

struct digest_config {
    uint32_t algo;
    uint32_t length;
};

static const struct digest_config g_digest_config[] = {
    { CRYPTO_TYPE_DIGEST_MD5,    MD5_DIGEST_LENGTH },
    { CRYPTO_TYPE_DIGEST_SHA1,   SHA_DIGEST_LENGTH },
    { CRYPTO_TYPE_DIGEST_SHA224, SHA224_DIGEST_LENGTH },
    { CRYPTO_TYPE_DIGEST_SHA256, SHA256_DIGEST_LENGTH },
    { CRYPTO_TYPE_DIGEST_SHA384, SHA384_DIGEST_LENGTH },
    { CRYPTO_TYPE_DIGEST_SHA512, SHA512_DIGEST_LENGTH },
};

static const uint32_t g_algorithm_digest[] = {
    CRYPTO_TYPE_DIGEST_MD5,
    CRYPTO_TYPE_DIGEST_SHA1,
    CRYPTO_TYPE_DIGEST_SHA224,
    CRYPTO_TYPE_DIGEST_SHA256,
    CRYPTO_TYPE_DIGEST_SHA384,
    CRYPTO_TYPE_DIGEST_SHA512,
    CRYPTO_TYPE_DIGEST_SM3,
};

static const struct digest_config *get_hash_config(uint32_t alg_type)
{
    for (size_t i = 0; i < sizeof(g_digest_config) / sizeof(g_digest_config[0]); i++) {
        if (alg_type == g_digest_config[i].algo)
            return &g_digest_config[i];
    }

    return NULL;
}

static int32_t digest_init(uint32_t alg_type, void *ctx)
{
    int32_t rc = BORINGSSL_ERR;

    switch (alg_type) {
    case CRYPTO_TYPE_DIGEST_MD5:
        rc = MD5_Init(ctx);
        break;
    case CRYPTO_TYPE_DIGEST_SHA1:
        rc = SHA1_Init(ctx);
        break;
    case CRYPTO_TYPE_DIGEST_SHA224:
        rc = SHA224_Init(ctx);
        break;
    case CRYPTO_TYPE_DIGEST_SHA256:
        rc = SHA256_Init(ctx);
        break;
    case CRYPTO_TYPE_DIGEST_SHA384:
        rc = SHA384_Init(ctx);
        break;
    case CRYPTO_TYPE_DIGEST_SHA512:
        rc = SHA512_Init(ctx);
        break;
    default:
        break;
    }
    return rc;
}

static bool check_valid_dest_len(uint32_t alg_type, uint32_t size)
{
    const struct digest_config *config = get_hash_config(alg_type);
    if (config == NULL)
        return false;

    return size >= config->length;
}

static int32_t do_hash_final(uint8_t *out_buffer, struct ctx_handle_t *ctx)
{
    int32_t rc = BORINGSSL_ERR;

    switch (ctx->alg_type) {
    case CRYPTO_TYPE_DIGEST_MD5:
        rc = MD5_Final(out_buffer, (MD5_CTX*)(uintptr_t)(ctx->ctx_buffer));
        break;
    case CRYPTO_TYPE_DIGEST_SHA1:
        rc = SHA1_Final(out_buffer, (SHA_CTX *)(uintptr_t)(ctx->ctx_buffer));
        break;
    case CRYPTO_TYPE_DIGEST_SHA224:
        rc = SHA224_Final(out_buffer, (SHA256_CTX *)(uintptr_t)(ctx->ctx_buffer));
        break;
    case CRYPTO_TYPE_DIGEST_SHA256:
        rc = SHA256_Final(out_buffer, (SHA256_CTX *)(uintptr_t)(ctx->ctx_buffer));
        break;
    case CRYPTO_TYPE_DIGEST_SHA384:
        rc = SHA384_Final(out_buffer, (SHA512_CTX *)(uintptr_t)(ctx->ctx_buffer));
        break;
    case CRYPTO_TYPE_DIGEST_SHA512:
        rc = SHA512_Final(out_buffer, (SHA512_CTX *)(uintptr_t)(ctx->ctx_buffer));
        break;
    default:
        break;
    }
    return rc;
}

static int32_t digest_dofinal(struct ctx_handle_t *ctx, struct memref_t *data_out)
{
    bool check = (ctx == NULL || data_out == NULL || data_out->buffer == 0);
    if (check)
        return BORINGSSL_ERR;

    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;
    int32_t ret = do_hash_final(out_buffer, ctx);
    if (ret != BORINGSSL_OK) {
        tloge("do digest final failed!");
        return BORINGSSL_ERR;
    }

    const struct digest_config *config = get_hash_config(ctx->alg_type);
    if (config == NULL)
        return BORINGSSL_ERR;

    data_out->size = config->length;

    return BORINGSSL_OK;
}

int32_t soft_crypto_hash_init(struct ctx_handle_t *ctx)
{
    if (ctx == NULL)
        return CRYPTO_BAD_PARAMETERS;

    if (ctx->alg_type == CRYPTO_TYPE_DIGEST_SM3)
        return sm3_digest_init(ctx);

    int32_t rc = check_valid_algorithm(ctx->alg_type, g_algorithm_digest, ARRAY_NUM(g_algorithm_digest));
    if (rc != CRYPTO_SUCCESS) {
        tloge("algorithm 0x%x is incorrect", ctx->alg_type);
        return rc;
    }

    uint32_t hash_size = get_hash_context_size(ctx->alg_type);
    void *hash_ctx = TEE_Malloc(hash_size, 0);
    if (hash_ctx == NULL) {
        tloge("Malloc failed!");
        return CRYPTO_BAD_PARAMETERS;
    }

    rc = digest_init(ctx->alg_type, hash_ctx);
    if (rc != BORINGSSL_OK) {
        tloge("hash init failed!");
        TEE_Free(hash_ctx);
        return CRYPTO_BAD_FORMAT;
    }

    ctx->ctx_size = hash_size;
    ctx->ctx_buffer = (uint64_t)(uintptr_t)hash_ctx;
    return CRYPTO_SUCCESS;
}

static int32_t do_hash_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;

    switch (ctx->alg_type) {
    case CRYPTO_TYPE_DIGEST_MD5:
        return MD5_Update((MD5_CTX *)(uintptr_t)(ctx->ctx_buffer), in_buffer, data_in->size);
    case CRYPTO_TYPE_DIGEST_SHA1:
        return SHA1_Update((SHA_CTX *)(uintptr_t)(ctx->ctx_buffer), in_buffer, data_in->size);
    case CRYPTO_TYPE_DIGEST_SHA224:
        return SHA224_Update((SHA256_CTX *)(uintptr_t)(ctx->ctx_buffer), in_buffer, data_in->size);
    case CRYPTO_TYPE_DIGEST_SHA256:
        return SHA256_Update((SHA256_CTX *)(uintptr_t)(ctx->ctx_buffer), in_buffer, data_in->size);
    case CRYPTO_TYPE_DIGEST_SHA384:
        return SHA384_Update((SHA512_CTX *)(uintptr_t)(ctx->ctx_buffer), in_buffer, data_in->size);
    case CRYPTO_TYPE_DIGEST_SHA512:
        return SHA512_Update((SHA512_CTX *)(uintptr_t)(ctx->ctx_buffer), in_buffer, data_in->size);
    default:
        return BORINGSSL_ERR;
    }
}

int32_t soft_crypto_hash_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    bool check = (ctx == NULL || ctx->ctx_buffer == 0 || data_in == NULL || data_in->buffer == 0);
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (ctx->alg_type == CRYPTO_TYPE_DIGEST_SM3)
        return sm3_digest_update(ctx, data_in);

    int32_t rc = do_hash_update(ctx, data_in);
    if (rc != BORINGSSL_OK) {
        tloge("hash update failed");
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_hash_dofinal(struct ctx_handle_t *ctx, struct memref_t *data_out)
{
    int32_t rc;
    bool check = (ctx == NULL || ctx->ctx_buffer == 0);
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    check = (data_out == NULL || data_out->buffer == 0);
    if (check) {
        tloge("Invalid params\n");
        rc = CRYPTO_BAD_PARAMETERS;
        goto free_ctx;
    }

    if (ctx->alg_type == CRYPTO_TYPE_DIGEST_SM3)
        return sm3_digest_dofinal(ctx, data_out);

    check = check_valid_dest_len(ctx->alg_type, data_out->size);
    if (!check) {
        tloge("dest len is not large enough!");
        rc =  CRYPTO_SHORT_BUFFER;
        goto free_ctx;
    }

    rc = digest_dofinal(ctx, data_out);
    if (rc != BORINGSSL_OK) {
        tloge("hash dofinal failed");
        rc = CRYPTO_BAD_PARAMETERS;
        goto free_ctx;
    }

    rc = CRYPTO_SUCCESS;

free_ctx:
    TEE_Free((void *)(uintptr_t)(ctx->ctx_buffer));
    ctx->ctx_buffer = 0;
    return rc;
}

static void do_hash(uint32_t alg_type, const struct memref_t *data_in, struct memref_t *data_out)
{
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;

    switch (alg_type) {
    case CRYPTO_TYPE_DIGEST_MD5:
        out_buffer = MD5((const uint8_t *)(uintptr_t)data_in->buffer, data_in->size, out_buffer);
        data_out->size = MD5_DIGEST_LENGTH;
        break;
    case CRYPTO_TYPE_DIGEST_SHA1:
        out_buffer = SHA1((const uint8_t *)(uintptr_t)data_in->buffer, data_in->size, out_buffer);
        data_out->size = SHA_DIGEST_LENGTH;
        break;
    case CRYPTO_TYPE_DIGEST_SHA224:
        out_buffer = SHA224((const uint8_t *)(uintptr_t)data_in->buffer, data_in->size, out_buffer);
        data_out->size = SHA224_DIGEST_LENGTH;
        break;
    case CRYPTO_TYPE_DIGEST_SHA256:
        out_buffer = SHA256((const uint8_t *)(uintptr_t)data_in->buffer, data_in->size, out_buffer);
        data_out->size = SHA256_DIGEST_LENGTH;
        break;
    case CRYPTO_TYPE_DIGEST_SHA384:
        out_buffer = SHA384((const uint8_t *)(uintptr_t)data_in->buffer, data_in->size, out_buffer);
        data_out->size = SHA384_DIGEST_LENGTH;
        break;
    case CRYPTO_TYPE_DIGEST_SHA512:
        out_buffer = SHA512((const uint8_t *)(uintptr_t)data_in->buffer, data_in->size, out_buffer);
        data_out->size = SHA512_DIGEST_LENGTH;
        break;
    default:
        break;
    }
}

static int32_t check_hash_param(uint32_t alg_type, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (data_in == NULL || data_out == NULL || data_in->buffer == 0 || data_out->buffer == 0);
    if (check) {
        tloge("param is Invalid");
        return CRYPTO_BAD_PARAMETERS;
    }

    check = check_valid_dest_len(alg_type, data_out->size);
    if (!check) {
        tloge("dest len is not large enough!");
        return CRYPTO_SHORT_BUFFER;
    }
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_hash(uint32_t alg_type, const struct memref_t *data_in, struct memref_t *data_out)
{
    if (alg_type == CRYPTO_TYPE_DIGEST_SM3)
        return crypto_sm3_hash(data_in, data_out);

    int32_t ret = (check_hash_param(alg_type, data_in, data_out));
    if (ret != CRYPTO_SUCCESS)
        return ret;

    do_hash(alg_type, data_in, data_out);
    if (data_out->buffer == 0) {
        tloge("do hash failed");
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}
