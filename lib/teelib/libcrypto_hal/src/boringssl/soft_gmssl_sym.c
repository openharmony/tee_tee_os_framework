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

#include "soft_gmssl.h"
#include "gmssl_internal.h"
#include "soft_err.h"
#include <securec.h>
#include <openssl/hmac.h>
#include <hmac/hmac_local.h>
#include <openssl/ossl_typ.h>
#include <evp/evp_local.h>
#include <tee_log.h>
#include <tee_crypto_api.h>
#include <tee_property_inner.h>
#include "crypto_inner_defines.h"

#ifdef CRYPTO_SUPPORT_SOFT_SM4
static TEE_Result sm4_cipher_init_params_check(uint32_t alg_type, const struct memref_t *iv)
{
    bool check = (alg_type == TEE_ALG_SM4_CTR) || (alg_type == TEE_ALG_SM4_CBC_NOPAD) ||
                 (alg_type == TEE_ALG_SM4_CFB128) || (alg_type == TEE_ALG_SM4_CBC_PKCS7) ||
                 (alg_type == TEE_ALG_SM4_GCM);
    if (check) {
        bool check_iv = (iv == NULL || iv->buffer == 0 || iv->size == 0);
        if (check_iv) {
            tloge("IV is NULL, please set IV first\n");
            return CRYPTO_BAD_PARAMETERS;
        }
    }

    return CRYPTO_SUCCESS;
}

static int32_t sm4_cbc_encrypt_init(uint32_t direction, EVP_CIPHER_CTX *ctx, uint8_t *key_buffer, uint8_t *iv_buffer)
{
    if (direction == ENC_MODE)
        return EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key_buffer,
            (unsigned char *)iv_buffer);
    return EVP_DecryptInit_ex(ctx, EVP_sm4_cbc(), NULL, key_buffer,
        (unsigned char *)iv_buffer);
}

static int32_t sm4_ecb_encrypt_init(uint32_t direction, EVP_CIPHER_CTX *ctx, uint8_t *key_buffer, uint8_t *iv_buffer)
{
    if (direction == ENC_MODE)
        return EVP_EncryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key_buffer,
            (unsigned char *)iv_buffer);
    return EVP_DecryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key_buffer,
        (unsigned char *)iv_buffer);
}

static int32_t sm4_ctr_encrypt_init(uint32_t direction, EVP_CIPHER_CTX *ctx, uint8_t *key_buffer, uint8_t *iv_buffer)
{
    if (direction == ENC_MODE)
        return EVP_EncryptInit_ex(ctx, EVP_sm4_ctr(), NULL, key_buffer,
            (unsigned char *)iv_buffer);
    return EVP_DecryptInit_ex(ctx, EVP_sm4_ctr(), NULL, key_buffer,
        (unsigned char *)iv_buffer);
}

static int32_t sm4_cfb_encrypt_init(uint32_t direction, EVP_CIPHER_CTX *ctx,
    const uint8_t *key_buffer, const uint8_t *iv_buffer)
{
    if (direction == ENC_MODE)
        return EVP_EncryptInit_ex(ctx, EVP_sm4_cfb128(), NULL, key_buffer,
            (unsigned char *)iv_buffer);
    return EVP_DecryptInit_ex(ctx, EVP_sm4_cfb128(), NULL, key_buffer,
        (unsigned char *)iv_buffer);
}

static int32_t sm4_do_encrypt_init(EVP_CIPHER_CTX *ctx, uint32_t alg_type, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv)
{
    uint8_t *iv_buffer = NULL;
    bool check = (alg_type == TEE_ALG_SM4_CBC_NOPAD || alg_type == TEE_ALG_SM4_CTR) ||
                 (alg_type == TEE_ALG_SM4_CBC_PKCS7) || (alg_type == TEE_ALG_SM4_CFB128);
    if (check)
        iv_buffer = (uint8_t *)(uintptr_t)(iv->buffer);
    uint8_t *key_buffer = (uint8_t *)(uintptr_t)(key->key_buffer);

    switch (alg_type) {
    case TEE_ALG_SM4_CBC_NOPAD:
    case TEE_ALG_SM4_CBC_PKCS7:
        return sm4_cbc_encrypt_init(direction, ctx, key_buffer, iv_buffer);
    case TEE_ALG_SM4_ECB_NOPAD:
        return sm4_ecb_encrypt_init(direction, ctx, key_buffer, iv_buffer);
    case TEE_ALG_SM4_CTR:
        return sm4_ctr_encrypt_init(direction, ctx, key_buffer, iv_buffer);
    case TEE_ALG_SM4_CFB128:
        return sm4_cfb_encrypt_init(direction, ctx, key_buffer, iv_buffer);
    default:
        return GMSSL_ERR;
    }
}

void *tee_sm4_cipher_init(uint32_t alg_type, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv)
{
    int32_t ret;
    TEE_Result ret_c;
    bool check = (key == NULL || key->key_buffer == 0 || key->key_size == 0);
    if (check) {
        tloge("keybuf is NULL");
        return NULL;
    }

    ret_c = sm4_cipher_init_params_check(alg_type, iv);
    if (ret_c != CRYPTO_SUCCESS) {
        tloge("check iv failed\n");
        return NULL;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        tloge("New SM4 ctx failed");
        return NULL;
    }
    ret = EVP_CIPHER_CTX_reset(ctx);
    if (ret != 1) {
        tloge("init SM4 ctx failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    ret = sm4_do_encrypt_init(ctx, alg_type, direction, key, iv);
    if (ret != 1)
        goto exit;

    if (alg_type == TEE_ALG_SM4_CBC_PKCS7)
        (void)EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
    else
        (void)EVP_CIPHER_CTX_set_padding(ctx, 0);
    return ctx;

exit:
    tloge("EVP sm4 cipher init failed\n");
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
}

int32_t sm4_cipher_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key, const struct memref_t *iv)
{
    bool check = (ctx == NULL || key == NULL || key->key_buffer == 0 || key->key_size == 0);
    if (check) {
        tloge("input is null\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    void *sm4_ctx = tee_sm4_cipher_init(ctx->alg_type, ctx->direction, key, iv);
    if (sm4_ctx == NULL) {
        tloge("sm4 init failed");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    ctx->ctx_buffer = (uint64_t)(uintptr_t)sm4_ctx;
    ctx->free_context = free_sm4_context;
    return CRYPTO_SUCCESS;
}

static int32_t sm4_update_params_check(uint32_t alg_type, uint32_t src_len, uint32_t dest_len)
{
    if (alg_type == TEE_ALG_SM4_CBC_PKCS7)
        return CRYPTO_SUCCESS;

    bool check = (alg_type == TEE_ALG_SM4_ECB_NOPAD) || (alg_type == TEE_ALG_SM4_CBC_NOPAD);
    if (check) {
        if ((src_len % SM4_BLOCK) != 0) {
            tloge("DataSize should be 16 bytes aligned!");
            return CRYPTO_BAD_PARAMETERS;
        }
    }

    if (dest_len < src_len || dest_len == 0) {
        tloge("output buffer is too small\n");
        return CRYPTO_SHORT_BUFFER;
    }

    return CRYPTO_SUCCESS;
}

static int32_t tee_sm4_update(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    int32_t ret;

    EVP_CIPHER_CTX *sm4_ctx = (EVP_CIPHER_CTX *)(uintptr_t)ctx->ctx_buffer;
    if (sm4_ctx == NULL) {
        tloge("The sm4 cipher ctx is null");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;

    ret = sm4_update_params_check(ctx->alg_type, data_in->size, data_out->size);
    if (ret != CRYPTO_SUCCESS) {
        tloge("sm4 update parameter check failed\n");
        return ret;
    }

    if (data_out->size > INT32_MAX) {
        tloge("data out size is too long\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    int32_t temp_dest_len = (int32_t)data_out->size;
    if (ctx->direction == ENC_MODE)
        ret = EVP_EncryptUpdate(sm4_ctx, out_buffer, &temp_dest_len, in_buffer, data_in->size);
    else
        ret = EVP_DecryptUpdate(sm4_ctx, out_buffer, &temp_dest_len, in_buffer, data_in->size);
    if (ret != GMSSL_OK || temp_dest_len < 0) {
        tloge("sm4 cipher update failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    data_out->size = (uint32_t)temp_dest_len;
    return CRYPTO_SUCCESS;
}

int32_t sm4_cipher_update(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    bool check = (ctx == NULL || data_in == NULL || data_out == NULL ||
        ((ctx->alg_type != TEE_ALG_SM4_CBC_PKCS7 || ctx->direction == ENC_MODE) && data_out->size < data_in->size));
    if (check) {
        tloge("input is null\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    return tee_sm4_update(ctx, data_in, data_out);
}

static int32_t tee_sm4_do_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    int32_t ret;
    int32_t update_len = 0;
    uint32_t temp_len = data_out->size;
    if (data_in->buffer != 0 && data_in->size != 0) {
        ret = tee_sm4_update(ctx, data_in, data_out);
        if (ret != CRYPTO_SUCCESS) {
            tloge("sm4 update last block failed");
            EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)(uintptr_t)(ctx->ctx_buffer));
            ctx->ctx_buffer = 0;
            return ret;
        }
        update_len = (int32_t)data_out->size;
    }

    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;
    int32_t final_len = temp_len - update_len;
    if (ctx->direction == ENC_MODE)
        ret = EVP_EncryptFinal_ex((EVP_CIPHER_CTX *)(uintptr_t)ctx->ctx_buffer,
            out_buffer + update_len, &final_len);
    else
        ret = EVP_DecryptFinal_ex((EVP_CIPHER_CTX *)(uintptr_t)ctx->ctx_buffer,
            out_buffer + update_len, &final_len);
    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)(uintptr_t)(ctx->ctx_buffer));
    ctx->ctx_buffer = 0;
    if (ret != 1) {
        tloge("sm4 cipher final failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    if (update_len > INT32_MAX - final_len) {
        tloge("final len is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }
    data_out->size = (uint32_t)(update_len + final_len);
    return CRYPTO_SUCCESS;
}

int32_t sm4_cipher_do_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    bool check = (ctx == NULL || data_in == NULL || data_out == NULL || data_out->buffer == 0 ||
                  data_out->size == 0 || data_out->size < data_in->size);
    if (check) {
        tloge("bad parameters\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    return tee_sm4_do_final(ctx, data_in, data_out);
}
#endif // CRYPTO_SUPPORT_SOFT_SM4

int32_t sm3_mac_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key)
{
    bool check = (ctx == NULL || key == NULL || key->key_buffer == 0 || key->key_size == 0);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    HMAC_CTX *hmac_ctx = HMAC_CTX_new();
    if (hmac_ctx == NULL) {
        tloge("malloc failed!\n");
        return get_soft_crypto_error(CRYPTO_NOT_SUPPORTED);
    }

    if (HMAC_Init(hmac_ctx, (const unsigned char *)(uintptr_t)(key->key_buffer), key->key_size, EVP_sm3()) == 0) {
        tloge("sm3 hmac failed");
        HMAC_CTX_free(hmac_ctx);
        return get_soft_crypto_error(CRYPTO_MAC_INVALID);
    }
    ctx->ctx_buffer = (uint64_t)(uintptr_t)hmac_ctx;
    ctx->ctx_size = sizeof(*hmac_ctx);

    return CRYPTO_SUCCESS;
}

int32_t sm3_mac_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    int32_t ret;
    bool check = (ctx == NULL || ctx->ctx_buffer == 0 || data_in == NULL ||
        data_in->buffer == 0 || data_in->size == 0);
    if (check) {
        tloge("bad params\n");
        ret = CRYPTO_BAD_PARAMETERS;
        goto out;
    }

    if (HMAC_Update((HMAC_CTX *)(uintptr_t)(ctx->ctx_buffer),
                    (const unsigned char *)(uintptr_t)(data_in->buffer), data_in->size) == 0) {
        tloge("sm3 hmac failed");
        ret = get_soft_crypto_error(CRYPTO_MAC_INVALID);
        goto out;
    }
    return CRYPTO_SUCCESS;
out:
    if (ctx != NULL) {
        HMAC_CTX_free((HMAC_CTX *)(uintptr_t)ctx->ctx_buffer);
        ctx->ctx_buffer = 0;
    }
    return ret;
}

int32_t sm3_mac_computefinal(struct ctx_handle_t *ctx, struct memref_t *data_out)
{
    int32_t ret;
    if (ctx == NULL || ctx->ctx_buffer == 0)
        return CRYPTO_BAD_PARAMETERS;

    bool check = (data_out == NULL || data_out->buffer == 0 || data_out->size < SM3_DIGEST_LENGTH);
    if (check) {
        tloge("context is NULL");
        ret = CRYPTO_BAD_PARAMETERS;
        goto out;
    }

    uint32_t out_len = 0;
    if (HMAC_Final((HMAC_CTX *)(uintptr_t)(ctx->ctx_buffer),
                   (unsigned char *)(uintptr_t)data_out->buffer, &out_len) == 0) {
        tloge("sm3 hmac failed");
        ret = get_soft_crypto_error(CRYPTO_MAC_INVALID);
        goto out;
    }

    data_out->size = out_len;
    ret = CRYPTO_SUCCESS;
out:
    HMAC_CTX_free((HMAC_CTX *)(uintptr_t)ctx->ctx_buffer);
    ctx->ctx_buffer = 0;
    return ret;
}

int32_t sm3_digest_init(struct ctx_handle_t *ctx)
{
    if (ctx == NULL)
        return CRYPTO_BAD_PARAMETERS;

    EVP_MD_CTX *sm3_ctx = EVP_MD_CTX_new();
    if (sm3_ctx == NULL) {
        tloge("malloc context failed!\n");
        return get_soft_crypto_error(CRYPTO_ERROR_OUT_OF_MEMORY);
    }

    if (EVP_DigestInit(sm3_ctx, EVP_sm3()) == 0) {
        tloge("sm3 init failed");
        EVP_MD_CTX_free(sm3_ctx);
        return get_soft_crypto_error(CRYPTO_MAC_INVALID);
    }

    ctx->ctx_buffer = (uint64_t)(uintptr_t)sm3_ctx;
    ctx->ctx_size = sizeof(*sm3_ctx);

    return CRYPTO_SUCCESS;
}

int32_t sm3_digest_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    int32_t ret;
    bool check = (ctx == NULL || ctx->ctx_buffer == 0 || data_in == NULL ||
        data_in->buffer == 0 || data_in->size == 0);
    if (check) {
        tloge("Invalid params\n");
        ret = CRYPTO_BAD_PARAMETERS;
        goto out;
    }

    if (EVP_DigestUpdate((EVP_MD_CTX *)(uintptr_t)(ctx->ctx_buffer),
                         (const unsigned char *)(uintptr_t)data_in->buffer, (size_t)data_in->size) == 0) {
        tloge("sm3 hash update failed");
        ret = CRYPTO_MAC_INVALID;
        goto out;
    }

    return CRYPTO_SUCCESS;
out:
    if (ctx != NULL) {
        TEE_Free((void *)(uintptr_t)ctx->ctx_buffer);
        ctx->ctx_buffer = 0;
    }
    return ret;
}

int32_t sm3_digest_dofinal(struct ctx_handle_t *ctx, struct memref_t *data_out)
{
    int32_t ret;
    bool check = (ctx == NULL || ctx->ctx_buffer == 0);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    check = (data_out == NULL || data_out->buffer == 0 || data_out->size < SM3_DIGEST_LENGTH);
    if (check) {
        tloge("context is NULL");
        ret = CRYPTO_BAD_PARAMETERS;
        goto out;
    }

    if (EVP_DigestFinal((EVP_MD_CTX *)(uintptr_t)(ctx->ctx_buffer),
                        (unsigned char *)(uintptr_t)(data_out->buffer), NULL) == 0) {
        tloge("do sm3 hash failed");
        ret = get_soft_crypto_error(CRYPTO_MAC_INVALID);
        goto out;
    }
    data_out->size = SM3_DIGEST_LENGTH;

    ret = CRYPTO_SUCCESS;

out:
    EVP_MD_CTX_free((EVP_MD_CTX *)(uintptr_t)ctx->ctx_buffer);
    ctx->ctx_buffer = 0;
    return ret;
}

static int32_t copy_sm_buf_info(uint64_t *dst_buf, const uint64_t src_buf, uint32_t src_size)
{
    TEE_Free((void *)(uintptr_t)*dst_buf);
    *dst_buf = 0;
    bool check = ((src_buf == 0) || (src_size == 0));
    if (check)
        return CRYPTO_SUCCESS;

    *dst_buf = (uint64_t)(uintptr_t)TEE_Malloc(src_size, TEE_MALLOC_FILL_ZERO);
    if (*dst_buf == 0) {
        tloge("dst_buf malloc failed\n");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    (void)memcpy_s((void *)(uintptr_t)*dst_buf, src_size, (void *)(uintptr_t)src_buf, src_size);

    return CRYPTO_SUCCESS;
}

static int32_t copy_sm4_operation(struct ctx_handle_t *dest, const struct ctx_handle_t *src)
{
    if (dest == NULL || src == NULL)
        return CRYPTO_BAD_PARAMETERS;

    if (dest->ctx_buffer != 0) {
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)(uintptr_t)(dest->ctx_buffer));
        dest->ctx_buffer = 0;
    }
    if (src->ctx_buffer == 0)
        return CRYPTO_SUCCESS;

    EVP_CIPHER_CTX *new_ctx = EVP_CIPHER_CTX_new();
    if (new_ctx == NULL) {
        tloge("New aes ctx failed");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    int32_t ret = EVP_CIPHER_CTX_copy(new_ctx, (EVP_CIPHER_CTX *)(uintptr_t)(src->ctx_buffer));
    if (ret != GMSSL_OK) {
        tloge("Copy aes ctx failed");
        EVP_CIPHER_CTX_free(new_ctx);
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    dest->ctx_buffer = (uint64_t)(uintptr_t)new_ctx;

    return CRYPTO_SUCCESS;
}

int32_t soft_copy_gmssl_info(struct ctx_handle_t *dest, const struct ctx_handle_t *src)
{
    bool check = (dest == NULL || src == NULL);
    if (check) {
        tloge("Invalid params!\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    switch (src->alg_type) {
    case TEE_ALG_SM3:
        return copy_sm_buf_info(&(dest->ctx_buffer), src->ctx_buffer, sizeof(EVP_MD_CTX));
    case TEE_ALG_HMAC_SM3:
        return copy_sm_buf_info(&(dest->ctx_buffer), src->ctx_buffer, sizeof(HMAC_CTX));
    case TEE_ALG_SM4_ECB_NOPAD:
    case TEE_ALG_SM4_CBC_NOPAD:
    case TEE_ALG_SM4_CBC_PKCS7:
    case TEE_ALG_SM4_CTR:
    case TEE_ALG_SM4_CFB128:
    case TEE_ALG_SM4_GCM:
        return copy_sm4_operation(dest, src);
    default:
        return CRYPTO_SUCCESS;
    }
}

void free_sm4_context(uint64_t *ctx)
{
    bool check = (ctx == NULL || *ctx == 0);
    if (check) {
        tloge("Invalid params!\n");
        return;
    }

    EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)(uintptr_t)(*ctx));
    *ctx = 0;
}

int32_t crypto_sm3_hash(const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (data_in == NULL || data_out == NULL);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    struct ctx_handle_t ctx;
    int32_t rc = sm3_digest_init(&ctx);
    if (rc != CRYPTO_SUCCESS) {
        tloge("sm3 hash init failed");
        return get_soft_crypto_error(CRYPTO_ERROR_SECURITY);
    }

    rc = sm3_digest_update(&ctx, data_in);
    if (rc != CRYPTO_SUCCESS) {
        tloge("sm3 update failed");
        TEE_Free((void *)(uintptr_t)(ctx.ctx_buffer));
        return rc;
    }
    rc = sm3_digest_dofinal(&ctx, data_out);
    if (rc != CRYPTO_SUCCESS)
        tloge("sm3 dofinal failed");

    return rc;
}

int32_t crypto_sm3_hmac(const struct symmerit_key_t *key, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (key == NULL || data_in == NULL || data_out == NULL);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    struct ctx_handle_t ctx = {0};

    int32_t rc = sm3_mac_init(&ctx, key);
    if (rc != CRYPTO_SUCCESS) {
        tloge("sm3 hmac init failed");
        return get_soft_crypto_error(CRYPTO_ERROR_SECURITY);
    }

    rc = sm3_mac_update(&ctx, data_in);
    if (rc != CRYPTO_SUCCESS) {
        tloge("sm3 hmac init failed");
        TEE_Free((void *)(uintptr_t)(ctx.ctx_buffer));
        return get_soft_crypto_error(CRYPTO_ERROR_SECURITY);
    }

    rc = sm3_mac_computefinal(&ctx, data_out);
    if (rc != CRYPTO_SUCCESS)
        tloge("sm3 hmac dofinal failed");

    return rc;
}
