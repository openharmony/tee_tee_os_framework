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

#include "soft_ae.h"
#include <securec.h>
#include <tee_log.h>
#include "soft_common_api.h"
#include "ae_common.h"
#include "soft_err.h"

static bool check_param_is_invalid(uint32_t alg_type, const struct symmerit_key_t *key,
    const struct ae_init_data *ae_init_param)
{
    bool check = (key == NULL || key->key_buffer == 0 || key->key_size == 0 ||
        (ae_init_param == NULL) || (ae_init_param->nonce == 0));
    if (check) {
        tloge("The input has null point");
        return true;
    }

    check = ((alg_type != CRYPTO_TYPE_AES_CCM) && (alg_type != CRYPTO_TYPE_AES_GCM) &&
             (alg_type != CRYPTO_TYPE_SM4_GCM));
    if (check) {
        tloge("Invalid AE algorithm, algorithm=0x%x", alg_type);
        return true;
    }

    return false;
}

static int32_t set_expected_tag(struct ctx_handle_t *ctx, void *tag, uint32_t tag_len)
{
    if (tag_len != ctx->tag_len) {
        tloge("The input tag length is not equal actual tag length, tag_len = 0x%x, crypto_hal_data->tag_len = 0x%x\n",
            tag_len, ctx->tag_len);
        return CRYPTO_BAD_PARAMETERS;
    }
    uint32_t tag_flag = ((ctx->alg_type == CRYPTO_TYPE_AES_CCM) ? EVP_CTRL_CCM_SET_TAG : EVP_CTRL_GCM_SET_TAG);
    int32_t rc = EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)(uintptr_t)(ctx->ctx_buffer), tag_flag, tag_len, tag);
    if (rc != BORINGSSL_OK) {
        tloge("Evp aes cipher update aad data failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    return CRYPTO_SUCCESS;
}

static int32_t set_ae_ccm_tag(struct ctx_handle_t *ae_ctx, EVP_CIPHER_CTX *ctx,
    const struct ae_init_data *ae_init_param)
{
    if (ae_ctx->alg_type != CRYPTO_TYPE_AES_CCM)
        return BORINGSSL_OK;

    if (ae_ctx->direction == ENC_MODE) {
        return EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, ae_init_param->tag_len, NULL);
    } else {
        uint8_t tag[AES_CCM_MAX_TAG_LEN] = { 0 };
        return EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, ae_init_param->tag_len, tag);
    }
}

static int32_t init_ae_info(struct ctx_handle_t *ae_ctx, EVP_CIPHER_CTX *ctx, const struct symmerit_key_t *key,
    const struct ae_init_data *ae_init_param, const EVP_CIPHER *cipher)
{
    int32_t ret;
    uint8_t aes_key[AES_MAX_KEY_SIZE] = { 0 };

    uint8_t *key_buffer = (uint8_t *)(uintptr_t)key->key_buffer;
    errno_t rc = memcpy_s(aes_key, AES_MAX_KEY_SIZE, key_buffer, key->key_size);
    if (rc != EOK) {
        tloge("Copy key failed");
        return CRYPTO_ERROR_SECURITY;
    }
    uint32_t enc_mode = ((ae_ctx->direction == TEE_MODE_ENCRYPT) ? AES_MODE_ENCRYPT : AES_MODE_DECRYPT);
    ret = EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc_mode);
    if (ret != BORINGSSL_OK) {
        (void)memset_s(aes_key, AES_MAX_KEY_SIZE, 0x0, AES_MAX_KEY_SIZE);
        tloge("Evp ae cipher init failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    uint32_t iv_flag = ((ae_ctx->alg_type == CRYPTO_TYPE_AES_CCM) ? EVP_CTRL_CCM_SET_IVLEN : EVP_CTRL_GCM_SET_IVLEN);
    ret = EVP_CIPHER_CTX_ctrl(ctx, iv_flag, ae_init_param->nonce_len, NULL);
    if (ret != BORINGSSL_OK) {
        tloge("ae set nounce failed\n");
        (void)memset_s(aes_key, AES_MAX_KEY_SIZE, 0x0, AES_MAX_KEY_SIZE);
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    /* Only the ccm algorithm should been set tag len */
    ret = set_ae_ccm_tag(ae_ctx, ctx, ae_init_param);
    if (ret != BORINGSSL_OK) {
        tloge("ae set tag failed\n");
        (void)memset_s(aes_key, AES_MAX_KEY_SIZE, 0x0, AES_MAX_KEY_SIZE);
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }

    ret = EVP_CipherInit_ex(ctx, NULL, NULL, aes_key, (uint8_t *)(uintptr_t)(ae_init_param->nonce), -1);
    (void)memset_s(aes_key, AES_MAX_KEY_SIZE, 0x0, AES_MAX_KEY_SIZE);
    if (ret != BORINGSSL_OK) {
        tloge("ae init failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    int32_t out_len = 0;
    if (ae_ctx->alg_type == CRYPTO_TYPE_AES_CCM) {
        ret = EVP_CipherUpdate(ctx, NULL, &out_len, NULL, ae_init_param->payload_len);
        if (ret != BORINGSSL_OK) {
            tloge("Evp ae cipher update failed\n");
            return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        }
    }

    return CRYPTO_SUCCESS;
}

static int32_t soft_ae_crypto_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    bool check = (data_in->size > INT32_MAX || data_out->size > INT32_MAX);
    if (check) {
        tloge("data size is too long\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t dest_len_temp = 0;
    int32_t final_len = 0;

    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;

    EVP_CIPHER_CTX *ae_ctx = (EVP_CIPHER_CTX *)(uintptr_t)(ctx->ctx_buffer);
    int32_t rc;
    check = (in_buffer != NULL && data_in->size != 0);
    if (check) {
        dest_len_temp = (int32_t)(data_out->size);
        rc = EVP_CipherUpdate(ae_ctx, out_buffer, &dest_len_temp,
            in_buffer, (int32_t)(data_in->size));
        if (rc != BORINGSSL_OK) {
            tloge("Evp ae cipher update data failed\n");
            return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        }
    }
    if (ctx->alg_type == CRYPTO_TYPE_AES_GCM || ctx->alg_type == CRYPTO_TYPE_SM4_GCM) {
        final_len = (int32_t)(data_out->size) - dest_len_temp;
        rc = EVP_CipherFinal_ex(ae_ctx, out_buffer + dest_len_temp, &final_len);
        if (rc != BORINGSSL_OK) {
            tloge("Evp ae cipher final data failed\n");
            return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
        }
    }
    if (dest_len_temp + final_len < 0) {
        tloge("Evp ae cipher final data failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    data_out->size = (uint32_t)(dest_len_temp + final_len);
    return CRYPTO_SUCCESS;
}

static int32_t ae_final_chek_param(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    const struct memref_t *tag, struct memref_t *data_out)
{
    bool check = (ctx == NULL || ctx->ctx_buffer == 0);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    check = (data_in == NULL || data_out == NULL || data_out->buffer == 0 || tag == NULL || tag->buffer == 0);
    if (check) {
        tloge("bad params");
        free_cipher_context(&(ctx->ctx_buffer));
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_ae_dec_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    const struct memref_t *tag_in, struct memref_t *data_out)
{
    if (ae_final_chek_param(ctx, data_in, tag_in, data_out) != CRYPTO_SUCCESS)
        return CRYPTO_BAD_PARAMETERS;

    int32_t ret = set_expected_tag(ctx, (uint8_t *)(uintptr_t)(tag_in->buffer), tag_in->size);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Evp ae set expected tag data failed");
        free_cipher_context(&(ctx->ctx_buffer));
        return ret;
    }

    ret = soft_ae_crypto_final(ctx, data_in, data_out);
    free_cipher_context(&(ctx->ctx_buffer));
    if (ret != CRYPTO_SUCCESS)
        tloge("Evp ae crypto final data failed\n");
    return ret;
}

int32_t soft_crypto_ae_enc_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out, struct memref_t *tag_out)
{
    if (ae_final_chek_param(ctx, data_in, tag_out, data_out) != CRYPTO_SUCCESS)
        return CRYPTO_BAD_PARAMETERS;

    uint32_t actual_tag_len = ctx->tag_len;
    if (tag_out->size < actual_tag_len) {
        tloge("The input tag buffer length is too small\n");
        free_cipher_context(&(ctx->ctx_buffer));
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t rc = soft_ae_crypto_final(ctx, data_in, data_out);
    if (rc != CRYPTO_SUCCESS) {
        tloge("do ae enc final failed, ret = %d", rc);
        free_cipher_context(&(ctx->ctx_buffer));
        return rc;
    }

    uint32_t tag_flag = ((ctx->alg_type == CRYPTO_TYPE_AES_CCM) ? EVP_CTRL_CCM_GET_TAG : EVP_CTRL_GCM_GET_TAG);
    rc = EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)(uintptr_t)(ctx->ctx_buffer), tag_flag,
        actual_tag_len, (uint8_t *)(uintptr_t)(tag_out->buffer));
    free_cipher_context(&(ctx->ctx_buffer));
    if (rc != BORINGSSL_OK) {
        tloge("Evp ae get tag data failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    tag_out->size = actual_tag_len;

    return TEE_SUCCESS;
}

static evp_cipher_func get_ae_cipher(uint32_t alg_type, uint32_t key_size)
{
    for (uint32_t i = 0; i < ARRAY_NUM(g_aes_des_init_oeration); i++) {
        if (g_aes_des_init_oeration[i].algorithm == alg_type &&
            g_aes_des_init_oeration[i].key_size == key_size)
            return g_aes_des_init_oeration[i].aes_cipher;
    }
    return NULL;
}

int32_t soft_crypto_ae_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key,
    const struct ae_init_data *ae_init_param)
{
    if (ctx == NULL)
        return CRYPTO_BAD_PARAMETERS;

    if (check_param_is_invalid(ctx->alg_type, key, ae_init_param)) {
        tloge("The input param is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }
    evp_cipher_func aes_cipher = get_ae_cipher(ctx->alg_type, key->key_size);
    if (aes_cipher == NULL) {
        tloge("Get ae cipher func failed");
        return CRYPTO_BAD_PARAMETERS;
    }

    EVP_CIPHER_CTX *ae_ctx = EVP_CIPHER_CTX_new();
    if (ae_ctx == NULL) {
        tloge("New ae ctx failed");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t ret = init_ae_info(ctx, ae_ctx, key, ae_init_param, aes_cipher());
    if (ret != CRYPTO_SUCCESS) {
        tloge("Evp ae init failed\n");
        EVP_CIPHER_CTX_free(ae_ctx);
        return ret;
    }

    ctx->ctx_buffer = (uint64_t)(uintptr_t)ae_ctx;
    ctx->tag_len = ae_init_param->tag_len;
    ctx->free_context = free_cipher_context;

    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_ae_update_aad(struct ctx_handle_t *ctx, const struct memref_t *aad_data)
{
    bool check = (ctx == NULL || aad_data == NULL || ctx->ctx_buffer == 0 ||
        aad_data->buffer == 0 || aad_data->size == 0 || aad_data->size > INT32_MAX);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    int32_t out_len = 0;
    EVP_CIPHER_CTX *ae_ctx = (EVP_CIPHER_CTX *)(uintptr_t)(ctx->ctx_buffer);
    int32_t rc = EVP_CipherUpdate(ae_ctx, NULL, &out_len, (uint8_t *)(uintptr_t)(aad_data->buffer),
        (int32_t)(aad_data->size));
    if (rc != BORINGSSL_OK) {
        tloge("Evp aes cipher update aad data failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_ae_update(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (ctx != NULL && ctx->alg_type == CRYPTO_TYPE_AES_CCM);
    if (check)
        return CRYPTO_NOT_SUPPORTED;
    check = (ctx == NULL || ctx->ctx_buffer == 0 || data_in == NULL || data_out == NULL ||
        data_in->buffer == 0 || data_out->buffer == 0);
    if (check) {
        tloge("bad params");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;

    if (data_out->size > INT32_MAX)
        return CRYPTO_BAD_PARAMETERS;

    int32_t dest_len_temp = (int32_t)(data_out->size);

    int32_t rc = EVP_CipherUpdate((EVP_CIPHER_CTX *)(uintptr_t)(ctx->ctx_buffer), out_buffer, &dest_len_temp,
        in_buffer, (int32_t)data_in->size);
    check = (rc != BORINGSSL_OK || dest_len_temp < 0);
    if (check) {
        tloge("Evp aes cipher update aad data failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS);
    }
    data_out->size = (uint32_t)dest_len_temp;
    return CRYPTO_SUCCESS;
}
