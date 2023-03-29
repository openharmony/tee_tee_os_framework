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

#include "crypto_hal_ae.h"
#include <securec.h>
#include <tee_log.h>
#include <tee_crypto_hal.h>
#include "crypto_manager.h"
#include "soft_ae.h"
#include "crypto_hal.h"

static struct crypto_cache_t *alloc_crypto_cache(uint32_t alg_type, const struct ae_init_data *ae_init_param)
{
    uint32_t total_buff_len = 0;

    if (alg_type == CRYPTO_TYPE_AES_CCM)
        total_buff_len = ae_init_param->payload_len;
    else if (alg_type == CRYPTO_TYPE_AES_GCM || alg_type == CRYPTO_TYPE_SM4_GCM)
        total_buff_len = ((ae_init_param->payload_len > 0) && (ae_init_param->payload_len < MAX_CRYPTO_DATA_LEN)) ?
            ae_init_param->payload_len : MAX_CRYPTO_DATA_LEN;
    else
        return NULL;

    if (total_buff_len > MAX_CRYPTO_DATA_LEN) {
        tloge("Payload len is too large, total_buff_len=0x%x\n", total_buff_len);
        return NULL;
    }
    struct crypto_cache_t *crypto_cache = TEE_Malloc(sizeof(*crypto_cache), 0);
    if (crypto_cache == NULL) {
        tloge("Malloc cache buffer failed\n");
        return NULL;
    }
    crypto_cache->total_len = total_buff_len;
    crypto_cache->effective_len = 0;
    crypto_cache->buffer = TEE_Malloc(total_buff_len, 0);
    if (crypto_cache->buffer == NULL) {
        tloge("Malloc cache buffer failed\n");
        TEE_Free(crypto_cache);
        return NULL;
    }

    return crypto_cache;
}

struct ctx_handle_t *tee_crypto_ae_init(uint32_t alg_type, uint32_t direction, const struct symmerit_key_t *key,
    const struct ae_init_data *ae_init_param, uint32_t engine)
{
    bool check = (key == NULL || ae_init_param == NULL);
    if (check) {
        tloge("Invalid params\n");
        return NULL;
    }

    check = ((alg_type == CRYPTO_TYPE_AES_CCM) &&
        ((ae_init_param->payload_len == 0) || (ae_init_param->payload_len > MAX_CRYPTO_DATA_LEN)));
    if (check) {
        tloge("Invalid payload len, payload_len=0x%x\n", ae_init_param->payload_len);
        return NULL;
    }

    struct ctx_handle_t *ctx = alloc_ctx_handle(alg_type, engine);
    if (ctx == NULL) {
        tloge("Malloc ctx handle failed\n");
        return NULL;
    }
    ctx->direction = direction;
    if (alg_type == CRYPTO_TYPE_AES_CCM)
        ctx->aad_size = ae_init_param->aad_len;

    int32_t ret;

    if (engine == SOFT_CRYPTO)
        ret = soft_crypto_ae_init(ctx, key, ae_init_param);
    else
        ret = crypto_driver_ae_init(ctx, key, ae_init_param);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Ae init failed, ret=%d\n", ret);
        tee_crypto_ctx_free(ctx);
        return NULL;
    }

    ctx->is_support_ae_update = true;
    struct crypto_cache_t *ctx_cache_buffer = alloc_crypto_cache(alg_type, ae_init_param);
    if (ctx_cache_buffer == NULL) {
        tloge("Alloc crypto cache failed\n");
        tee_crypto_ctx_free(ctx);
        return NULL;
    }
    ctx->cache_buffer = (uint64_t)(uintptr_t)ctx_cache_buffer;

    return ctx;
}

int32_t tee_crypto_ae_update_aad(struct ctx_handle_t *ctx, const struct memref_t *aad_data)
{
    bool check = ((ctx == NULL) || (aad_data == NULL));
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if ((ctx->alg_type == CRYPTO_TYPE_AES_CCM) && (ctx->aad_size < aad_data->size)) {
        tloge("The AADLen size is bigger than AEInit\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (ctx->engine == SOFT_CRYPTO)
        return soft_crypto_ae_update_aad(ctx, aad_data);
    return crypto_driver_ae_update_aad(ctx, aad_data);
}

static int32_t check_ae_in_size(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    struct crypto_cache_t *cache = (struct crypto_cache_t *)(uintptr_t)(ctx->cache_buffer);
    bool check = ((cache == NULL) || (data_in->size > cache->total_len));
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    check = ((cache->effective_len > UINT32_MAX - data_in->size) ||
        (cache->effective_len + data_in->size > cache->total_len));
    if (check) {
        tloge("The src len is invalid, effective_len=0x%x, src_len=0x%x\n",
            cache->effective_len, data_in->size);
        return CRYPTO_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static int32_t do_crypto_cache(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    int32_t ret = check_ae_in_size(ctx, data_in);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    if (data_in->size == 0)
        return TEE_SUCCESS;

    struct crypto_cache_t *cache = (struct crypto_cache_t *)(uintptr_t)(ctx->cache_buffer);

    uint32_t avaliable_cache_len = cache->total_len - cache->effective_len;
    errno_t rc = memcpy_s((void *)((uintptr_t)cache->buffer + cache->effective_len), avaliable_cache_len,
        (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size);
    if (rc != EOK) {
        tloge("Copy ae data to cache failed");
        return TEE_ERROR_SECURITY;
    }

    cache->effective_len += data_in->size;
    data_out->size = 0;
    return CRYPTO_SUCCESS;
}

int32_t tee_crypto_ae_update(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = ((ctx == NULL) || (ctx->cache_buffer == 0) || (data_in == NULL) || (data_out == NULL));
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (data_in->size == 0)
        return CRYPTO_SUCCESS;

    int32_t ret;
    if (ctx->engine == SOFT_CRYPTO)
        ret = soft_crypto_ae_update(ctx, data_in, data_out);
    else
        ret = crypto_driver_ae_update(ctx, data_in, data_out);

    if (ret == CRYPTO_NOT_SUPPORTED) {
        ctx->is_support_ae_update = false;
        tlogd("this algorithm not support update!");
        ret = do_crypto_cache(ctx, data_in, data_out);
    }
    if (ret != CRYPTO_SUCCESS) {
        tloge("do ae update failed, ret = %d", ret);
        return ret;
    }
    return ret;
}

static int32_t do_ae_final_not_support_update(struct ctx_handle_t *ctx,
    const struct memref_t *data_in, struct memref_t *data_out,
    const struct memref_t *tag_in, struct memref_t *tag_out)
{
    uint32_t dest_size = data_out->size;
    int32_t ret = do_crypto_cache(ctx, data_in, data_out);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Do crypto cache failed, ret=%d\n", ret);
        return ret;
    }
    data_out->size = dest_size;
    struct crypto_cache_t *cache = (struct crypto_cache_t *)(uintptr_t)(ctx->cache_buffer);
    if (cache == NULL) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    struct memref_t new_data_in = {0};
    new_data_in.buffer = (uint64_t)(uintptr_t)(cache->buffer);
    new_data_in.size = cache->effective_len;

    if (ctx->engine == SOFT_CRYPTO) {
        if (ctx->direction == ENC_MODE)
            return soft_crypto_ae_enc_final(ctx, (const struct memref_t *)&new_data_in, data_out, tag_out);
        else
            return soft_crypto_ae_dec_final(ctx, (const struct memref_t *)&new_data_in, tag_in, data_out);
    } else {
        if (ctx->direction == ENC_MODE)
            return crypto_driver_ae_enc_final(ctx, (const struct memref_t *)&new_data_in, data_out, tag_out);
        else
            return crypto_driver_ae_dec_final(ctx, (const struct memref_t *)&new_data_in, tag_in, data_out);
    }
}

int32_t tee_crypto_ae_enc_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out, struct memref_t *tag_out)
{
    bool check = ((ctx == NULL) || (data_in == NULL) || (data_out == NULL) || (tag_out == NULL));
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (ctx->is_support_ae_update) {
        if (ctx->engine == SOFT_CRYPTO)
            return soft_crypto_ae_enc_final(ctx, data_in, data_out, tag_out);
        else
            return crypto_driver_ae_enc_final(ctx, data_in, data_out, tag_out);
    } else {
        return do_ae_final_not_support_update(ctx, data_in, data_out, NULL, tag_out);
    }
}

int32_t tee_crypto_ae_dec_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    const struct memref_t *tag_in, struct memref_t *data_out)
{
    bool check = ((ctx == NULL) || (data_in == NULL) || (tag_in == NULL) || (data_out == NULL));
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (ctx->is_support_ae_update) {
        if (ctx->engine == SOFT_CRYPTO)
            return soft_crypto_ae_dec_final(ctx, data_in, tag_in, data_out);
        else
            return crypto_driver_ae_dec_final(ctx, data_in, tag_in, data_out);
    } else {
        return do_ae_final_not_support_update(ctx, data_in, data_out, tag_in, NULL);
    }
}
