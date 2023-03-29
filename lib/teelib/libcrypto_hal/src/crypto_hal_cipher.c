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

#include "crypto_hal_cipher.h"
#include <securec.h>
#include <tee_log.h>
#include <tee_crypto_hal.h>
#include <tee_property_inner.h>
#include "crypto_manager.h"
#include "crypto_hal.h"
#include "soft_cipher.h"

struct ctx_handle_t *tee_crypto_cipher_init(uint32_t alg_type, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv, uint32_t engine)
{
    if (key == NULL) {
        tloge("Invalid params\n");
        return NULL;
    }

    struct ctx_handle_t *ctx = alloc_ctx_handle(alg_type, engine);
    if (ctx == NULL) {
        tloge("Malloc ctx handle failed\n");
        return NULL;
    }
    ctx->direction = direction;

    int32_t ret;
    if (engine == SOFT_CRYPTO)
        ret = soft_crypto_cipher_init(ctx, key, iv);
    else
        ret = crypto_driver_cipher_init(ctx, key, iv);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Cipher init failed, ret=%d\n", ret);
        tee_crypto_ctx_free(ctx);
        return NULL;
    }

    return ctx;
}

static int32_t adapt_cipher_dest_data(const struct memref_t *data_in, struct memref_t *data_out, bool *malloc_flag)
{
    if (data_out->buffer != 0)
        return CRYPTO_SUCCESS;

    if (data_in->size == 0) {
        tloge("Invalid data size\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    data_out->buffer = (uint64_t)(uintptr_t)TEE_Malloc(data_in->size, 0);
    if (data_out->buffer == 0) {
        tloge("Malloc memory failed\n");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    data_out->size = data_in->size;
    *malloc_flag = true;

    return CRYPTO_SUCCESS;
}

static int32_t rebuild_cipher_input_data(struct ctx_handle_t *ctx,
    const struct memref_t *data_in, struct memref_t *new_data_in, uint32_t cache_len)
{
    errno_t rc;

    if (ctx->cipher_cache_len != 0) {
        rc = memcpy_s((uint8_t *)(uintptr_t)(new_data_in->buffer), new_data_in->size,
            ctx->cipher_cache_data, ctx->cipher_cache_len);
        if (rc != EOK) {
            tloge("memory copy failed, rc=0x%x\n", rc);
            return CRYPTO_ERROR_SECURITY;
        }
    }

    if (new_data_in->size > ctx->cipher_cache_len) {
        rc = memcpy_s((uint8_t *)(uintptr_t)(new_data_in->buffer) + ctx->cipher_cache_len,
            new_data_in->size - ctx->cipher_cache_len,
            (void *)(uintptr_t)data_in->buffer, new_data_in->size - ctx->cipher_cache_len);
        if (rc != EOK) {
            tloge("memory copy failed, rc=0x%x\n", rc);
            return CRYPTO_ERROR_SECURITY;
        }
    }

    ctx->cipher_cache_len = cache_len;
    if (cache_len == 0) {
        (void)memset_s(ctx->cipher_cache_data, sizeof(ctx->cipher_cache_data), 0, sizeof(ctx->cipher_cache_data));
        return CRYPTO_SUCCESS;
    }

    rc = memcpy_s(ctx->cipher_cache_data, CIPHER_CACHE_LEN,
        ((uint8_t *)(uintptr_t)data_in->buffer) + data_in->size - cache_len, cache_len);
    if (rc != EOK) {
        tloge("memory copy failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }

    return CRYPTO_SUCCESS;
}

static int32_t do_cipher_cache_update(struct ctx_handle_t *ctx,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    struct memref_t new_data_in = {0};
    uint32_t total_len = data_in->size + ctx->cipher_cache_len;
    uint32_t cache_len = (total_len % CIPHER_CACHE_LEN == 0) ? CIPHER_CACHE_LEN : (total_len % CIPHER_CACHE_LEN);
    uint32_t input_len = (total_len < cache_len) ? 0 : (total_len - cache_len);

    uint8_t *input_buf = TEE_Malloc(input_len, 0);
    if (input_buf == NULL) {
        tloge("Malloc memory failed\n");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    new_data_in.buffer = (uint64_t)(uintptr_t)input_buf;
    new_data_in.size = input_len;

    int32_t ret = rebuild_cipher_input_data(ctx, data_in, &new_data_in, cache_len);
    if (ret != EOK) {
        tloge("Rebuild cipher input data failed, ret=0x%x\n", ret);
        (void)memset_s(input_buf, input_len, 0, input_len);
        TEE_Free(input_buf);
        input_buf = NULL;
        new_data_in.buffer = 0;
        return ret;
    }

    ret = crypto_driver_cipher_update(ctx, (const struct memref_t *)&new_data_in, data_out);
    (void)memset_s(input_buf, input_len, 0, input_len);
    TEE_Free(input_buf);
    input_buf = NULL;
    new_data_in.buffer = 0;
    return ret;
}

static int32_t do_crypto_cipher_update(struct ctx_handle_t *ctx,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    if (data_in->size == 0)
        return CRYPTO_SUCCESS;

    if (data_in->size > MAX_CRYPTO_DATA_LEN) {
        tloge("Input data is too large\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    /* For XTS all the input data units must be of the same size */
    if ((tee_get_ta_api_level() == API_LEVEL1_0) || (ctx->alg_type == CRYPTO_TYPE_AES_XTS))
        return crypto_driver_cipher_update(ctx, data_in, data_out);

    if ((data_in->size + ctx->cipher_cache_len) > CIPHER_CACHE_LEN)
        return do_cipher_cache_update(ctx, data_in, data_out);

    errno_t rc = memcpy_s(ctx->cipher_cache_data + ctx->cipher_cache_len,
        CIPHER_CACHE_LEN - ctx->cipher_cache_len, (void *)(uintptr_t)data_in->buffer, data_in->size);
    if (rc != EOK) {
        tloge("memory copy failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }
    ctx->cipher_cache_len += data_in->size;
    data_out->size = 0;

    return CRYPTO_SUCCESS;
}

int32_t tee_crypto_cipher_update(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = ((ctx == NULL) || (data_in == NULL) || (data_out == NULL));
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (ctx->engine == SOFT_CRYPTO)
        return soft_crypto_cipher_update(ctx, data_in, data_out);

    bool malloc_flag = false;
    int32_t ret = adapt_cipher_dest_data(data_in, data_out, &malloc_flag);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Adapt cipher dest data failed\n");
        return ret;
    }

    if ((ctx->driver_ability & DRIVER_CACHE) == DRIVER_CACHE)
        ret = crypto_driver_cipher_update(ctx, data_in, data_out);
    else
        ret = do_crypto_cipher_update(ctx, data_in, data_out);

    if (malloc_flag) {
        (void)memset_s((void *)(uintptr_t)(data_out->buffer), data_out->size, 0, data_out->size);
        TEE_Free((void *)(uintptr_t)(data_out->buffer));
        data_out->buffer = 0;
    }

    return ret;
}

static int32_t build_padding_data_in(struct memref_t *padding_data_in, const struct memref_t *data_in,
    const struct memref_t *data_out)
{
    if (data_in->size > MAX_CRYPTO_DATA_LEN - CRYPTO_PADDING_LEN) {
        tloge("srcLen is too large! srcLen = 0x%x\n", data_in->size);
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t padding_num = CRYPTO_PADDING_LEN - (data_in->size % CRYPTO_PADDING_LEN);
    padding_data_in->size = data_in->size + padding_num;
    if (data_out->size < padding_data_in->size) {
        tloge("out len is not large enough!insize = 0x%x, outsize = 0x%x", padding_data_in->size, data_out->size);
        return CRYPTO_SHORT_BUFFER;
    }

    uint8_t *padding_data_in_buffer = TEE_Malloc(padding_data_in->size, 0);
    if (padding_data_in_buffer == NULL) {
        tloge("Malloc memory failed\n");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    (void)memset_s(padding_data_in_buffer, padding_data_in->size, (int)padding_num, padding_data_in->size);
    if (data_in->buffer != 0) {
        errno_t rc = memcpy_s(padding_data_in_buffer, padding_data_in->size,
            (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size);
        if (rc != EOK) {
            tloge("Copy data buffer failed\n");
            TEE_Free(padding_data_in_buffer);
            return CRYPTO_ERROR_SECURITY;
        }
    }
    padding_data_in->buffer = (uint64_t)(uintptr_t)padding_data_in_buffer;
    return CRYPTO_SUCCESS;
}

static int32_t do_padding_enc(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    struct memref_t padding_data_in = {0};
    int32_t ret = build_padding_data_in(&padding_data_in, data_in, data_out);
    if (ret != CRYPTO_SUCCESS) {
        tloge(" build data in failed!\n");
        return ret;
    }

    ret = crypto_driver_cipher_dofinal(ctx, (const struct memref_t *)&padding_data_in, data_out);
    TEE_Free((void *)(uintptr_t)padding_data_in.buffer);
    padding_data_in.buffer = 0;
    if (ret != CRYPTO_SUCCESS) {
        tloge("Cipher dofinal failed\n");
        return ret;
    }

    return CRYPTO_SUCCESS;
}

static int32_t check_padding_valid(struct memref_t *padding_data_out)
{
    if (padding_data_out->size == 0) {
        tloge("Invalid data size\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t padding_num = ((uint8_t *)(uintptr_t)(padding_data_out->buffer))[padding_data_out->size - 1];
    bool check = ((padding_num <= 0) || (padding_num > CRYPTO_PADDING_LEN) || (padding_data_out->size < padding_num));
    if (check) {
        tloge("Invalid padding, padding num=0x%x\n", padding_num);
        return CRYPTO_BAD_FORMAT;
    }
    for (uint32_t i = 0; i < padding_num; i++) {
        if (((uint8_t *)(uintptr_t)(padding_data_out->buffer))[padding_data_out->size - 1 - i] != padding_num) {
            tloge("Invalid padding\n");
            return CRYPTO_BAD_FORMAT;
        }
    }

    return CRYPTO_SUCCESS;
}

static int32_t check_and_copy_data_out(struct memref_t *padding_data_out, const uint8_t *padding_data_out_buffer,
    struct memref_t *data_out)
{
    int32_t ret = check_padding_valid(padding_data_out);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Padding is invalid\n");
        return ret;
    }

    padding_data_out->size = padding_data_out->size - (padding_data_out_buffer)[padding_data_out->size - 1];
    if (data_out->size < padding_data_out->size) {
        tloge("The out buf size is too short\n");
        return CRYPTO_SHORT_BUFFER;
    }
    errno_t rc = memcpy_s((uint8_t *)(uintptr_t)(data_out->buffer), data_out->size,
        padding_data_out_buffer, padding_data_out->size);
    if (rc != EOK) {
        tloge("Copy data buffer failed\n");
        return CRYPTO_ERROR_SECURITY;
    }

    data_out->size = padding_data_out->size;
    return CRYPTO_SUCCESS;
}

static int32_t do_padding_dec(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = ((data_in->size == 0) || (data_in->size > MAX_CRYPTO_DATA_LEN) || data_in->size < CRYPTO_PADDING_LEN ||
        (data_in->buffer == 0) || (data_out->buffer == 0) ||
        (data_out->size == 0) || (data_out->size > MAX_CRYPTO_DATA_LEN));
    if (check) {
        tloge("Input params invalid\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct memref_t padding_data_out = {0};
    padding_data_out.size = data_out->size;
    uint8_t *padding_data_out_buffer = TEE_Malloc(data_out->size, 0);
    if (padding_data_out_buffer == NULL) {
        tloge("Memory malloc failed\n");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    padding_data_out.buffer = (uint64_t)(uintptr_t)padding_data_out_buffer;

    int32_t ret = crypto_driver_cipher_dofinal(ctx, data_in, &padding_data_out);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Cipher dofinal failed\n");
        TEE_Free(padding_data_out_buffer);
        return ret;
    }

    ret = check_and_copy_data_out(&padding_data_out, padding_data_out_buffer, data_out);
    if (ret != CRYPTO_SUCCESS)
        tloge("check data out failed!\n");

    TEE_Free(padding_data_out_buffer);
    return ret;
}

static int32_t do_padding_cipher(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    if ((ctx->direction == ENC_MODE) || (ctx->alg_type == CRYPTO_TYPE_AES_CBC_MAC_PKCS5))
        return do_padding_enc(ctx, data_in, data_out);
    else
        return do_padding_dec(ctx, data_in, data_out);
}

static int32_t proc_not_soft_cipher_dofinal(struct ctx_handle_t *ctx,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = ((ctx->engine != SOFT_CRYPTO) &&
        ((ctx->alg_type == CRYPTO_TYPE_AES_ECB_PKCS5) || (ctx->alg_type == CRYPTO_TYPE_AES_CBC_PKCS5) ||
         (ctx->alg_type == CRYPTO_TYPE_AES_CBC_MAC_PKCS5)));
    if (check)
        return do_padding_cipher(ctx, data_in, data_out);
    else
        return crypto_driver_cipher_dofinal(ctx, data_in, data_out);
}

static int32_t do_cipher_cache_dofinal(struct ctx_handle_t *ctx,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    struct memref_t new_data_in = {0};

    if (data_in->size > MAX_CRYPTO_DATA_LEN) {
        tloge("Input data is too large\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    /* For XTS all the input data units must be of the same size */
    if ((tee_get_ta_api_level() == API_LEVEL1_0) || (ctx->alg_type == CRYPTO_TYPE_AES_XTS))
        return proc_not_soft_cipher_dofinal(ctx, data_in, data_out);

    if ((data_in->size + ctx->cipher_cache_len) == 0)
        return CRYPTO_SUCCESS;

    uint8_t *input_buf = TEE_Malloc(data_in->size + ctx->cipher_cache_len, 0);
    if (input_buf == NULL) {
        tloge("Malloc memory failed\n");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    new_data_in.buffer = (uint64_t)(uintptr_t)input_buf;
    new_data_in.size = data_in->size + ctx->cipher_cache_len;

    int32_t ret = rebuild_cipher_input_data(ctx, data_in, &new_data_in, 0);
    if (ret != EOK) {
        tloge("Rebuild cipher input data failed, ret=0x%x\n", ret);
        (void)memset_s(input_buf, data_in->size + ctx->cipher_cache_len, 0, data_in->size + ctx->cipher_cache_len);
        TEE_Free(input_buf);
        new_data_in.buffer = 0;
        return ret;
    }
    ctx->cipher_cache_len = 0;
    (void)memset_s(ctx->cipher_cache_data, sizeof(ctx->cipher_cache_data), 0, sizeof(ctx->cipher_cache_data));

    ret = proc_not_soft_cipher_dofinal(ctx, (const struct memref_t *)&new_data_in, data_out);
    (void)memset_s(input_buf, data_in->size + ctx->cipher_cache_len, 0, data_in->size + ctx->cipher_cache_len);
    TEE_Free(input_buf);
    new_data_in.buffer = 0;

    return ret;
}

int32_t tee_crypto_cipher_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = ((ctx == NULL) || (data_in == NULL) || (data_out == NULL));
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (ctx->engine == SOFT_CRYPTO)
        return soft_crypto_cipher_dofinal(ctx, data_in, data_out);
    else if ((ctx->driver_ability & DRIVER_CACHE) == DRIVER_CACHE)
        return crypto_driver_cipher_dofinal(ctx, data_in, data_out);
    else
        return do_cipher_cache_dofinal(ctx, data_in, data_out);
}

struct once_crypto_param {
    uint32_t alg_type;
    uint32_t direction;
    uint32_t engine;
};

static int32_t do_once_padding_enc(const struct once_crypto_param *base_param, const struct symmerit_key_t *key,
    const struct memref_t *iv, const struct memref_t *data_in, struct memref_t *data_out)
{
    struct memref_t padding_data_in = {0};
    int32_t ret = build_padding_data_in(&padding_data_in, data_in, data_out);
    if (ret != CRYPTO_SUCCESS) {
        tloge(" build data in failed!\n");
        return ret;
    }

    ret = crypto_driver_cipher(base_param->alg_type, base_param->direction, key, iv,
        (const struct memref_t *)&padding_data_in, data_out, base_param->engine);
    TEE_Free((void *)(uintptr_t)padding_data_in.buffer);
    padding_data_in.buffer = 0;
    if (ret != CRYPTO_SUCCESS) {
        tloge("Do once padding enc failed\n");
        return ret;
    }

    return CRYPTO_SUCCESS;
}

static int32_t do_once_padding_dec(const struct once_crypto_param *base_param, const struct symmerit_key_t *key,
    const struct memref_t *iv, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (data_in->size == 0 || data_in->size > MAX_CRYPTO_DATA_LEN || data_in->size < CRYPTO_PADDING_LEN ||
        data_in->buffer == 0 || data_out->buffer == 0 || data_out->size == 0 || data_out->size > MAX_CRYPTO_DATA_LEN);
    if (check) {
        tloge("Invalid input params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct memref_t padding_data_out = {0};
    padding_data_out.size = data_out->size;
    uint8_t *padding_data_out_buffer = TEE_Malloc(data_out->size, 0);
    if (padding_data_out_buffer == NULL) {
        tloge("Malloc memory failed\n");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    padding_data_out.buffer = (uint64_t)(uintptr_t)padding_data_out_buffer;
    int32_t ret = crypto_driver_cipher(base_param->alg_type, base_param->direction, key, iv,
        data_in, &padding_data_out, base_param->engine);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Do once padding dec failed\n");
        TEE_Free(padding_data_out_buffer);
        return ret;
    }

    ret = check_and_copy_data_out(&padding_data_out, padding_data_out_buffer, data_out);
    if (ret != CRYPTO_SUCCESS)
        tloge("check data out failed!\n");

    TEE_Free(padding_data_out_buffer);
    return ret;
}

static int32_t do_once_padding_cipher(const struct once_crypto_param *base_param, const struct symmerit_key_t *key,
    const struct memref_t *iv, const struct memref_t *data_in, struct memref_t *data_out)
{
    if ((base_param->direction == ENC_MODE) || (base_param->alg_type == CRYPTO_TYPE_AES_CBC_MAC_PKCS5))
        return do_once_padding_enc(base_param, key, iv, data_in, data_out);
    else
        return do_once_padding_dec(base_param, key, iv, data_in, data_out);
}

int32_t tee_crypto_cipher(uint32_t alg_type, uint32_t direction, const struct symmerit_key_t *key,
    const struct memref_t *iv, const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine)
{
    bool check = ((key == NULL) || (data_in == NULL) || (data_out == NULL));
    if (check) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (engine == SOFT_CRYPTO)
        return soft_crypto_cipher(alg_type, direction, key, iv, data_in, data_out);

    struct once_crypto_param base_param = {0};
    base_param.alg_type = alg_type;
    base_param.direction = direction;
    base_param.engine = engine;
    check = ((engine != SOFT_CRYPTO) && ((alg_type == CRYPTO_TYPE_AES_ECB_PKCS5) ||
            (alg_type == CRYPTO_TYPE_AES_CBC_PKCS5) || (alg_type == CRYPTO_TYPE_AES_CBC_MAC_PKCS5)));
    if (check)
        return do_once_padding_cipher((const struct once_crypto_param *)&base_param, key, iv, data_in, data_out);
    else
        return crypto_driver_cipher(alg_type, direction, key, iv, data_in, data_out, engine);
}
