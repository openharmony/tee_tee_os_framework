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
#include "crypto_manager.h"
#include <stdio.h>
#include <securec.h>
#include <drv.h>
#include <mem_ops.h>
#include "tee_log.h"
#include "crypto_default_engine.h"
#include "tee_drv_client.h"
#include "crypto_mgr_syscall.h"
#include "tee_inner_uuid.h"
#include "tee_object_api.h"
#include "tee_mem_mgmt_api.h"
#include "crypto_mgr_syscall.h"
#include "crypto_hal.h"
#include "crypto_driver_adaptor_ops.h"
#include "tee_msg_type.h"

int64_t get_ctx_fd_handle(uint32_t alg_type, bool is_copy_ctx)
{
    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    if (is_copy_ctx)
        return tee_drv_open(drv_name, &alg_type, sizeof(alg_type));
    else
        return tee_drv_open(drv_name, &alg_type, sizeof(alg_type) + TYPE_DRV_OPEN);
}

int32_t driver_ctx_buffer_prepare(const struct ctx_handle_t *src_ctx, struct ctx_handle_t *dest_ctx)
{
    (void)src_ctx;
    if (dest_ctx == NULL)
        return CRYPTO_BAD_PARAMETERS;

    if (dest_ctx->fd > 0)
        tee_drv_close(dest_ctx->fd);

    dest_ctx->fd = get_ctx_fd_handle(dest_ctx->alg_type, true);
    if (dest_ctx->fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

struct ctx_handle_t *driver_alloc_ctx_handle(uint32_t alg_type, uint32_t engine, struct ctx_handle_t *ctx)
{
    (void)engine;
    if (ctx == NULL)
        return NULL;

    int64_t fd = get_ctx_fd_handle(alg_type, false);
    if (fd <= 0) {
        tloge("open fd failed\n");
        goto error;
    }
    ctx->driver_ability = crypto_driver_get_driver_ability(fd);
    ctx->fd = fd;
    return ctx;

error:
    if (fd > 0)
        tee_drv_close(fd);

    TEE_Free(ctx);
    return NULL;
}

static inline uint32_t get_share_mem_size(const struct drv_memref_t *fill_data, uint32_t fill_data_count)
{
    uint32_t share_mem_size = 0;

    for (uint32_t i = 0; i < fill_data_count; i++) {
        if (fill_data[i].size > SHARE_MEMORY_MAX_SIZE) {
            tloge("the %d fill data size is too big", i);
            return INVALID_MEMORY_SIZE;
        }

        share_mem_size += fill_data[i].size;
    }

    share_mem_size += fill_data_count * sizeof(uint32_t);
    return share_mem_size;
}

static int32_t copy_to_shared_buf(const void *buf, uint32_t buf_size, uint8_t **shared_buf, bool need_copy)
{
    if (buf_size != 0 && buf == NULL) {
        tloge("copy buf size is not 0 but copy buf is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (memcpy_s(*shared_buf, sizeof(uint32_t), (void *)&buf_size, sizeof(uint32_t)) != EOK) {
        tloge("copy buf size failed\n");
        return CRYPTO_ERROR_SECURITY;
    }

    *shared_buf += sizeof(uint32_t);

    if (buf_size == 0 || buf == NULL)
        return CRYPTO_SUCCESS;

    if (need_copy) {
        if (memcpy_s(*shared_buf, buf_size, buf, buf_size) != EOK) {
            tloge("copy buf failed\n");
            return CRYPTO_ERROR_SECURITY;
        }
    }
    *shared_buf += buf_size;
    return CRYPTO_SUCCESS;
}

static inline int32_t fill_share_mem(uint8_t *shared_buf, const struct drv_memref_t *fill_data,
    uint32_t fill_data_count)
{
    for (uint32_t i = 0; i < fill_data_count; i++) {
        int32_t ret = copy_to_shared_buf((void *)(uintptr_t)fill_data[i].buffer, fill_data[i].size,
            &shared_buf, fill_data[i].need_copy);
        if (ret != CRYPTO_SUCCESS) {
            tloge("fill share memory failed! fill data No. = %d\n", i);
            return ret;
        }
    }
    return CRYPTO_SUCCESS;
}

static int32_t prepare_ioctl_parameters(const struct drv_memref_t *data, uint32_t data_count,
    struct memref_t *share_mem, struct crypto_ioctl *ioctl_param, struct ctx_handle_t *ctx)
{
    TEE_UUID uuid = CRYPTOMGR;
    uint32_t size = get_share_mem_size(data, data_count);
    if (size > SHARE_MEMORY_MAX_SIZE) {
        tloge("share memory size is too long. size = %u\n", size);
        return CRYPTO_OVERFLOW;
    }

    if (ctx->ctx_size < size) {
        if (ctx->ctx_buffer != 0) {
            (void)memset_s((void *)(uintptr_t)ctx->ctx_buffer, ctx->ctx_size, 0, ctx->ctx_size);
            free_sharemem((void *)(uintptr_t)ctx->ctx_buffer, ctx->ctx_size);
        }

        share_mem->buffer = (uint64_t)(uintptr_t)alloc_sharemem_aux(&uuid, size);
        if (share_mem->buffer == 0) {
            tloge("alloc share memory failed\n");
            return CRYPTO_OVERFLOW;
        }
        ctx->ctx_size = size;
        ctx->ctx_buffer = share_mem->buffer;
    } else {
        share_mem->buffer = ctx->ctx_buffer;
    }

    int32_t ret = fill_share_mem((uint8_t *)(uintptr_t)share_mem->buffer, data, data_count);
    if (ret != CRYPTO_SUCCESS) {
        tloge("fill share memory failed. ret = %d\n", ret);
        goto error;
    }

    share_mem->size = size;
    ioctl_param->buf = share_mem->buffer;
    ioctl_param->buf_len = size;
    ioctl_param->total_nums = data_count;
    return ret;

error:
    (void)memset_s((void *)(uintptr_t)share_mem->buffer, size, 0, size);
    free_sharemem((void *)(uintptr_t)share_mem->buffer, size);
    ctx->ctx_size = 0;
    ctx->ctx_buffer = 0;
    share_mem->buffer = 0;
    return ret;
}

static int32_t copy_from_shared_buf(void *buf, uint32_t *buf_size, uint8_t **shared_buf)
{
    uint32_t original_size = *buf_size;

    if (memcpy_s(buf_size, sizeof(uint32_t), *shared_buf, sizeof(uint32_t)) != EOK) {
        tloge("copy buf size failed\n");
        return CRYPTO_ERROR_SECURITY;
    }

    if (*buf_size > original_size) {
        tloge("buf size is too big\n");
        return CRYPTO_OVERFLOW;
    }

    *shared_buf += sizeof(uint32_t);

    if (*buf_size == 0)
        return CRYPTO_SUCCESS;

    if (memcpy_s(buf, *buf_size, *shared_buf, *buf_size) != EOK) {
        tloge("copy buf failed\n");
        return CRYPTO_ERROR_SECURITY;
    }

    *shared_buf += *buf_size;
    return CRYPTO_SUCCESS;
}

static inline int32_t get_share_mem(uint8_t *shared_buf, struct drv_memref_t *get_data, uint32_t get_data_count)
{
    for (uint32_t i = 0; i < get_data_count; i++) {
        int32_t ret = copy_from_shared_buf((void *)(uintptr_t)get_data[i].buffer, &(get_data[i].size), &shared_buf);
        if (ret != CRYPTO_SUCCESS) {
            tloge("get share memory failed! get data No. = %d\n", i);
            return ret;
        }
    }
    return CRYPTO_SUCCESS;
}

uint32_t crypto_get_default_engine(uint32_t algorithm)
{
    uint32_t i;
    uint32_t count = sizeof(g_algorithm_engine) / sizeof(g_algorithm_engine[0]);
    for (i = 0; i < count; i++) {
        if (g_algorithm_engine[i].algorithm == algorithm)
            return g_algorithm_engine[i].engine;
    }
    return SOFT_CRYPTO;
}

uint32_t crypto_get_default_generate_key_engine(uint32_t algorithm)
{
    uint32_t i;
    uint32_t count = sizeof(g_generate_key_engine) / sizeof(g_generate_key_engine[0]);
    for (i = 0; i < count; i++) {
        if (g_generate_key_engine[i].algorithm == algorithm)
            return g_generate_key_engine[i].engine;
    }
    return SOFT_CRYPTO;
}

int32_t crypto_driver_get_driver_ability(int64_t fd)
{
    uint32_t args = 0;
    return tee_drv_ioctl(fd, IOCTRL_CRYPTO_GET_DRV_ABILITY, &args, sizeof(args));
}

int32_t crypto_driver_ctx_copy(const struct ctx_handle_t *src_ctx, struct ctx_handle_t *dest_ctx)
{
    if (dest_ctx == NULL || src_ctx == NULL) {
        tloge("dest_ctx is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t args = src_ctx->alg_type;

    int32_t ret = tee_drv_ioctl(dest_ctx->fd, IOCTRL_CRYPTO_CTX_COPY, &args, sizeof(args));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl ctx copy failed. ret = %d\n", ret);
        return ret;
    }

    return CRYPTO_SUCCESS;
}

int32_t crypto_driver_hash_init(struct ctx_handle_t *ctx)
{
    if (ctx == NULL) {
        tloge("ctx is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct crypto_ioctl input = {0};

    input.arg1 = ctx->alg_type;

    int32_t ret = tee_drv_ioctl(ctx->fd, IOCTRL_CRYPTO_HASH_INIT, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS)
        tloge("share buffer failed\n");

    return ret;
}

int32_t crypto_driver_hash_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    if (ctx == NULL || data_in == NULL) {
        tloge("ctx or data_in is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct drv_memref_t fill_data[] = {
        { .buffer = data_in->buffer, .size = data_in->size, .need_copy = true }
    };
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hash update prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    ret = tee_drv_ioctl(ctx->fd, IOCTRL_CRYPTO_HASH_UPDATE, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS)
        tloge("driver ioctl hash update failed. ret = %d\n", ret);

    return ret;
}

int32_t crypto_driver_hash_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    (void)data_in;
    if (ctx == NULL || data_out == NULL) {
        tloge("ctx or data_out is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct drv_memref_t fill_data[] = {
        { .buffer = data_out->buffer, .size = data_out->size, .need_copy = false }
    };
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hash dofinal prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    ret = tee_drv_ioctl(ctx->fd, IOCTRL_CRYPTO_HASH_DOFINAL, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl hash dofinal failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hash dofinal get share mem failed. ret = %d\n", ret);
        goto end;
    }

    data_out->size = fill_data[0].size;
end:
    tee_crypto_free_sharemem(ctx);
    return ret;
}

int32_t crypto_driver_hash(uint32_t alg_type, const struct memref_t *data_in,
    struct memref_t *data_out, uint32_t engine)
{
    (void)engine;
    struct ctx_handle_t ctx = { 0 };
    if (data_in == NULL || data_out == NULL) {
        tloge("data_in or data_out is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    struct drv_memref_t fill_data[] = {
        { .buffer = data_out->buffer, .size = data_out->size, .need_copy = false },
        { .buffer = data_in->buffer,  .size = data_in->size, .need_copy = true }
    };
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, &ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hash prepare ioctl parameters failed. ret = %d\n", ret);
        goto end;
    }

    input.arg1 = alg_type;

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_HASH, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl hash failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hash get share mem failed. ret = %d\n", ret);
        goto end;
    }

    data_out->size = fill_data[CRYPTO_DATA_OUT_OFFSET_0].size;
end:
    (void)tee_drv_close(fd);
    tee_crypto_free_sharemem(&ctx);
    return ret;
}

int32_t crypto_driver_hmac_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key)
{
    if (ctx == NULL || key == NULL) {
        tloge("ctx or key is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct drv_memref_t fill_data[] = {
        { .buffer = key->key_buffer, .size = key->key_size, .need_copy = true },
    };
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hmac init prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    input.arg1 = ctx->alg_type;
    input.arg2 = key->key_type;

    ret = tee_drv_ioctl(ctx->fd, IOCTRL_CRYPTO_HMAC_INIT, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl hmac initialize failed. ret = %d\n", ret);
        goto end;
    }

    return ret;
end:
    tee_crypto_free_sharemem(ctx);
    return ret;
}

int32_t crypto_driver_hmac_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    if (ctx == NULL || data_in == NULL) {
        tloge("ctx or key is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct drv_memref_t fill_data[] = {
        { .buffer = data_in->buffer, .size = data_in->size, .need_copy = true },
    };
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hmac update prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    input.arg1 = ctx->alg_type;

    ret = tee_drv_ioctl(ctx->fd, IOCTRL_CRYPTO_HMAC_UPDATE, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl hmac update failed. ret = %d\n", ret);
        goto end;
    }

    return ret;
end:
    tee_crypto_free_sharemem(ctx);
    return ret;
}

int32_t crypto_driver_hmac_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    (void)data_in;
    if (ctx == NULL || data_out == NULL) {
        tloge("ctx or data_out is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct drv_memref_t fill_data[] = {
        { .buffer = data_out->buffer, .size = data_out->size, .need_copy = false },
    };
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hmac dofinal prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    ret = tee_drv_ioctl(ctx->fd, IOCTRL_CRYPTO_HMAC_DOFINAL, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl hmac dofinal failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hmac dofinal get share mem failed. ret = %d\n", ret);
        goto end;
    }

    data_out->size = fill_data[0].size;
end:
    tee_crypto_free_sharemem(ctx);
    return ret;
}

int32_t crypto_driver_hmac(uint32_t alg_type, const struct symmerit_key_t *key,
    const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine)
{
    (void)engine;
    struct ctx_handle_t ctx = { 0 };
    if (key == NULL || data_in == NULL || data_out == NULL) {
        tloge("key or data_in or data_out is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    struct drv_memref_t fill_data[] = {
        { .buffer = data_out->buffer, .size = data_out->size, .need_copy = false },
        { .buffer = data_in->buffer,  .size = data_in->size, .need_copy = true },
        { .buffer = key->key_buffer,  .size = key->key_size, .need_copy = true },
    };
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, &ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hmac prepare ioctl parameters failed. ret = %d\n", ret);
        goto end;
    }

    input.arg1 = alg_type;
    input.arg2 = key->key_type;

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_HMAC, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl hmac failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hmac get share mem failed. ret = %d\n", ret);
        goto end;
    }

    data_out->size = fill_data[CRYPTO_DATA_OUT_OFFSET_0].size;
end:
    (void)tee_drv_close(fd);
    tee_crypto_free_sharemem(&ctx);
    return ret;
}

int32_t crypto_driver_cipher_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key,
    const struct memref_t *iv)
{
    if (ctx == NULL || key == NULL) {
        tloge("ctx or key is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct crypto_ioctl input = {0};
    (void)memset_s(&input, sizeof(input), 0, sizeof(input));
    errno_t rc;
    input.data_size_1 = key->key_size;
    rc = memcpy_s(input.data_1, sizeof(input.data_1), (void*)(uintptr_t)key->key_buffer, key->key_size);
    if (rc != EOK) {
        tloge("memcpy data in fail");
        return rc;
    }
    if (iv != NULL) {
        input.data_size_2 = iv->size;
        rc = memcpy_s(input.data_2, sizeof(input.data_2), (void*)(uintptr_t)iv->buffer, iv->size);
        if (rc != EOK) {
            tloge("memcpy data in fail");
            return rc;
        }
    }

    input.arg1 = ctx->alg_type;
    input.arg2 = ctx->driver_ability;
    input.arg3 = ctx->direction;
    input.arg4 = key->key_type;

    uint32_t ret = tee_drv_ioctl(ctx->fd, IOCTRL_CRYPTO_CIPHER_INIT, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS)
        tloge("driver ioctl cipher initialize failed. ret = %d\n", ret);

    return ret;
}

int32_t crypto_driver_cipher_update(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    if (ctx == NULL || data_in == NULL || data_out == NULL) {
        tloge("ctx or data_in or data_out is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    struct crypto_ioctl input = {0};

    struct drv_memref_t fill_data[] = {
        { .buffer = data_out->buffer, .size = data_out->size, .need_copy = false },
        { .buffer = data_in->buffer,  .size = data_in->size, .need_copy = true },
    };
    struct memref_t ioctl = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("cipher update prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    ret = tee_drv_ioctl(ctx->fd, IOCTRL_CRYPTO_CIPHER_UPDATE, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl cipher update failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((void *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS) {
        tloge("cipher update get share mem failed. ret = %d\n", ret);
        goto end;
    }

    data_out->size = fill_data[0].size;
    return CRYPTO_SUCCESS;
end:
    tee_crypto_free_sharemem(ctx);
    return ret;
}

int32_t crypto_driver_cipher_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    if (ctx == NULL || data_in == NULL || data_out == NULL) {
        tloge("ctx or data_in or data_out is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct drv_memref_t fill_data[] = {
        { .buffer = data_out->buffer, .size = data_out->size, .need_copy = false },
        { .buffer = data_in->buffer,  .size = data_in->size, .need_copy = true },
    };
    struct crypto_ioctl input = { 0 };
    struct memref_t ioctl = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("cipher dofinal prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    ret = tee_drv_ioctl(ctx->fd, IOCTRL_CRYPTO_CIPHER_DOFINAL, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl cipher dofinal failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS) {
        tloge("cipher dofinal get share mem failed. ret = %d\n", ret);
        goto end;
    }

    data_out->size = fill_data[0].size;
end:
    tee_crypto_free_sharemem(ctx);
    return ret;
}

int32_t crypto_driver_cipher(uint32_t alg_type, uint32_t direction, const struct symmerit_key_t *key,
    const struct memref_t *iv, const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine)
{
    (void)engine;
    struct ctx_handle_t ctx = { 0 };
    if (key == NULL || data_in == NULL || data_out == NULL)
        return CRYPTO_BAD_PARAMETERS;

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0)
        return CRYPTO_OVERFLOW;

    struct drv_memref_t fill_data[] = {
        { .buffer = data_out->buffer, .size = data_out->size, .need_copy = false },
        { .buffer = data_in->buffer,  .size = data_in->size, .need_copy = true },
        { .buffer = key->key_buffer,  .size = key->key_size, .need_copy = true },
        { .buffer = 0,                .size = 0, .need_copy = true },
    };

    if (iv != NULL) {
        fill_data[CRYPTO_IV_OFFSET_3].buffer = iv->buffer;
        fill_data[CRYPTO_IV_OFFSET_3].size = iv->size;
    }

    struct crypto_ioctl input = { 0 };
    struct memref_t ioctl = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, &ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("cipher prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    input.arg1 = alg_type;
    input.arg2 = direction;
    input.arg3 = key->key_type;

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_CIPHER, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl cipher failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS) {
        tloge("cipher get share mem failed. ret = %d\n", ret);
        goto end;
    }

    data_out->size = fill_data[CRYPTO_DATA_OUT_OFFSET_0].size;
end:
    (void)tee_drv_close(fd);
    tee_crypto_free_sharemem(&ctx);
    return ret;
}

int32_t crypto_driver_ae_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key,
    const struct ae_init_data *ae_init_param)
{
    if (ctx == NULL || key == NULL || ae_init_param == NULL) {
        tloge("ctx or key or ae_init_param is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct crypto_ioctl input = {0};
    (void)memset_s(&input, sizeof(input), 0, sizeof(input));
    errno_t rc;
    input.data_size_1 = key->key_size;
    rc = memcpy_s(input.data_1, sizeof(input.data_1), (void*)(uintptr_t)key->key_buffer, key->key_size);
    if (rc != EOK) {
        tloge("memcpy data in fail");
        return rc;
    }
    input.data_size_2 = ae_init_param->nonce_len;
    rc = memcpy_s(input.data_2, sizeof(input.data_2), (void*)(uintptr_t)ae_init_param->nonce, ae_init_param->nonce_len);
    if (rc != EOK) {
        tloge("memcpy data in fail");
        return rc;
    }

    input.arg1 = ctx->alg_type;
    input.arg2 = ctx->direction;
    input.arg3 = key->key_type;
    input.arg4 = ae_init_param->tag_len;
    input.arg5 = ae_init_param->aad_len;
    input.arg6 = ae_init_param->payload_len;

    uint32_t ret = tee_drv_ioctl(ctx->fd, IOCTRL_CRYPTO_AE_INIT, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS)
        tloge("driver ioctl ae initialize failed. ret = %d\n", ret);

    return ret;
}

int32_t crypto_driver_ae_update_aad(struct ctx_handle_t *ctx, const struct memref_t *aad_data)
{
    if (ctx == NULL || aad_data == NULL) {
        tloge("ctx or aad_data is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct crypto_ioctl input;
    (void)memset_s(&input, sizeof(input), 0, sizeof(input));
    errno_t rc;
    input.data_size_1 = aad_data->size;
    rc = memcpy_s(input.data_1, sizeof(input.data_1), (void*)(uintptr_t)aad_data->buffer, aad_data->size);
    if (rc != EOK) {
        tloge("memcpy data in fail");
        return rc;
    }

    uint32_t ret = tee_drv_ioctl(ctx->fd, IOCTRL_CRYPTO_AE_UPDATE_AAD, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS)
        tloge("driver ioctl ae update aad failed. ret = %d\n", ret);

    return ret;
}

int32_t crypto_driver_ae_update(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out)
{
    if (ctx == NULL || data_in == NULL || data_out == NULL) {
        tloge("ctx or data_in or data_out is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct drv_memref_t fill_data[] = {
        { .buffer = data_out->buffer, .size = data_out->size, .need_copy = false },
        { .buffer = data_in->buffer,  .size = data_in->size, .need_copy = true }
    };
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("ae update prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    ret = tee_drv_ioctl(ctx->fd, IOCTRL_CRYPTO_AE_UPDATE, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl ae update failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS) {
        tloge("ae update get share mem failed. ret = %d\n", ret);
        goto end;
    }

    data_out->size = fill_data[0].size;
    return CRYPTO_SUCCESS;
end:
    tee_crypto_free_sharemem(ctx);
    return ret;
}

int32_t crypto_driver_ae_enc_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out, struct memref_t *tag_out)
{
    if (ctx == NULL || data_in == NULL || data_out == NULL || tag_out == NULL) {
        tloge("ctx or data_in or data_out or tag_out is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct drv_memref_t fill_data[] = {
        { .buffer = data_out->buffer, .size = data_out->size, .need_copy = false },
        { .buffer = tag_out->buffer,  .size = tag_out->size, .need_copy = true },
        { .buffer = data_in->buffer,  .size = data_in->size, .need_copy = true }
    };
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("ae enc final prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    ret = tee_drv_ioctl(ctx->fd, IOCTRL_CRYPTO_AE_ENC_FINAL, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl ae enc final failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_2);
    if (ret != CRYPTO_SUCCESS) {
        tloge("ae enc final get share mem failed. ret = %d\n", ret);
        goto end;
    }

    data_out->size = fill_data[CRYPTO_DATA_OUT_OFFSET_0].size;
    tag_out->size = fill_data[CRYPTO_TAG_OUT_OFFSET_1].size;
end:
    tee_crypto_free_sharemem(ctx);
    return ret;
}

int32_t crypto_driver_ae_dec_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    const struct memref_t *tag_in, struct memref_t *data_out)
{
    if (ctx == NULL || data_in == NULL || tag_in == NULL || data_out == NULL) {
        tloge("ctx or data_in or tag_in or data_out is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct drv_memref_t fill_data[] = {
        { .buffer = data_out->buffer, .size = data_out->size, .need_copy = false },
        { .buffer = data_in->buffer,  .size = data_in->size, .need_copy = true },
        { .buffer = tag_in->buffer,   .size = tag_in->size, .need_copy = true }
    };
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("ae dec final prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    ret = tee_drv_ioctl(ctx->fd, IOCTRL_CRYPTO_AE_DEC_FINAL, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl ae dec final failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS) {
        tloge("ae dec final get share mem failed. ret = %d\n", ret);
        goto end;
    }

    data_out->size = fill_data[CRYPTO_DATA_OUT_OFFSET_0].size;
end:
    tee_crypto_free_sharemem(ctx);
    return ret;
}

int32_t crypto_driver_rsa_generate_keypair(uint32_t key_size, const struct memref_t *e_value, bool crt_mode,
    struct rsa_priv_key_t *key_pair, uint32_t engine)
{
    (void)engine;
    struct ctx_handle_t ctx = { 0 };
    if (key_pair == NULL) {
        tloge("key_pair is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    struct drv_memref_t fill_data[] = {
        { .buffer = (uint64_t)(uintptr_t)key_pair, .size = sizeof(*key_pair), .need_copy = true },
        { .buffer = 0,                             .size = 0, .need_copy = true },
    };

    if (e_value != NULL) {
        fill_data[CRYPTO_E_VALUE_OFFSET_1].buffer = e_value->buffer;
        fill_data[CRYPTO_E_VALUE_OFFSET_1].size = e_value->size;
    }

    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, &ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("rsa generate keypair prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    input.arg1 = key_size;
    input.arg2 = (uint32_t)crt_mode;

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_RSA_GENERATE_KEYPAIR, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl rsa generate keypair failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS)
        tloge("rsa generate keypair get share mem failed. ret = %d\n", ret);

end:
    (void)tee_drv_close(fd);
    tee_crypto_free_sharemem(&ctx);
    return ret;
}

#define DOUBLE_SIZE   2
static uint32_t get_attr_buf_size(const struct asymmetric_params_t *asymmetric_params)
{
    uint32_t attr_buf_size = 0;
    struct crypto_attribute_t *attr = (struct crypto_attribute_t *)(uintptr_t)(asymmetric_params->attribute);

    for (uint32_t i = 0; i < asymmetric_params->param_count; i++) {
        attr_buf_size += sizeof(uint32_t);
        if (TEE_ATTR_IS_BUFFER(attr->attribute_id)) {
            attr_buf_size += (sizeof(uint32_t) + attr->content.ref.length);
        } else {
            attr_buf_size += DOUBLE_SIZE * sizeof(uint32_t);
            tlogd("this is a value attribute\n");
        }
        attr++;
    }
    return attr_buf_size;
}

static int32_t restore_attr_buff(uint8_t **restore_buf, const struct crypto_attribute_t *attr)
{
    if (attr->content.ref.buffer == 0 || attr->content.ref.length == 0) {
        tloge("attribute buffer or length error! length = %d", attr->content.ref.length);
        return CRYPTO_BAD_PARAMETERS;
    }

    if (memcpy_s(*restore_buf, sizeof(uint32_t), &(attr->content.ref.length), sizeof(uint32_t)) != EOK) {
        tloge("copy attribute buffer length fail");
        return CRYPTO_ERROR_SECURITY;
    }

    *restore_buf += sizeof(uint32_t);

    if (memcpy_s(*restore_buf, attr->content.ref.length, (void *)(uintptr_t)(attr->content.ref.buffer),
        attr->content.ref.length) != EOK) {
        tloge("copy attribute buffer fail");
        return CRYPTO_ERROR_SECURITY;
    }

    *restore_buf += attr->content.ref.length;
    return CRYPTO_SUCCESS;
}

static int32_t restore_attr_value(uint8_t **restore_buf, const struct crypto_attribute_t *attr)
{
    if (memcpy_s(*restore_buf, sizeof(uint32_t), &(attr->content.value.a), sizeof(uint32_t)) != EOK) {
        tloge("copy attribute value a fail");
        return CRYPTO_ERROR_SECURITY;
    }

    *restore_buf += sizeof(uint32_t);

    if (memcpy_s(*restore_buf, sizeof(uint32_t), &(attr->content.value.b), sizeof(uint32_t)) != EOK) {
        tloge("copy attribute value b fail");
        return CRYPTO_ERROR_SECURITY;
    }

    *restore_buf += sizeof(uint32_t);
    return CRYPTO_SUCCESS;
}

static int32_t restore_attrs(const struct asymmetric_params_t *asymmetric_params, uint8_t **buf, uint32_t *buf_len)
{
    if (asymmetric_params == NULL || asymmetric_params->param_count == 0 || asymmetric_params->attribute == 0) {
        *buf = NULL;
        *buf_len = 0;
        return CRYPTO_SUCCESS;
    }

    uint32_t attr_len = get_attr_buf_size(asymmetric_params);
    uint8_t *attr_buf = (uint8_t *)TEE_Malloc(attr_len + sizeof(uint32_t), 0);
    if (attr_buf == NULL) {
        tloge("Failed to allocate memory for attribute\n");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    int32_t ret;
    uint8_t *tmp_buf = attr_buf;
    if (memcpy_s(tmp_buf, sizeof(uint32_t), &(asymmetric_params->param_count), sizeof(uint32_t)) != EOK) {
        tloge("copy param count fail");
        ret = CRYPTO_ERROR_SECURITY;
        goto clean;
    }
    tmp_buf += sizeof(uint32_t);

    struct crypto_attribute_t *attr = (struct crypto_attribute_t *)(uintptr_t)(asymmetric_params->attribute);
    for (uint32_t i = 0; i < asymmetric_params->param_count; i++) {
        if (memcpy_s(tmp_buf, sizeof(uint32_t), &(attr->attribute_id), sizeof(uint32_t)) != EOK) {
            tloge("copy attribute id fail");
            ret = CRYPTO_ERROR_SECURITY;
            goto clean;
        }
        tmp_buf += sizeof(uint32_t);

        if (TEE_ATTR_IS_BUFFER(attr->attribute_id)) /* buffer attribute */
            ret = restore_attr_buff(&tmp_buf, attr);
        else
            ret = restore_attr_value(&tmp_buf, attr);

        if (ret != CRYPTO_SUCCESS)
            goto clean;

        attr++;
    }
    *buf = attr_buf;
    *buf_len = attr_len + sizeof(uint32_t);
    return CRYPTO_SUCCESS;

clean:
    TEE_Free(tmp_buf);
    *buf = NULL;
    *buf_len = 0;

    return ret;
}

int32_t crypto_rsa_encrypt_ops(uint64_t fd, struct drv_memref_t *fill_data, uint32_t fill_data_count, uint32_t alg_type)
{
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };
    struct ctx_handle_t ctx = { 0 };

    input.arg1 = alg_type;

    int32_t ret = prepare_ioctl_parameters(fill_data, fill_data_count, &ioctl, &input, &ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("rsa encrypt prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_RSA_ENCRYPT, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl rsa encrypt failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS) {
        tloge("rsa encrypt get share mem failed. ret = %d\n", ret);
        goto end;
    }

end:
    tee_crypto_free_sharemem(&ctx);
    return ret;
}

int32_t crypto_driver_rsa_encrypt(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *data_in,
    struct memref_t *data_out, uint32_t engine)
{
    (void)engine;
    if (public_key == NULL || data_in == NULL || data_out == NULL) {
        tloge("public_key or data_in or data_out is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    uint8_t *attr_buf = NULL;
    uint32_t attr_buf_len = 0;

    int32_t ret = restore_attrs(rsa_params, &attr_buf, &attr_buf_len);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    struct drv_memref_t fill_data[] = {
        { .buffer = data_out->buffer,                .size = data_out->size, .need_copy = false },
        { .buffer = data_in->buffer,                 .size = data_in->size, .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)public_key, .size = sizeof(*public_key), .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)attr_buf,   .size = attr_buf_len, .need_copy = true },
    };

    ret = crypto_rsa_encrypt_ops(fd, fill_data, ARRAY_SIZE(fill_data), alg_type);
    if (ret != CRYPTO_SUCCESS) {
        tloge("crypto rsa encrypt ops failed. ret = %d", ret);
        goto end;
    }

    data_out->size = fill_data[CRYPTO_DATA_OUT_OFFSET_0].size;
end:
    (void)tee_drv_close(fd);
    if (attr_buf != NULL)
        TEE_Free(attr_buf);

    return ret;
}

int32_t crypto_rsa_decrypt_ops(uint64_t fd, struct drv_memref_t *fill_data, uint32_t fill_data_count, uint32_t alg_type)
{
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };
    struct ctx_handle_t ctx = { 0 };

    input.arg1 = alg_type;

    int32_t ret = prepare_ioctl_parameters(fill_data, fill_data_count, &ioctl, &input, &ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("rsa decrypt prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_RSA_DECRYPT, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl rsa decrypt failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS) {
        tloge("rsa decrypt get share mem failed. ret = %d\n", ret);
        goto end;
    }

end:
    tee_crypto_free_sharemem(&ctx);
    return ret;
}

int32_t crypto_driver_rsa_decrypt(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *data_in, struct memref_t *data_out,
    uint32_t engine)
{
    (void)engine;
    if (private_key == NULL || data_in == NULL || data_out == NULL) {
        tloge("private_key or data_in or data_out is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    uint8_t *attr_buf = NULL;
    uint32_t attr_buf_len = 0;

    int32_t ret = restore_attrs(rsa_params, &attr_buf, &attr_buf_len);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    struct drv_memref_t fill_data[] = {
        { .buffer = data_out->buffer,                 .size = data_out->size, .need_copy = false },
        { .buffer = data_in->buffer,                  .size = data_in->size, .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)private_key, .size = sizeof(*private_key), .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)attr_buf,    .size = attr_buf_len, .need_copy = true },
    };

    ret = crypto_rsa_decrypt_ops(fd, fill_data, ARRAY_SIZE(fill_data), alg_type);
    if (ret != CRYPTO_SUCCESS) {
        tloge("crypto rsa decrypt ops failed. ret = %d", ret);
        goto end;
    }

    data_out->size = fill_data[CRYPTO_DATA_OUT_OFFSET_0].size;
end:
    (void)tee_drv_close(fd);
    if (attr_buf != NULL)
        TEE_Free(attr_buf);

    return ret;
}

int32_t crypto_rsa_sign_digest_ops(uint64_t fd, struct drv_memref_t *fill_data,
    uint32_t fill_data_count, uint32_t alg_type)
{
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };
    struct ctx_handle_t ctx = { 0 };

    input.arg1 = alg_type;

    int32_t ret = prepare_ioctl_parameters(fill_data, fill_data_count, &ioctl, &input, &ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("rsa sign digest prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_RSA_SIGN_DIGEST, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl rsa sign digest failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS) {
        tloge("rsa sign digest get share mem failed. ret = %d\n", ret);
        goto end;
    }

end:
    tee_crypto_free_sharemem(&ctx);
    return ret;
}

int32_t crypto_driver_rsa_sign_digest(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
    const struct asymmetric_params_t *rsa_params,
    const struct memref_t *digest, struct memref_t *signature, uint32_t engine)
{
    (void)engine;
    if (private_key == NULL || digest == NULL || signature == NULL) {
        tloge("private_key or digest or signature is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    uint8_t *attr_buf = NULL;
    uint32_t attr_buf_len = 0;

    int32_t ret = restore_attrs(rsa_params, &attr_buf, &attr_buf_len);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    struct drv_memref_t fill_data[] = {
        { .buffer = signature->buffer,                .size = signature->size, .need_copy = true },
        { .buffer = digest->buffer,                   .size = digest->size, .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)private_key, .size = sizeof(*private_key), .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)attr_buf,    .size = attr_buf_len, .need_copy = true },
    };

    ret = crypto_rsa_sign_digest_ops(fd, fill_data, ARRAY_SIZE(fill_data), alg_type);
    if (ret != CRYPTO_SUCCESS) {
        tloge("crypto rsa sign digest ops failed. ret = %d", ret);
        goto end;
    }

    signature->size = fill_data[CRYPTO_SIGNATURE_OFFSET_0].size;
end:
    (void)tee_drv_close(fd);
    if (attr_buf != NULL)
        TEE_Free(attr_buf);

    return ret;
}

int32_t crypto_driver_rsa_verify_digest(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct asymmetric_params_t *rsa_params,
    const struct memref_t *digest, const struct memref_t *signature, uint32_t engine)
{
    (void)engine;
    if (public_key == NULL || digest == NULL || signature == NULL) {
        tloge("public_key or digest or signature is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    uint8_t *attr_buf = NULL;
    uint32_t attr_buf_len = 0;

    int32_t ret = restore_attrs(rsa_params, &attr_buf, &attr_buf_len);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    struct drv_memref_t fill_data[] = {
        { .buffer = signature->buffer,               .size = signature->size, .need_copy = true },
        { .buffer = digest->buffer,                  .size = digest->size, .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)public_key, .size = sizeof(*public_key), .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)attr_buf,   .size = attr_buf_len, .need_copy = true },
    };
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };
    struct ctx_handle_t ctx = { 0 };

    ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, &ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("rsa verify digest prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    input.arg1 = alg_type;

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_RSA_VERIFY_DIGEST, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS)
        tloge("driver ioctl rsa verify digest failed. ret = %d\n", ret);

end:
    (void)tee_drv_close(fd);
    tee_crypto_free_sharemem(&ctx);
    if (attr_buf != NULL)
        TEE_Free(attr_buf);

    return ret;
}

int32_t crypto_driver_ecc_generate_keypair(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key, uint32_t engine)
{
    (void)engine;
    if (public_key == NULL || private_key == NULL) {
        tloge("public_key or private_key is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    struct drv_memref_t fill_data[] = {
        { .buffer = (uint64_t)(uintptr_t)public_key,  .size = sizeof(*public_key), .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)private_key, .size = sizeof(*private_key), .need_copy = true },
    };

    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };
    struct ctx_handle_t ctx = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, &ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("ecc generate keypair prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    input.arg1 = key_size;
    input.arg2 = curve;

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_ECC_GENERATE_KEYPAIR, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl ecc generate keypair failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_2);
    if (ret != CRYPTO_SUCCESS)
        tloge("ecc generate keypair get share mem failed. ret = %d\n", ret);

end:
    (void)tee_drv_close(fd);
    tee_crypto_free_sharemem(&ctx);
    return ret;
}

int32_t crypto_ecc_encrypt_ops(uint64_t fd, struct drv_memref_t *fill_data, uint32_t fill_data_count, uint32_t alg_type)
{
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };
    struct ctx_handle_t ctx = { 0 };

    input.arg1 = alg_type;

    int32_t ret = prepare_ioctl_parameters(fill_data, fill_data_count, &ioctl, &input, &ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("ecc encrypt prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_ECC_ENCRYPT, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl ecc encrypt failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS) {
        tloge("ecc encrypt get share mem failed. ret = %d\n", ret);
        goto end;
    }

end:
    tee_crypto_free_sharemem(&ctx);
    return ret;
}

int32_t crypto_driver_ecc_encrypt(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params,
    const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine)
{
    (void)engine;
    if (public_key == NULL || data_in == NULL || data_out == NULL) {
        tloge("public_key or data_in or data_out is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    uint8_t *attr_buf = NULL;
    uint32_t attr_buf_len = 0;

    int32_t ret = restore_attrs(ec_params, &attr_buf, &attr_buf_len);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    struct drv_memref_t fill_data[] = {
        { .buffer = data_out->buffer,                .size = data_out->size, .need_copy = false },
        { .buffer = data_in->buffer,                 .size = data_in->size, .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)public_key, .size = sizeof(*public_key), .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)attr_buf,   .size = attr_buf_len, .need_copy = true },
    };

    ret = crypto_ecc_encrypt_ops(fd, fill_data, ARRAY_SIZE(fill_data), alg_type);
    if (ret != CRYPTO_SUCCESS) {
        tloge("crypto ecc encrypt ops failed. ret = %d", ret);
        goto end;
    }

    data_out->size = fill_data[CRYPTO_DATA_OUT_OFFSET_0].size;
end:
    (void)tee_drv_close(fd);
    if (attr_buf != NULL)
        TEE_Free(attr_buf);

    return ret;
}

int32_t crypto_ecc_decrypt_ops(uint64_t fd, struct drv_memref_t *fill_data, uint32_t fill_data_count, uint32_t alg_type)
{
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };
    struct ctx_handle_t ctx = { 0 };

    input.arg1 = alg_type;

    int32_t ret = prepare_ioctl_parameters(fill_data, fill_data_count, &ioctl, &input, &ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("ecc decrypt prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_ECC_DECRYPT, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl ecc decrypt failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS) {
        tloge("ecc decrypt get share mem failed. ret = %d\n", ret);
        goto end;
    }

end:
    tee_crypto_free_sharemem(&ctx);
    return ret;
}

int32_t crypto_driver_ecc_decrypt(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params,
    const struct memref_t *data_in, struct memref_t *data_out, uint32_t engine)
{
    (void)engine;
    if (private_key == NULL || data_in == NULL || data_out == NULL) {
        tloge("private_key or data_in or data_out is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    uint8_t *attr_buf = NULL;
    uint32_t attr_buf_len = 0;

    int32_t ret = restore_attrs(ec_params, &attr_buf, &attr_buf_len);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    struct drv_memref_t fill_data[] = {
        { .buffer = data_out->buffer,                 .size = data_out->size, .need_copy = false },
        { .buffer = data_in->buffer,                  .size = data_in->size, .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)private_key, .size = sizeof(*private_key), .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)attr_buf,    .size = attr_buf_len, .need_copy = true },
    };

    ret = crypto_ecc_decrypt_ops(fd, fill_data, ARRAY_SIZE(fill_data), alg_type);
    if (ret != CRYPTO_SUCCESS) {
        tloge("crypto ecc decrypt ops failed. ret = %d", ret);
        goto end;
    }

    data_out->size = fill_data[CRYPTO_DATA_OUT_OFFSET_0].size;
end:
    (void)tee_drv_close(fd);
    if (attr_buf != NULL)
        TEE_Free(attr_buf);

    return ret;
}

int32_t crypto_ecc_sign_digest_ops(uint64_t fd, struct drv_memref_t *fill_data,
    uint32_t fill_data_count, uint32_t alg_type)
{
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };
    struct ctx_handle_t ctx = { 0 };

    input.arg1 = alg_type;

    int32_t ret = prepare_ioctl_parameters(fill_data, fill_data_count, &ioctl, &input, &ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("ecc sign digest prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_ECC_SIGN_DIGEST, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl ecc sign digest failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS) {
        tloge("ecc sign digest get share mem failed. ret = %d\n", ret);
        goto end;
    }

end:
    tee_crypto_free_sharemem(&ctx);
    return ret;
}

int32_t crypto_driver_ecc_sign_digest(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params,
    const struct memref_t *digest, struct memref_t *signature, uint32_t engine)
{
    (void)engine;
    if (private_key == NULL || digest == NULL || signature == NULL) {
        tloge("private_key or digest or signature is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    uint8_t *attr_buf = NULL;
    uint32_t attr_buf_len = 0;

    int32_t ret = restore_attrs(ec_params, &attr_buf, &attr_buf_len);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    struct drv_memref_t fill_data[] = {
        { .buffer = signature->buffer,                .size = signature->size, .need_copy = true },
        { .buffer = digest->buffer,                   .size = digest->size, .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)private_key, .size = sizeof(*private_key), .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)attr_buf,    .size = attr_buf_len, .need_copy = true },
    };

    ret = crypto_ecc_sign_digest_ops(fd, fill_data, ARRAY_SIZE(fill_data), alg_type);
    if (ret != CRYPTO_SUCCESS) {
        tloge("crypto ecc sign digest ops failed. ret = %d", ret);
        goto end;
    }

    signature->size = fill_data[CRYPTO_SIGNATURE_OFFSET_0].size;
end:
    (void)tee_drv_close(fd);
    if (attr_buf != NULL)
        TEE_Free(attr_buf);

    return ret;
}

int32_t crypto_driver_ecc_verify_digest(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params,
    const struct memref_t *digest, const struct memref_t *signature, uint32_t engine)
{
    (void)engine;
    if (public_key == NULL || digest == NULL || signature == NULL) {
        tloge("public_key or digest or signature is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    uint8_t *attr_buf = NULL;
    uint32_t attr_buf_len = 0;

    int32_t ret = restore_attrs(ec_params, &attr_buf, &attr_buf_len);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    struct drv_memref_t fill_data[] = {
        { .buffer = signature->buffer,               .size = signature->size, .need_copy = true },
        { .buffer = digest->buffer,                  .size = digest->size, .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)public_key, .size = sizeof(*public_key), .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)attr_buf,   .size = attr_buf_len, .need_copy = true },
    };
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };
    struct ctx_handle_t ctx = { 0 };

    ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, &ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("ecc verify digest prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    input.arg1 = alg_type;

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_ECC_VERIFY_DIGEST, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl ecc verify digest failed. ret = %d\n", ret);
        goto end;
    }

end:
    (void)tee_drv_close(fd);
    tee_crypto_free_sharemem(&ctx);
    if (attr_buf != NULL)
        TEE_Free(attr_buf);

    return ret;
}

int32_t crypto_ecdh_derive_key_ops(uint64_t fd, struct drv_memref_t *fill_data,
    uint32_t fill_data_count, uint32_t alg_type)
{
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };
    struct ctx_handle_t ctx = { 0 };

    input.arg1 = alg_type;

    int32_t ret = prepare_ioctl_parameters(fill_data, fill_data_count, &ioctl, &input, &ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("ecdh derive key prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_ECDH_DERIVE_KEY, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl ecdh derive key failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS) {
        tloge("ecdh derive key get share mem failed. ret = %d\n", ret);
        goto end;
    }

end:
    tee_crypto_free_sharemem(&ctx);
    return ret;
}

int32_t crypto_driver_ecdh_derive_key(uint32_t alg_type,
    const struct ecc_pub_key_t *client_key, const struct ecc_priv_key_t *server_key,
    const struct asymmetric_params_t *ec_params, struct memref_t *secret, uint32_t engine)
{
    (void)engine;
    if (client_key == NULL || server_key == NULL || secret == NULL) {
        tloge("client_key or server_key or secret is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    uint8_t *attr_buf = NULL;
    uint32_t attr_buf_len = 0;

    int32_t ret = restore_attrs(ec_params, &attr_buf, &attr_buf_len);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    struct drv_memref_t fill_data[] = {
        { .buffer = secret->buffer,                  .size = secret->size, .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)client_key, .size = sizeof(*client_key), .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)server_key, .size = sizeof(*server_key), .need_copy = true },
        { .buffer = (uint64_t)(uintptr_t)attr_buf,   .size = attr_buf_len, .need_copy = true },
    };

    ret = crypto_ecdh_derive_key_ops(fd, fill_data, ARRAY_SIZE(fill_data), alg_type);
    if (ret != CRYPTO_SUCCESS) {
        tloge("crypto ecdh derive key ops failed. ret = %d", ret);
        goto end;
    }

    secret->size = fill_data[CRYPTO_SECRET_OFFSET_0].size;
end:
    (void)tee_drv_close(fd);
    if (attr_buf != NULL)
        TEE_Free(attr_buf);

    return ret;
}

int32_t crypto_driver_dh_generate_key(const struct dh_key_t *dh_generate_key_data,
    struct memref_t *pub_key, struct memref_t *priv_key, uint32_t engine)
{
    (void)engine;
    if (dh_generate_key_data == NULL || pub_key == NULL || priv_key == NULL) {
        tloge("dh_generate_key_data or pub_key or priv_key is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    struct drv_memref_t fill_data[] = {
        { .buffer = pub_key->buffer,                 .size = pub_key->size, .need_copy = true },
        { .buffer = priv_key->buffer,                .size = priv_key->size, .need_copy = true },
        { .buffer = dh_generate_key_data->prime,     .size = dh_generate_key_data->prime_size, .need_copy = true },
        { .buffer = dh_generate_key_data->generator, .size = dh_generate_key_data->generator_size, .need_copy = true },
        { .buffer = dh_generate_key_data->dh_param.generate_key_t.q,
            .size = dh_generate_key_data->dh_param.generate_key_t.q_size, .need_copy = true },
    };
    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };
    struct ctx_handle_t ctx = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, &ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("dh generate key prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    input.arg1 = dh_generate_key_data->dh_param.generate_key_t.l;
    input.arg2 = dh_generate_key_data->dh_param.generate_key_t.dh_mode;

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_DH_GENERATE_KEY, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl dh generate key failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_2);
    if (ret != CRYPTO_SUCCESS)
        tloge("dh generate key get share mem failed. ret = %d\n", ret);

end:
    (void)tee_drv_close(fd);
    tee_crypto_free_sharemem(&ctx);
    return ret;
}

int32_t crypto_driver_dh_derive_key(const struct dh_key_t *dh_derive_key_data,
    struct memref_t *secret, uint32_t engine)
{
    (void)engine;
    if (dh_derive_key_data == NULL || secret == NULL) {
        tloge("dh_derive_key_data or secret is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    struct drv_memref_t fill_data[] = {
        { .buffer = secret->buffer,                .size = secret->size, .need_copy = true },
        { .buffer = dh_derive_key_data->prime,     .size = dh_derive_key_data->prime_size, .need_copy = true },
        { .buffer = dh_derive_key_data->generator, .size = dh_derive_key_data->generator_size, .need_copy = true },
        { .buffer = dh_derive_key_data->dh_param.derive_key_t.pub_key,
            .size = dh_derive_key_data->dh_param.derive_key_t.pub_key_size, .need_copy = true },
        { .buffer = dh_derive_key_data->dh_param.derive_key_t.priv_key,
            .size = dh_derive_key_data->dh_param.derive_key_t.priv_key_size, .need_copy = true },
    };

    struct crypto_ioctl input = {0};
    struct memref_t ioctl = { 0 };
    struct ctx_handle_t ctx = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, &input, &ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("dh derive key prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_DH_DERIVE_KEY, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl dh derive key failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS)
        tloge("dh derive key get share mem failed. ret = %d\n", ret);

end:
    (void)tee_drv_close(fd);
    tee_crypto_free_sharemem(&ctx);
    return ret;
}

int32_t crypto_get_buf_ops(uint32_t cmd_id, uint64_t fd, void *buffer, uint32_t size)
{
    int64_t ret;
    struct crypto_ioctl input = { 0 };

    struct drv_memref_t fill_data[] = {
        { .buffer = (uint64_t)(uintptr_t)buffer, .size = size, .need_copy = true }
    };

    uint32_t ioctl_size = size + sizeof(uint32_t);
    TEE_UUID uuid = CRYPTOMGR;
    uint8_t *ioctl_buf = alloc_sharemem_aux(&uuid, ioctl_size);
    if (ioctl_buf == NULL) {
        tloge("init alloc share mem failed\n");
        return CRYPTO_OVERFLOW;
    }

    ret = fill_share_mem(ioctl_buf, fill_data, ARRAY_SIZE(fill_data));
    if (ret != CRYPTO_SUCCESS)
        goto end;

    input.buf = (uint64_t)(uintptr_t)ioctl_buf;
    input.buf_len = ioctl_size;
    input.total_nums = ARRAY_SIZE(fill_data);

    ret = tee_drv_ioctl(fd, cmd_id, (void *)(&input), sizeof(input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("share buffer failed\n");
        goto end;
    }

    ret = get_share_mem(ioctl_buf, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS)
        goto end;

end:
    if (ioctl_buf != NULL)
        free_sharemem(ioctl_buf, ioctl_size);

    return ret;
}

int32_t crypto_driver_generate_random(void *buffer, uint32_t size, bool is_hw_rand)
{
    (void)is_hw_rand;
    if (buffer == NULL || size == 0) {
        tloge("params is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }
    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    int64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }
    int32_t ret = crypto_get_buf_ops(IOCTRL_CRYPTO_GENERATE_RANDOM, fd, buffer, size);

    (void)tee_drv_close(fd);
    return ret;
}

int32_t crypto_driver_get_entropy(void *buffer, uint32_t size)
{
#if !defined(CRYPTO_MGR_SERVER_ENABLE)
    return soft_random_get(buffer, size);
#else
    if (buffer == NULL || size == 0) {
        tloge("params is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }
    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }
    int32_t ret = crypto_get_buf_ops(IOCTRL_CRYPTO_GET_ENTROPY, fd, buffer, size);
    if (ret != CRYPTO_SUCCESS)
        tloge("generate random failed");

    (void)tee_drv_close(fd);
    return ret;
#endif
}

static int32_t crypto_root_key_ops(uint64_t fd, const struct memref_t *data_in,
    struct memref_t *data_out, struct crypto_ioctl *input)
{
    int32_t ret;

    struct drv_memref_t fill_data[] = {
        { .buffer = data_out->buffer, .size = data_out->size, .need_copy = false },
        { .buffer = data_in->buffer,  .size = data_in->size, .need_copy = true },
    };

    uint32_t ioctl_size = data_out->size + data_in->size + ARRAY_SIZE(fill_data) * sizeof(uint32_t);
    TEE_UUID uuid = CRYPTOMGR;
    uint8_t *ioctl_buf = alloc_sharemem_aux(&uuid, ioctl_size);
    if (ioctl_buf == NULL) {
        tloge("root init alloc share mem failed\n");
        return CRYPTO_OVERFLOW;
    }

    ret = fill_share_mem(ioctl_buf, fill_data, ARRAY_SIZE(fill_data));
    if (ret != CRYPTO_SUCCESS)
        goto end;

    input->buf = (uint64_t)(uintptr_t)ioctl_buf;
    input->buf_len = ioctl_size;
    input->total_nums = ARRAY_SIZE(fill_data);

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_DERIVE_ROOT_KEY, (void *)(input), sizeof(*input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("share buffer failed\n");
        goto end;
    }

    ret = get_share_mem(ioctl_buf, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS)
        goto end;
    data_out->size = fill_data[CRYPTO_DATA_OUT_OFFSET_0].size;

end:
    if (ioctl_buf != NULL)
        free_sharemem(ioctl_buf, ioctl_size);

    return ret;
}

int32_t crypto_driver_derive_root_key(uint32_t derive_type,
    const struct memref_t *data_in, struct memref_t *data_out, uint32_t iter_num)
{
    struct crypto_ioctl input = { 0 };

    if (data_in == NULL || data_out == 0) {
        tloge("params is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }
    input.arg1 = derive_type;
    input.arg2 = iter_num;
    int32_t ret = crypto_root_key_ops(fd, data_in, data_out, &input);
    if (ret != CRYPTO_SUCCESS)
        tloge("generate random failed");

    (void)tee_drv_close(fd);

    return ret;
}

static int32_t crypto_pbkdf2_ops(uint64_t fd, const struct memref_t *password,
    const struct memref_t *salt, struct memref_t *data_out, struct crypto_ioctl *input)
{
    struct drv_memref_t fill_data[] = {
        { .buffer = data_out->buffer, .size = data_out->size, .need_copy = false },
        { .buffer = salt->buffer,     .size = salt->size, .need_copy = true },
        { .buffer = password->buffer, .size = password->size, .need_copy = true }
    };

    struct memref_t ioctl = { 0 };
    struct ctx_handle_t ctx = { 0 };

    int32_t ret = prepare_ioctl_parameters(fill_data, ARRAY_SIZE(fill_data), &ioctl, input, &ctx);
    if (ret != CRYPTO_SUCCESS) {
        tloge("pbkdf2 prepare ioctl parameters failed. ret = %d\n", ret);
        return ret;
    }

    ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_PBKDF2, (void *)(input), sizeof(*input));
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl pbkdf2 failed. ret = %d\n", ret);
        goto end;
    }

    ret = get_share_mem((uint8_t *)(uintptr_t)ioctl.buffer, fill_data, CRYPTO_PARAM_COUNT_1);
    if (ret != CRYPTO_SUCCESS) {
        tloge("driver ioctl pbkdf2 failed. ret = %d\n", ret);
        goto end;
    }

    data_out->size = fill_data[CRYPTO_DATA_OUT_OFFSET_0].size;
end:
    tee_crypto_free_sharemem(&ctx);
    return ret;
}

int32_t crypto_driver_pbkdf2(const struct memref_t *password, const struct memref_t *salt, uint32_t iterations,
    uint32_t digest_type, struct memref_t *data_out, uint32_t engine)
{
    (void)engine;
    struct crypto_ioctl input = { 0 };

    if (password == NULL || salt == NULL || data_out == NULL) {
        tloge("params is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }

    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    input.arg1 = iterations;
    input.arg2 = digest_type;
    int32_t ret = crypto_pbkdf2_ops(fd, password, salt, data_out, &input);
    if (ret != CRYPTO_SUCCESS)
        tloge("crypto pbkdf2 failed");

    (void)tee_drv_close(fd);

    return ret;
}

int32_t tee_crypto_check_alg_support(uint32_t alg_type)
{
    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;

    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    int32_t ret = tee_drv_ioctl(fd, IOCTRL_CRYPTO_CHECK_ALG_SUPPORT, (void *)(&alg_type), sizeof(uint32_t));
    if (ret != CRYPTO_SUCCESS)
        tloge("check alg support failed\n");

    (void)tee_drv_close(fd);

    return ret;
}

int32_t tee_crypto_get_oemkey(void *buf, uint32_t size)
{
    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;

    uint64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("open fd failed\n");
        return CRYPTO_OVERFLOW;
    }

    int32_t ret = crypto_get_buf_ops(IOCTRL_CRYPTO_GET_OEMKEY, fd, buf, size);
    if (ret != CRYPTO_SUCCESS)
        tloge("get oemkey failed\n");

    (void)tee_drv_close(fd);

    return ret;
}
