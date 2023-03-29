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
#include "crypto_syscall_random.h"
#include <securec.h>
#include "tee_driver_module.h"
#include <tee_log.h>
#include "drv_param_ops.h"

static uint8_t g_cached_random[CACHED_RANDOM_SIZE] = {0};
static uint32_t g_used_block_count = TOTAL_RANDOM_BLOCK;

static int32_t do_generate_random(const struct crypto_drv_ops_t *ops, void *buffer, size_t size)
{
    if (ops->generate_random == NULL) {
        tloge("generate is not support\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ops->generate_random(buffer, size);
    if (ret != CRYPTO_SUCCESS)
        tloge("generate random failed\n");

    do_power_off(ops);
    return ret;
}

static int32_t generate_random_from_cached(const struct crypto_drv_ops_t *ops, void *buffer, size_t size)
{
    if (g_used_block_count > TOTAL_RANDOM_BLOCK) {
        tloge("Invalid cache block size\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (g_used_block_count == TOTAL_RANDOM_BLOCK ||
        size > (TOTAL_RANDOM_BLOCK - g_used_block_count) * ONE_BLOCK_SIZE) {
        (void)memset_s(g_cached_random, sizeof(g_cached_random), 0, sizeof(g_cached_random));
        int32_t ret = do_generate_random(ops, g_cached_random, sizeof(g_cached_random));
        if (ret != CRYPTO_SUCCESS)
            return ret;

        g_used_block_count = 0;
    }

    uint32_t need_block_count = (size % ONE_BLOCK_SIZE == 0) ? (size / ONE_BLOCK_SIZE) : (size / ONE_BLOCK_SIZE + 1);
    errno_t rc = memcpy_s(buffer, size, g_cached_random + g_used_block_count * ONE_BLOCK_SIZE, size);
    if (rc != EOK) {
        tloge("memory copy failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }

    rc = memset_s(g_cached_random + g_used_block_count * ONE_BLOCK_SIZE,
        sizeof(g_cached_random) - g_used_block_count * ONE_BLOCK_SIZE, 0, size);
    if (rc != EOK)
        tloge("memory set failed, rc=0x%x\n", rc);

    g_used_block_count += need_block_count;

    return CRYPTO_SUCCESS;
}

int32_t hw_generate_random_ops(const void *ops, void *buf, uint32_t size)
{
    if (buf == NULL || size == 0 || ops == NULL) {
        tloge("generate random params fail\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (size < CACHED_RANDOM_SIZE)
        return generate_random_from_cached(ops, buf, size);

    return do_generate_random(ops, buf, size);
}

static int32_t generate_random(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg)
{
    void *buffer = NULL;
    size_t size;

    buffer = (void *)(uintptr_t)crypto_arg->buffer;
    size = crypto_arg->size;

    return hw_generate_random_ops(ops, buffer, size);
}

int32_t generate_random_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    uint8_t *generate_random_share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &generate_random_share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = generate_random(ops, buf_arg);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)generate_random_share_buf, ioctl_args->buf_len, ioctl_args->buf,
        ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        tloge("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(generate_random_share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return CRYPTO_SUCCESS;
}

static int32_t get_entropy_ops(const struct crypto_drv_ops_t *ops, struct memref_t *buf_arg)
{
    if (ops->get_entropy == NULL) {
        tloge("hardware engine get entropy fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    size_t size = buf_arg->size;
    void *buffer = (void *)(uintptr_t)buf_arg->buffer;

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ops->get_entropy(buffer, size);
    if (ret != CRYPTO_SUCCESS)
        tloge("generate random failed\n");

    do_power_off(ops);

    return ret;
}

int32_t get_entropy_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    uint8_t *get_entropy_share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &get_entropy_share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = get_entropy_ops(ops, buf_arg);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)get_entropy_share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        tloge("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(get_entropy_share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return CRYPTO_SUCCESS;
}
