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
#include "crypto_syscall_hmac.h"
#include <securec.h>
#include <tee_log.h>
#include "drv_param_ops.h"

static int32_t hmac_init_ops(const struct drv_data *drv, const struct crypto_drv_ops_t *ops,
    struct memref_t *crypto_arg, const struct crypto_ioctl *ioctl)
{
    if (ops->hmac_init == NULL || drv->private_data == NULL) {
        tloge("hardware engine hmac init fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct symmerit_key_t key;
    key.key_type = ioctl->arg2;
    key.key_buffer = crypto_arg->buffer;
    key.key_size = crypto_arg->size;

    uint32_t alg_type = ioctl->arg1;
    ret = ops->hmac_init(alg_type, drv->private_data, &key);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do hmac init failed. ret = %d\n", ret);
        return ret;
    }

    return ret;
}

int32_t hmac_init_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = hmac_init_ops(drv, ops, buf_arg, ioctl_args);

    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t hmac_update_ops(const struct drv_data *drv,
    const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg)
{
    if (ops->hmac_update == NULL || drv->private_data == NULL) {
        tloge("hardware engine hmac update fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t data_in;
    data_in.buffer = crypto_arg->buffer;
    data_in.size = crypto_arg->size;

    ret = ops->hmac_update(drv->private_data, &data_in);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do hmac update failed. ret = %d\n", ret);
        return ret;
    }

    return ret;
}

int32_t hmac_update_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = hmac_update_ops(drv, ops, buf_arg);

    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t hmac_dofinal_ops(const struct drv_data *drv,
    const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg)
{
    if (ops->hmac_dofinal == NULL || drv->private_data == NULL) {
        tloge("hardware engine hmac dofinal fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t data_out;
    data_out.buffer = crypto_arg->buffer;
    data_out.size = crypto_arg->size;

    ret = ops->hmac_dofinal(drv->private_data, NULL, &data_out);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do hmac dofinal failed. ret = %d\n", ret);
        return ret;
    }

    if (data_out.size > crypto_arg->size) {
        tloge("new data out size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, data_out.size);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    crypto_arg->size = data_out.size;
    return ret;
}

int32_t hmac_dofinal_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = hmac_dofinal_ops(drv, ops, buf_arg);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = fill_share_mem(share_buf, buf_arg, ioctl_args->total_nums);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        tloge("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t hmac_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg,
    const struct crypto_ioctl *ioctl)
{
    if (ops->hmac == NULL) {
        tloge("hardware engine hmac fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    uint32_t alg_type = ioctl->arg1;
    struct memref_t *hmac_arg = crypto_arg;

    struct memref_t data_out;
    data_out.buffer = hmac_arg->buffer;
    data_out.size = hmac_arg->size;

    hmac_arg++;
    struct memref_t data_in;
    data_in.buffer = hmac_arg->buffer;
    data_in.size = hmac_arg->size;

    hmac_arg++;
    struct symmerit_key_t key;
    key.key_type = ioctl->arg2;
    key.key_buffer = hmac_arg->buffer;
    key.key_size = hmac_arg->size;

    ret = ops->hmac(alg_type, &key, &data_in, &data_out);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do hmac failed. ret = %d\n", ret);
        return ret;
    }

    if (data_out.size > crypto_arg->size) {
        tloge("new data out size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, data_out.size);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    crypto_arg->size = data_out.size;

    return ret;
}

int32_t hmac_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = hmac_ops(ops, buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = fill_share_mem(share_buf, buf_arg, ioctl_args->total_nums);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        tloge("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}
