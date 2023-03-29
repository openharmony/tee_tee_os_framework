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
#include "crypto_syscall_common.h"
#include <securec.h>
#include "tee_driver_module.h"
#include <tee_log.h>
#include "drv_param_ops.h"

static int32_t cipher_init_ops(const struct drv_data *drv, const struct crypto_drv_ops_t *ops,
    struct crypto_ioctl *ioctl)
{
    if (ops->cipher_init == NULL || drv->private_data == NULL) {
        tloge("hardware engine cipher init fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    uint32_t driver_ability;
    uint32_t alg_type;

    driver_ability = ioctl->arg2;
    if ((driver_ability & DRIVER_PADDING) == DRIVER_PADDING)
        alg_type = ioctl->arg1;
    else
        alg_type = change_pkcs5_to_nopad(ioctl->arg1);

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct symmerit_key_t key;
    key.key_type = ioctl->arg4;
    key.key_buffer = (uint64_t)(uintptr_t)ioctl->data_1;
    key.key_size = ioctl->data_size_1;

    struct memref_t iv;
    iv.buffer = (uint64_t)(uintptr_t)ioctl->data_2;
    iv.size = ioctl->data_size_2;

    uint32_t direction = ioctl->arg3;
    ret = ops->cipher_init(alg_type, drv->private_data, direction, &key, &iv);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do hmac init failed. ret = %d\n", ret);
        return ret;
    }

    return ret;
}

int32_t cipher_init_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    return cipher_init_ops(drv, ops, ioctl_args);
}

static int32_t cipher_update_ops(const struct drv_data *drv,
    const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg)
{
    if (ops->cipher_update == NULL || drv->private_data == NULL) {
        tloge("hardware engine cipher update fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t data_out;
    data_out.buffer = crypto_arg->buffer;
    data_out.size = crypto_arg->size;

    crypto_arg++;
    struct memref_t data_in;
    data_in.buffer = crypto_arg->buffer;
    data_in.size = crypto_arg->size;

    ret = ops->cipher_update(drv->private_data, &data_in, &data_out);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do cipher update failed. ret = %d\n", ret);
        return ret;
    }

    crypto_arg--;
    if (data_out.size > crypto_arg->size) {
        tloge("new data out size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, data_out.size);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    crypto_arg->size = data_out.size;
    return ret;
}

int32_t cipher_update_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    uint8_t *cipher_update_share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &cipher_update_share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = cipher_update_ops(drv, ops, buf_arg);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = fill_share_mem(cipher_update_share_buf, buf_arg, ioctl_args->total_nums);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)cipher_update_share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        tloge("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(cipher_update_share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t cipher_dofinal_ops(const struct drv_data *drv,
    const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg)
{
    if (ops->cipher_dofinal == NULL || drv->private_data == NULL) {
        tloge("hardware engine cipher dofinal fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t data_out;
    data_out.size = crypto_arg->size;
    data_out.buffer = crypto_arg->buffer;

    crypto_arg++;
    struct memref_t data_in;
    data_in.size = crypto_arg->size;
    data_in.buffer = crypto_arg->buffer;

    ret = ops->cipher_dofinal(drv->private_data, &data_in, &data_out);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do cipher dofinal failed. ret = %d\n", ret);
        return ret;
    }

    crypto_arg--;
    if (data_out.size > crypto_arg->size) {
        tloge("new data out size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, data_out.size);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    crypto_arg->size = data_out.size;
    return ret;
}

int32_t cipher_dofinal_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    uint8_t *cipher_dofinal_share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &cipher_dofinal_share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = cipher_dofinal_ops(drv, ops, buf_arg);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = fill_share_mem(cipher_dofinal_share_buf, buf_arg, ioctl_args->total_nums);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)cipher_dofinal_share_buf, ioctl_args->buf_len, ioctl_args->buf,
        ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        tloge("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(cipher_dofinal_share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t cipher_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg,
    const struct crypto_ioctl *ioctl)
{
    if (ops->cipher == NULL) {
        tloge("hardware engine cipher fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    uint32_t alg_type = ioctl->arg1;
    uint32_t direction = ioctl->arg2;
    struct memref_t *temp_crypto_arg = crypto_arg;

    struct memref_t data_out;
    data_out.buffer = temp_crypto_arg->buffer;
    data_out.size = temp_crypto_arg->size;

    temp_crypto_arg++;
    struct memref_t data_in;
    data_in.buffer = temp_crypto_arg->buffer;
    data_in.size = temp_crypto_arg->size;

    temp_crypto_arg++;
    struct symmerit_key_t key;
    key.key_type = ioctl->arg3;
    key.key_buffer = temp_crypto_arg->buffer;
    key.key_size = temp_crypto_arg->size;

    temp_crypto_arg++;
    struct memref_t iv;
    iv.buffer = temp_crypto_arg->buffer;
    iv.size = temp_crypto_arg->size;

    ret = ops->cipher(alg_type, direction, &key, &data_in, &data_out, &iv);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do cipher failed. ret = %d\n", ret);
        return ret;
    }

    if (data_out.size > crypto_arg->size) {
        tloge("new data out size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, data_out.size);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    crypto_arg->size = data_out.size;

    return ret;
}

int32_t cipher_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    uint8_t *cipher_share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &cipher_share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = cipher_ops(ops, buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = fill_share_mem(cipher_share_buf, buf_arg, ioctl_args->total_nums);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)cipher_share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        tloge("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(cipher_share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}
