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

static int32_t ae_init_ops(const struct drv_data *drv, const struct crypto_drv_ops_t *ops,
    const struct crypto_ioctl *ioctl)
{
    int32_t ret;
    uint32_t alg_type = ioctl->arg1;
    uint32_t direction = ioctl->arg2;

    if (ops->ae_init == NULL || drv->private_data == NULL) {
        tloge("hardware engine ae init fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct symmerit_key_t key;
    key.key_buffer = (uint64_t)(uintptr_t)ioctl->data_1;
    key.key_size = ioctl->data_size_1;
    key.key_type = ioctl->arg3;

    struct ae_init_data ae_init_param;
    ae_init_param.nonce = (uint64_t)(uintptr_t)ioctl->data_2;
    ae_init_param.nonce_len = ioctl->data_size_2;
    ae_init_param.tag_len = ioctl->arg4;
    ae_init_param.aad_len = ioctl->arg5;
    ae_init_param.payload_len = ioctl->arg6;

    ret = ops->ae_init(alg_type, drv->private_data, direction, &key, &ae_init_param);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do ae init failed. ret = %d\n", ret);
        return ret;
    }

    return ret;
}

int32_t ae_init_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = ae_init_ops(drv, ops, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        tloge("ae init ops fail\n");

    return ret;
}

static int32_t ae_update_aad_ops(const struct drv_data *drv, const struct crypto_drv_ops_t *ops,
    struct crypto_ioctl *crypto_arg)
{
    int32_t ret;
    if (ops->ae_update_aad == NULL || drv->private_data == NULL) {
        tloge("hardware engine ae update aad fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t aad;
    aad.buffer = (uint64_t)(uintptr_t)crypto_arg->data_1;
    aad.size = crypto_arg->data_size_1;

    ret = ops->ae_update_aad(drv->private_data, &aad);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do ae update aad failed. ret = %d\n", ret);
        return ret;
    }

    return ret;
}

int32_t ae_update_aad_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = ae_update_aad_ops(drv, ops, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        tloge("ae update fail\n");

    return ret;
}

static int32_t ae_update_ops(const struct drv_data *drv, const struct crypto_drv_ops_t *ops,
    struct memref_t *crypto_arg)
{
    int32_t ret;
    if (ops->ae_update == NULL || drv->private_data == NULL) {
        tloge("hardware engine ae update fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t data_out;
    data_out.buffer = crypto_arg->buffer;
    data_out.size = crypto_arg->size;

    crypto_arg++;
    struct memref_t data_in;
    data_in.buffer = crypto_arg->buffer;
    data_in.size = crypto_arg->size;

    ret = ops->ae_update(drv->private_data, &data_in, &data_out);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do ae update failed. ret = %d\n", ret);
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

int32_t ae_update_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ae_update_ops(drv, ops, buf_arg);
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

static void ae_enc_final_ops_prepare_parms(const struct memref_t *crypto_arg, struct memref_t *data_out,
    struct memref_t *tag_out, struct memref_t *data_in)
{
    data_out->buffer = crypto_arg->buffer;
    data_out->size = crypto_arg->size;

    crypto_arg++;
    tag_out->buffer = crypto_arg->buffer;
    tag_out->size = crypto_arg->size;

    crypto_arg++;
    data_in->buffer = crypto_arg->buffer;
    data_in->size = crypto_arg->size;
}

static int32_t ae_enc_final_ops(const struct drv_data *drv,
    const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg)
{
    if (ops->ae_enc_final == NULL || drv->private_data == NULL) {
        tloge("hardware engine ae enc final fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t data_out = {0};
    struct memref_t tag_out = {0};
    struct memref_t data_in = {0};

    ae_enc_final_ops_prepare_parms(crypto_arg, &data_out, &tag_out, &data_in);

    ret = ops->ae_enc_final(drv->private_data, &data_in, &data_out, &tag_out);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do ae enc final failed. ret = %d\n", ret);
        return ret;
    }

    if (data_out.size > crypto_arg->size) {
        tloge("new data out size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, data_out.size);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    crypto_arg->size = data_out.size;

    crypto_arg++;
    if (tag_out.size > crypto_arg->size) {
        tloge("new tag out size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, tag_out.size);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    crypto_arg->size = tag_out.size;

    return ret;
}

int32_t ae_enc_final_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ae_enc_final_ops(drv, ops, buf_arg);
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

static int32_t ae_dec_final_ops(const struct drv_data *drv,
    const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg)
{
    int32_t ret;
    if (ops->ae_dec_final == NULL || drv->private_data == NULL) {
        tloge("hardware engine ae dec final fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t *temp_crypto_arg = crypto_arg;

    struct memref_t data_out;
    data_out.buffer = temp_crypto_arg->buffer;
    data_out.size = temp_crypto_arg->size;

    temp_crypto_arg++;
    struct memref_t data_in;
    data_in.buffer = temp_crypto_arg->buffer;
    data_in.size = temp_crypto_arg->size;

    temp_crypto_arg++;
    struct memref_t tag_in;
    tag_in.buffer = temp_crypto_arg->buffer;
    tag_in.size = temp_crypto_arg->size;

    ret = ops->ae_dec_final(drv->private_data, &data_in, &tag_in, &data_out);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do ae dec final failed. ret = %d\n", ret);
        return ret;
    }

    if (data_out.size > crypto_arg->size) {
        tloge("new data out size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, data_out.size);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    crypto_arg->size = data_out.size;

    return ret;
}

int32_t ae_dec_final_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ae_dec_final_ops(drv, ops, buf_arg);
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
