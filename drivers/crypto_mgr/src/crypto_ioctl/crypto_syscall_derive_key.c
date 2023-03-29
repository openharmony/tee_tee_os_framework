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
#include "crypto_syscall_ec.h"

static int32_t ecdh_derive_key_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg, uint32_t alg_type)
{
    if (ops->ecdh_derive_key == NULL) {
        tloge("hardware engine ecdh derive key fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t *ecdh_arg = crypto_arg;
    struct memref_t secret;
    secret.buffer = ecdh_arg->buffer;
    secret.size = ecdh_arg->size;

    ecdh_arg++;
    struct ecc_pub_key_t *client_key = (struct ecc_pub_key_t *)(uintptr_t)ecdh_arg->buffer;
    ret = check_ecc_pub_key_len(client_key);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ecdh_arg++;
    struct ecc_priv_key_t *server_key = (struct ecc_priv_key_t *)(uintptr_t)ecdh_arg->buffer;
    ret = check_ecc_private_key_len(server_key);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ecdh_arg++;
    struct asymmetric_params_t ec_params;
    ret = restore_attrs(&ec_params, ecdh_arg);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ops->ecdh_derive_key(alg_type, client_key, server_key, &ec_params, &secret);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do ecdh derive key failed. ret = %d\n", ret);
        goto end;
    }

    if (secret.size > crypto_arg->size) {
        tloge("new secret size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, secret.size);
        goto end;
    }
    crypto_arg->size = secret.size;

end:
    if (ec_params.attribute != 0)
        free((void *)(uintptr_t)ec_params.attribute);

    return ret;
}

int32_t ecdh_derive_key_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *ecdh_buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &share_buf, &ecdh_buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ecdh_derive_key_ops(ops, ecdh_buf_arg, ioctl_args->arg1);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = fill_share_mem(share_buf, ecdh_buf_arg, ioctl_args->total_nums);
    if (ret != CRYPTO_SUCCESS)
        goto end;
    ret = copy_to_client((uintptr_t)share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        tloge("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, ecdh_buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t dh_generate_key_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg, uint32_t l,
    uint32_t dh_mode)
{
    if (ops->dh_generate_key == NULL) {
        tloge("hardware engine dh generate key fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t *dh_generate_arg = crypto_arg;
    struct memref_t pub_key;
    pub_key.buffer = dh_generate_arg->buffer;
    pub_key.size = dh_generate_arg->size;

    dh_generate_arg++;
    struct memref_t priv_key;
    priv_key.buffer = dh_generate_arg->buffer;
    priv_key.size = dh_generate_arg->size;

    dh_generate_arg++;
    struct dh_key_t dh_generate_key_data;
    dh_generate_key_data.prime = dh_generate_arg->buffer;
    dh_generate_key_data.prime_size = dh_generate_arg->size;

    dh_generate_arg++;
    dh_generate_key_data.generator = dh_generate_arg->buffer;
    dh_generate_key_data.generator_size = dh_generate_arg->size;

    dh_generate_arg++;
    dh_generate_key_data.dh_param.generate_key_t.q = dh_generate_arg->buffer;
    dh_generate_key_data.dh_param.generate_key_t.q_size = dh_generate_arg->size;
    dh_generate_key_data.dh_param.generate_key_t.l = l;
    dh_generate_key_data.dh_param.generate_key_t.dh_mode = dh_mode;

    ret = ops->dh_generate_key(&dh_generate_key_data, &pub_key, &priv_key);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do dh generate key failed. ret = %d\n", ret);
        return ret;
    }

    if (pub_key.size > crypto_arg->size) {
        tloge("new pub_key size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, pub_key.size);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    crypto_arg->size = pub_key.size;

    crypto_arg++;
    if (priv_key.size > crypto_arg->size) {
        tloge("new priv_key size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, priv_key.size);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    crypto_arg->size = priv_key.size;
    return ret;
}

int32_t dh_generate_key_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *dh_generate_buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &share_buf, &dh_generate_buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = dh_generate_key_ops(ops, dh_generate_buf_arg, ioctl_args->arg1, ioctl_args->arg2);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = fill_share_mem(share_buf, dh_generate_buf_arg, ioctl_args->total_nums);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        tloge("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, dh_generate_buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t dh_derive_key_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg)
{
    if (ops->dh_derive_key == NULL) {
        tloge("hardware engine dh derive key fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t *dh_derive_arg = crypto_arg;
    struct memref_t secret;
    secret.buffer = dh_derive_arg->buffer;
    secret.size = dh_derive_arg->size;

    dh_derive_arg++;
    struct dh_key_t dh_derive_key_data;
    dh_derive_key_data.prime = dh_derive_arg->buffer;
    dh_derive_key_data.prime_size = dh_derive_arg->size;

    dh_derive_arg++;
    dh_derive_key_data.generator = dh_derive_arg->buffer;
    dh_derive_key_data.generator_size = dh_derive_arg->size;

    dh_derive_arg++;
    dh_derive_key_data.dh_param.derive_key_t.pub_key = dh_derive_arg->buffer;
    dh_derive_key_data.dh_param.derive_key_t.pub_key_size = dh_derive_arg->size;

    dh_derive_arg++;
    dh_derive_key_data.dh_param.derive_key_t.priv_key = dh_derive_arg->buffer;
    dh_derive_key_data.dh_param.derive_key_t.priv_key_size = dh_derive_arg->size;

    ret = ops->dh_derive_key(&dh_derive_key_data, &secret);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do dh derive key failed. ret = %d\n", ret);
        return ret;
    }

    if (secret.size > crypto_arg->size) {
        tloge("new secret size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, secret.size);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    crypto_arg->size = secret.size;
    return ret;
}

int32_t dh_derive_key_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *dh_derive_buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &share_buf, &dh_derive_buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = dh_derive_key_ops(ops, dh_derive_buf_arg);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = fill_share_mem(share_buf, dh_derive_buf_arg, ioctl_args->total_nums);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        tloge("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, dh_derive_buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t derive_root_key(const struct crypto_drv_ops_t *ops, uint32_t key_type,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    if (data_in == NULL || data_out == NULL) {
        tloge("invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (ops->derive_root_key == NULL) {
        tloge("hardware engine derive root key fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ops->derive_root_key(key_type, data_in, data_out);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do derive root key failed. ret = %d\n", ret);
        return ret;
    }

    return ret;
}

#define DX_ROOT_KEY_SIZE 16
static int32_t do_derive_iter(const struct crypto_drv_ops_t *ops, uint32_t key_type,
    const struct memref_t *temp_in, struct memref_t *data_out, uint32_t iter_num)
{
    int32_t ret;

    if (temp_in->size < DX_ROOT_KEY_SIZE)
        return CRYPTO_BAD_PARAMETERS;

    for (uint32_t i = 0; i < iter_num; i++) {
        ret = (uint32_t)derive_root_key(ops, key_type, temp_in, data_out);
        if (ret != CRYPTO_SUCCESS)
            break;

        int32_t rc = memcpy_s((uint8_t *)(uintptr_t)temp_in->buffer, temp_in->size,
            (uint8_t *)(uintptr_t)data_out->buffer, data_out->size);
        if (rc != EOK) {
            ret = CRYPTO_ERROR_SECURITY;
            break;
        }
    }

    return ret;
}

static int32_t hw_derive_root_key_iter(const struct crypto_drv_ops_t *ops, uint32_t key_type,
    const struct memref_t *data_in, struct memref_t *data_out, uint32_t iter_num)
{
    int32_t ret;

    if (data_in == NULL || data_out == NULL || data_in->size == 0)
        return CRYPTO_BAD_PARAMETERS;

    uint8_t *temp_in_buff = malloc(data_in->size);
    if (temp_in_buff == NULL)
        return CRYPTO_BAD_PARAMETERS;

    (void)memcpy_s(temp_in_buff, data_in->size, (uint8_t *)(uintptr_t)data_in->buffer, data_in->size);
    struct memref_t temp_in = {0};
    temp_in.buffer = (uint64_t)(uintptr_t)temp_in_buff;
    temp_in.size = data_in->size;

    if (iter_num == 1)
        ret = (uint32_t)derive_root_key(ops, key_type, &temp_in, data_out);
    else
        ret = do_derive_iter(ops, key_type, &temp_in, data_out, iter_num);

    free(temp_in_buff);
    return ret;
}

static int32_t hw_derive_root_key_ops(const struct crypto_drv_ops_t *ops,
    struct memref_t *buf_arg, const struct crypto_ioctl *ioctl_args)
{
    struct memref_t data_out;
    struct memref_t data_in;
    uint32_t derive_type = ioctl_args->arg1;
    uint32_t iter_num = ioctl_args->arg2;

    data_out.buffer = buf_arg->buffer;
    data_out.size = buf_arg->size;
    buf_arg++;
    data_in.buffer = buf_arg->buffer;
    data_in.size = buf_arg->size;

    int32_t ret = hw_derive_root_key_iter(ops, derive_type, &data_in, &data_out, iter_num);
    if (ret != CRYPTO_SUCCESS) {
        tloge("derive root key iter fail\n");
        return ret;
    }
    buf_arg--;
    if (data_out.size > buf_arg->size) {
        tloge("new data out size > origin size. origin size = %u, new size = %u\n", buf_arg->size, data_out.size);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    buf_arg->size = data_out.size;
    return ret;
}

int32_t derive_root_key_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *derive_buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &share_buf, &derive_buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = hw_derive_root_key_ops(ops, derive_buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS) {
        tloge("derive root key failed. ret = %d", ret);
        goto end;
    }

    ret = copy_to_client((uintptr_t)share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        tloge("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, derive_buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t pbkdf2_fun_ops(const struct crypto_drv_ops_t *ops,
    struct memref_t *buf_arg, const struct crypto_ioctl *ioctl_args)
{
    if (ops->pbkdf2 == NULL) {
        tloge("hardware engine pbkdf2 fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    struct memref_t data_out;
    struct memref_t salt;
    struct memref_t password;

    uint32_t iterations = ioctl_args->arg1;
    uint32_t digest_type = ioctl_args->arg2;

    struct memref_t *tmp_buf_arg = buf_arg;
    data_out.buffer = tmp_buf_arg->buffer;
    data_out.size = tmp_buf_arg->size;

    tmp_buf_arg++;
    salt.buffer = tmp_buf_arg->buffer;
    salt.size = tmp_buf_arg->size;

    tmp_buf_arg++;
    password.buffer = tmp_buf_arg->buffer;
    password.size = tmp_buf_arg->size;

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ops->pbkdf2(&password, &salt, iterations, digest_type, &data_out);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do pbkdf2 failed. ret = %d\n", ret);
        return ret;
    }

    if (data_out.size > tmp_buf_arg->size) {
        tloge("new data out size > origin size. origin size = %u, new size = %u\n",
            tmp_buf_arg->size, data_out.size);
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    tmp_buf_arg->size = data_out.size;
    return ret;
}

int32_t pbkdf2_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops)
{
    uint8_t *share_buf = NULL;
    struct memref_t *pbkdf2_buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &share_buf, &pbkdf2_buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = pbkdf2_fun_ops(ops, pbkdf2_buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        tloge("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, pbkdf2_buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}
