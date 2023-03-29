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
#include "crypto_syscall_rsa.h"
#include <securec.h>
#include "tee_driver_module.h"
#include <tee_log.h>
#include "drv_param_ops.h"

static int32_t check_rsa_private_key_len(const struct rsa_priv_key_t *rsa_private_key)
{
    if (rsa_private_key == NULL) {
        tloge("rsa private key is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    bool check = (rsa_private_key->e_len > RSA_EXPONENT_LEN ||
        rsa_private_key->n_len > RSA_MAX_KEY_SIZE || rsa_private_key->d_len > RSA_MAX_KEY_SIZE ||
        rsa_private_key->p_len > RSA_MAX_KEY_SIZE_CRT || rsa_private_key->q_len > RSA_MAX_KEY_SIZE_CRT ||
        rsa_private_key->dp_len > RSA_MAX_KEY_SIZE_CRT || rsa_private_key->dq_len > RSA_MAX_KEY_SIZE_CRT ||
        rsa_private_key->qinv_len > RSA_MAX_KEY_SIZE_CRT);
    if (check) {
        tloge("rsa private key size is invalid\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

static int32_t check_rsa_pub_key_len(const struct rsa_pub_key_t *rsa_pub_key)
{
    if (rsa_pub_key == NULL) {
        tloge("rsa pub key is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (rsa_pub_key->e_len > RSA_EXPONENT_LEN || rsa_pub_key->n_len > RSA_MAX_KEY_SIZE) {
        tloge("rsa pub key size is invalid\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

static int32_t rsa_generate_keypair_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg,
    uint32_t key_size, bool crt_mode)
{
    if (ops->rsa_generate_keypair == NULL) {
        tloge("hardware engine rsa generate keypair fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct rsa_priv_key_t *key_pair = (struct rsa_priv_key_t *)(uintptr_t)crypto_arg->buffer;
    ret = check_rsa_private_key_len(key_pair);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    crypto_arg++;
    struct memref_t e_value;
    e_value.buffer = crypto_arg->buffer;
    e_value.size = crypto_arg->size;

    ret = ops->rsa_generate_keypair(key_size, &e_value, crt_mode, key_pair);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS)
        tloge("hardware engine do rsa generate keypair failed. ret = %d\n", ret);

    return ret;
}

int32_t rsa_generate_keypair_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    uint8_t *rsa_gen_share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &rsa_gen_share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = rsa_generate_keypair_ops(ops, buf_arg, ioctl_args->arg1, (bool)ioctl_args->arg2);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)rsa_gen_share_buf, ioctl_args->buf_len, ioctl_args->buf,
        ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        tloge("copy to client failed. ret = %d\n", ret);
end:
    driver_free_share_mem_and_buf_arg(rsa_gen_share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t rsa_encrypt_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg, uint32_t alg_type)
{
    if (ops->rsa_encrypt == NULL) {
        tloge("hardware engine rsa encrypt fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t *rsa_encrypt_arg = crypto_arg;
    struct memref_t data_out;
    data_out.buffer = rsa_encrypt_arg->buffer;
    data_out.size = rsa_encrypt_arg->size;

    rsa_encrypt_arg++;
    struct memref_t data_in;
    data_in.buffer = rsa_encrypt_arg->buffer;
    data_in.size = rsa_encrypt_arg->size;

    rsa_encrypt_arg++;
    struct rsa_pub_key_t *rsa_pub_key = (struct rsa_pub_key_t *)(uintptr_t)rsa_encrypt_arg->buffer;
    ret = check_rsa_pub_key_len(rsa_pub_key);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    rsa_encrypt_arg++;
    struct asymmetric_params_t rsa_params;
    ret = restore_attrs(&rsa_params, rsa_encrypt_arg);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ops->rsa_encrypt(alg_type, rsa_pub_key, &rsa_params, &data_in, &data_out);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do rsa encrypt failed. ret = %d\n", ret);
        goto end;
    }

    if (data_out.size > crypto_arg->size) {
        tloge("new data out size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, data_out.size);
        ret = CRYPTO_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    crypto_arg->size = data_out.size;

end:
    if (rsa_params.attribute != 0)
        free((void *)(uintptr_t)rsa_params.attribute);

    return ret;
}

int32_t rsa_encrypt_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    uint8_t *rsa_encrypt_share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &rsa_encrypt_share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = rsa_encrypt_ops(ops, buf_arg, ioctl_args->arg1);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = fill_share_mem(rsa_encrypt_share_buf, buf_arg, ioctl_args->total_nums);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)rsa_encrypt_share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        tloge("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(rsa_encrypt_share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t rsa_decrypt_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg, uint32_t alg_type)
{
    if (ops->rsa_decrypt == NULL) {
        tloge("hardware engine rsa decrypt fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t *rsa_decrypt_arg = crypto_arg;
    struct memref_t data_out;
    data_out.buffer = rsa_decrypt_arg->buffer;
    data_out.size = rsa_decrypt_arg->size;

    rsa_decrypt_arg++;
    struct memref_t data_in;
    data_in.buffer = rsa_decrypt_arg->buffer;
    data_in.size = rsa_decrypt_arg->size;

    rsa_decrypt_arg++;
    struct rsa_priv_key_t *private_key = (struct rsa_priv_key_t *)(uintptr_t)rsa_decrypt_arg->buffer;
    ret = check_rsa_private_key_len(private_key);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    rsa_decrypt_arg++;
    struct asymmetric_params_t rsa_params;
    ret = restore_attrs(&rsa_params, rsa_decrypt_arg);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ops->rsa_decrypt(alg_type, private_key, &rsa_params, &data_in, &data_out);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do rsa decrypt failed. ret = %d\n", ret);
        goto end;
    }

    if (data_out.size > crypto_arg->size) {
        tloge("new data out size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, data_out.size);
        ret = CRYPTO_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    crypto_arg->size = data_out.size;

end:
    if (rsa_params.attribute != 0)
        free((void *)(uintptr_t)rsa_params.attribute);

    return ret;
}

int32_t rsa_decrypt_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    uint8_t *rsa_decrypt_share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &rsa_decrypt_share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = rsa_decrypt_ops(ops, buf_arg, ioctl_args->arg1);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = fill_share_mem(rsa_decrypt_share_buf, buf_arg, ioctl_args->total_nums);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)rsa_decrypt_share_buf, ioctl_args->buf_len, ioctl_args->buf, ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        tloge("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(rsa_decrypt_share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t rsa_sign_digest_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg, uint32_t alg_type)
{
    if (ops->rsa_sign_digest == NULL) {
        tloge("hardware engine rsa sign digest fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t *rsa_sign_digest_arg = crypto_arg;
    struct memref_t signature;
    signature.buffer = rsa_sign_digest_arg->buffer;
    signature.size = rsa_sign_digest_arg->size;

    rsa_sign_digest_arg++;
    struct memref_t digest;
    digest.buffer = rsa_sign_digest_arg->buffer;
    digest.size = rsa_sign_digest_arg->size;

    rsa_sign_digest_arg++;
    struct rsa_priv_key_t *private_key = (struct rsa_priv_key_t *)(uintptr_t)rsa_sign_digest_arg->buffer;
    ret = check_rsa_private_key_len(private_key);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    rsa_sign_digest_arg++;
    struct asymmetric_params_t rsa_params;
    ret = restore_attrs(&rsa_params, rsa_sign_digest_arg);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ops->rsa_sign_digest(alg_type, private_key, &rsa_params, &digest, &signature);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do rsa sign digest failed. ret = %d\n", ret);
        goto end;
    }

    if (signature.size > crypto_arg->size) {
        tloge("new signature > origin size. origin size = %u, new size = %u\n", crypto_arg->size, signature.size);
        ret = CRYPTO_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    crypto_arg->size = signature.size;

end:
    if (rsa_params.attribute != 0)
        free((void *)(uintptr_t)rsa_params.attribute);

    return ret;
}

int32_t rsa_sign_digest_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    uint8_t *rsa_sign_share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &rsa_sign_share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = rsa_sign_digest_ops(ops, buf_arg, ioctl_args->arg1);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = fill_share_mem(rsa_sign_share_buf, buf_arg, ioctl_args->total_nums);
    if (ret != CRYPTO_SUCCESS)
        goto end;

    ret = copy_to_client((uintptr_t)rsa_sign_share_buf, ioctl_args->buf_len, ioctl_args->buf,
        ioctl_args->buf_len);
    if (ret != CRYPTO_SUCCESS)
        tloge("copy to client failed. ret = %d\n", ret);

end:
    driver_free_share_mem_and_buf_arg(rsa_sign_share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}

static int32_t rsa_verify_digest_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg, uint32_t alg_type)
{
    if (ops->rsa_verify_digest == NULL) {
        tloge("hardware engine rsa verify digest fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t *rsa_verify_digest_arg = crypto_arg;
    struct memref_t signature;
    signature.buffer = rsa_verify_digest_arg->buffer;
    signature.size = rsa_verify_digest_arg->size;

    rsa_verify_digest_arg++;
    struct memref_t digest;
    digest.buffer = rsa_verify_digest_arg->buffer;
    digest.size = rsa_verify_digest_arg->size;

    rsa_verify_digest_arg++;
    struct rsa_pub_key_t *rsa_pub_key = (struct rsa_pub_key_t *)(uintptr_t)rsa_verify_digest_arg->buffer;
    ret = check_rsa_pub_key_len(rsa_pub_key);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    rsa_verify_digest_arg++;
    struct asymmetric_params_t rsa_params;
    ret = restore_attrs(&rsa_params, rsa_verify_digest_arg);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ops->rsa_verify_digest(alg_type, rsa_pub_key, &rsa_params, &digest, &signature);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS)
        tloge("hardware engine do rsa verify digest failed. ret = %d\n", ret);

    if (rsa_params.attribute != 0)
        free((void *)(uintptr_t)rsa_params.attribute);

    return ret;
}

int32_t rsa_verify_digest_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops)
{
    uint8_t *rsa_verify_share_buf = NULL;
    struct memref_t *buf_arg = NULL;

    if (check_hal_params_is_invalid(drv, args, args_len, ops))
        return CRYPTO_BAD_PARAMETERS;

    struct crypto_ioctl *ioctl_args = (struct crypto_ioctl *)(uintptr_t)args;

    int32_t ret = prepare_hard_engine_params(drv->taskid, &rsa_verify_share_buf, &buf_arg, ioctl_args);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = rsa_verify_digest_ops(ops, buf_arg, ioctl_args->arg1);
    if (ret != CRYPTO_SUCCESS)
        tloge("rsa verify digest ops. ret = %d\n", ret);

    driver_free_share_mem_and_buf_arg(rsa_verify_share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}
