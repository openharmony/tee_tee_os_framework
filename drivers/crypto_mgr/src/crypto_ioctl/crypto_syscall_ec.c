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
#include "crypto_syscall_ec.h"
#include <securec.h>
#include "tee_driver_module.h"
#include <tee_log.h>
#include "drv_param_ops.h"

int32_t check_ecc_pub_key_len(const struct ecc_pub_key_t *ecc_pub_key)
{
    if (ecc_pub_key == NULL) {
        tloge("ecc public key is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (ecc_pub_key->x_len > ECC_KEY_LEN || ecc_pub_key->y_len > ECC_KEY_LEN) {
        tloge("ecc public key size is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

int32_t check_ecc_private_key_len(const struct ecc_priv_key_t *ecc_private_key)
{
    if (ecc_private_key == NULL) {
        tloge("ecc private key is NULL\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (ecc_private_key->r_len > ECC_KEY_LEN) {
        tloge("ecc private key size is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

static int32_t ecc_generate_keypair_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg,
    uint32_t key_size, uint32_t curve)
{
    if (ops->ecc_generate_keypair == NULL) {
        tloge("hardware engine ecc generate keypair fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct ecc_pub_key_t *public_key = (struct ecc_pub_key_t *)(uintptr_t)crypto_arg->buffer;
    ret = check_ecc_pub_key_len(public_key);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    crypto_arg++;
    struct ecc_priv_key_t *private_key = (struct ecc_priv_key_t *)(uintptr_t)crypto_arg->buffer;
    ret = check_ecc_private_key_len(private_key);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ops->ecc_generate_keypair(key_size, curve, public_key, private_key);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS)
        tloge("hardware engine do ecc generate keypair failed. ret = %d\n", ret);

    return ret;
}

int32_t ecc_generate_keypair_call(const struct drv_data *drv, unsigned long args,
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

    ret = ecc_generate_keypair_ops(ops, buf_arg, ioctl_args->arg1, ioctl_args->arg2);
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

static int32_t ecc_encrypt_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg, uint32_t alg_type)
{
    if (ops->ecc_encrypt == NULL) {
        tloge("hardware engine ecc encrypt fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t *ecc_encrypt_arg = crypto_arg;
    struct memref_t data_out;
    data_out.buffer = ecc_encrypt_arg->buffer;
    data_out.size = ecc_encrypt_arg->size;

    ecc_encrypt_arg++;
    struct memref_t data_in;
    data_in.buffer = ecc_encrypt_arg->buffer;
    data_in.size = ecc_encrypt_arg->size;

    ecc_encrypt_arg++;
    struct ecc_pub_key_t *public_key = (struct ecc_pub_key_t *)(uintptr_t)ecc_encrypt_arg->buffer;
    ret = check_ecc_pub_key_len(public_key);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ecc_encrypt_arg++;
    struct asymmetric_params_t ec_params;
    ret = restore_attrs(&ec_params, ecc_encrypt_arg);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ops->ecc_encrypt(alg_type, public_key, &ec_params, &data_in, &data_out);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do ecc encrypt failed. ret = %d\n", ret);
        goto end;
    }

    if (data_out.size > crypto_arg->size) {
        tloge("new data out size > origin size. origin size = %u, new size = %u\n", crypto_arg->size, data_out.size);
        ret = CRYPTO_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    crypto_arg->size = data_out.size;

end:
    if (ec_params.attribute != 0)
        free((void *)(uintptr_t)ec_params.attribute);

    return ret;
}

int32_t ecc_encrypt_call(const struct drv_data *drv, unsigned long args,
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

    ret = ecc_encrypt_ops(ops, buf_arg, ioctl_args->arg1);
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

static int32_t ecc_decrypt_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg, uint32_t alg_type)
{
    if (ops->ecc_decrypt == NULL) {
        tloge("hardware engine ecc decrypt fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t *ecc_decrypt_arg = crypto_arg;
    struct memref_t data_out;
    data_out.buffer = ecc_decrypt_arg->buffer;
    data_out.size = ecc_decrypt_arg->size;

    ecc_decrypt_arg++;
    struct memref_t data_in;
    data_in.buffer = ecc_decrypt_arg->buffer;
    data_in.size = ecc_decrypt_arg->size;

    ecc_decrypt_arg++;
    struct ecc_priv_key_t *private_key = (struct ecc_priv_key_t *)(uintptr_t)ecc_decrypt_arg->buffer;
    ret = check_ecc_private_key_len(private_key);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ecc_decrypt_arg++;
    struct asymmetric_params_t ec_params;
    ret = restore_attrs(&ec_params, ecc_decrypt_arg);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ops->ecc_decrypt(alg_type, private_key, &ec_params, &data_in, &data_out);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do ecc decrypt failed. ret = %d\n", ret);
        goto end;
    }

    if (data_out.size > crypto_arg->size) {
        tloge("new data out size > origin size! origin size = %u, new size = %u\n", crypto_arg->size, data_out.size);
        ret = CRYPTO_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    crypto_arg->size = data_out.size;

end:
    if (ec_params.attribute != 0)
        free((void *)(uintptr_t)ec_params.attribute);

    return ret;
}

int32_t ecc_decrypt_call(const struct drv_data *drv, unsigned long args,
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

    ret = ecc_decrypt_ops(ops, buf_arg, ioctl_args->arg1);
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

static int32_t ecc_sign_digest_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg, uint32_t alg_type)
{
    if (ops->ecc_sign_digest == NULL) {
        tloge("hardware engine ecc sign digest fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t *ecc_sign_digest_arg = crypto_arg;
    struct memref_t signature;
    signature.buffer = ecc_sign_digest_arg->buffer;
    signature.size = ecc_sign_digest_arg->size;

    ecc_sign_digest_arg++;
    struct memref_t digest;
    digest.buffer = ecc_sign_digest_arg->buffer;
    digest.size = ecc_sign_digest_arg->size;

    ecc_sign_digest_arg++;
    struct ecc_priv_key_t *private_key = (struct ecc_priv_key_t *)(uintptr_t)ecc_sign_digest_arg->buffer;
    ret = check_ecc_private_key_len(private_key);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ecc_sign_digest_arg++;
    struct asymmetric_params_t ec_params;
    ret = restore_attrs(&ec_params, ecc_sign_digest_arg);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ops->ecc_sign_digest(alg_type, private_key, &ec_params, &digest, &signature);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS) {
        tloge("hardware engine do ecc sign digest failed. ret = %d\n", ret);
        goto end;
    }

    if (signature.size > crypto_arg->size) {
        tloge("new signature size > origin size. origin size = %u, new size = %u\n",
            crypto_arg->size, signature.size);
        ret = CRYPTO_ERROR_OUT_OF_MEMORY;
        goto end;
    }
    crypto_arg->size = signature.size;

end:
    if (ec_params.attribute != 0)
        free((void *)(uintptr_t)ec_params.attribute);

    return ret;
}

int32_t ecc_sign_digest_call(const struct drv_data *drv, unsigned long args,
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

    ret = ecc_sign_digest_ops(ops, buf_arg, ioctl_args->arg1);
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

static int32_t ecc_verify_digest_ops(const struct crypto_drv_ops_t *ops, struct memref_t *crypto_arg, uint32_t alg_type)
{
    if (ops->ecc_verify_digest == NULL) {
        tloge("hardware engine ecc verify digest fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    struct memref_t *ecc_verify_digest_arg = crypto_arg;
    struct memref_t signature;
    signature.buffer = ecc_verify_digest_arg->buffer;
    signature.size = ecc_verify_digest_arg->size;

    ecc_verify_digest_arg++;
    struct memref_t digest;
    digest.buffer = ecc_verify_digest_arg->buffer;
    digest.size = ecc_verify_digest_arg->size;

    ecc_verify_digest_arg++;
    struct ecc_pub_key_t *public_key = (struct ecc_pub_key_t *)(uintptr_t)ecc_verify_digest_arg->buffer;
    ret = check_ecc_pub_key_len(public_key);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ecc_verify_digest_arg++;
    struct asymmetric_params_t ec_params;
    ret = restore_attrs(&ec_params, ecc_verify_digest_arg);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ops->ecc_verify_digest(alg_type, public_key, &ec_params, &digest, &signature);
    do_power_off(ops);
    if (ret != CRYPTO_SUCCESS)
        tloge("hardware engine do ecc verify digest failed. ret = %d\n", ret);

    if (ec_params.attribute != 0)
        free((void *)(uintptr_t)ec_params.attribute);

    return ret;
}

int32_t ecc_verify_digest_call(const struct drv_data *drv, unsigned long args,
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

    ret = ecc_verify_digest_ops(ops, buf_arg, ioctl_args->arg1);
    if (ret != CRYPTO_SUCCESS)
        tloge("ecc verify digest ops. ret = %d\n", ret);

    driver_free_share_mem_and_buf_arg(share_buf, ioctl_args->buf_len, buf_arg,
        ioctl_args->total_nums * sizeof(struct memref_t));
    return ret;
}
