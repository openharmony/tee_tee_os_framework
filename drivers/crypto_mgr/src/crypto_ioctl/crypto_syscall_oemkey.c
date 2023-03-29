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
#include "crypto_syscall_oemkey.h"
#include <securec.h>
#include "tee_driver_module.h"
#include <tee_log.h>
#include "drv_param_ops.h"

static int32_t get_oemkey_ops(const struct crypto_drv_ops_t *ops, struct memref_t *buf_arg)
{
    if (ops->get_oemkey == NULL) {
        tloge("hardware engine get oemkey fun is null\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    void *buffer = NULL;
    size_t size;

    buffer = (void *)(uintptr_t)buf_arg->buffer;
    size = buf_arg->size;

    int32_t ret = do_power_on(ops);
    if (ret != CRYPTO_SUCCESS)
        return ret;

    ret = ops->get_oemkey(buffer, size);
    if (ret != CRYPTO_SUCCESS)
        tloge("get oemkey failed\n");

    do_power_off(ops);

    return ret;
}

int32_t get_oemkey_call(const struct drv_data *drv, unsigned long args,
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

    ret = get_oemkey_ops(ops, buf_arg);
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
