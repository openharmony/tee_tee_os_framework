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
#include "crypto_syscall_pm.h"

#include <tee_log.h>
#include "crypto_driver_adaptor.h"

int32_t crypto_mgr_suspend_call(const struct crypto_drv_ops_t *ops)
{
    if (ops == NULL) {
        tloge("hardware engine register failed\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    if (ops->suspend == NULL) {
        tlogd("crypto engine not need suspend\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = ops->suspend();
    if (ret != CRYPTO_SUCCESS)
        tloge("crypto_mgr suspend failed\n");

    return ret;
}

int32_t crypto_mgr_resume_call(const struct crypto_drv_ops_t *ops)
{
    if (ops == NULL) {
        tloge("hardware engine register failed\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    if (ops->resume == NULL) {
        tlogd("crypto engine not need resume\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = ops->resume();
    if (ret != CRYPTO_SUCCESS)
        tloge("crypto_mgr resume failed\n");

    return ret;
}
