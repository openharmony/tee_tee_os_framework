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
#include <securec.h>
#include <tee_log.h>
#include "crypto_wrapper.h"

TEE_Result aes_key_wrap(struct cdrm_params *params)
{
    (void)params;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result aes_key_unwrap(struct cdrm_params *params)
{
    (void)params;
    return TEE_ERROR_NOT_SUPPORTED;
}
