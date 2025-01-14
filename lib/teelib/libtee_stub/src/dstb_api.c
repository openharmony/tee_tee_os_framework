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
#include <dstb_api.h>

TEE_Result tee_dstb_gen_sharekey(struct device_info *device_info, const uint8_t *salt, uint32_t salt_len,
    const uint8_t *info, uint32_t info_len, uint8_t *key, uint32_t key_len)
{   
    (void)device_info;
    (void)salt;
    (void)salt_len;
    (void)info;
    (void)info_len;
    (void)key;
    (void)key_len;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_dstb_pre_attestation(struct device_info *device_info, uint32_t cond)
{
    (void)device_info;
    (void)cond;
    return TEE_ERROR_NOT_SUPPORTED;
}