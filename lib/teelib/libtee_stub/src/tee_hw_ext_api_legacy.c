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
#include "tee_hw_ext_api_legacy.h"

TEE_Result TEE_EXT_DeriveTARootKey(const uint8_t *salt, uint32_t size, uint8_t *key, uint32_t key_size)
{
    (void)salt;
    (void)size;
    (void)key;
    (void)key_size;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_root_derive_key2_by_huk2(const uint8_t *secret, uint32_t secret_len, uint8_t *key, uint32_t key_len)
{
    (void)secret;
    (void)secret_len;
    (void)key;
    (void)key_len;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_root_uuid_derive_key_by_huk2(const uint8_t *salt, uint32_t size, uint8_t *key, uint32_t *key_size)
{
    (void)salt;
    (void)size;
    (void)key;
    (void)key_size;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_root_derive_key2_by_huk2_enhance(const uint8_t *secret, uint32_t secret_len, uint8_t *key,
                                                    uint32_t key_len)
{
    (void)secret;
    (void)secret_len;
    (void)key;
    (void)key_len;
    return TEE_ERROR_NOT_SUPPORTED;
}


TEE_Result tee_ext_root_uuid_derive_key_by_huk2_enhance(const uint8_t *salt, uint32_t size, uint8_t *key,
                                                        uint32_t *key_size)
{
    (void)salt;
    (void)size;
    (void)key;
    (void)key_size;
    return TEE_ERROR_NOT_SUPPORTED;
}