/*
 * Copyright (C) 2024 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "tee_hw_ext_api.h"

TEE_Result tee_ext_get_device_unique_id(uint8_t *device_unique_id, uint32_t *length)
{
    (void)device_unique_id;
    (void)length;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_derive_key_iter(const struct meminfo_t *salt, struct meminfo_t *key,
    uint32_t outer_iter_num, uint32_t inner_iter_num)
{   
    (void)salt;
    (void)key;
    (void)outer_iter_num;
    (void)inner_iter_num;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_derive_key_iter_by_huk2(const struct meminfo_t *salt, struct meminfo_t *key,
    uint32_t outer_iter_num, uint32_t inner_iter_num)
{   
    (void)salt;
    (void)key;
    (void)outer_iter_num;
    (void)inner_iter_num;
    return TEE_ERROR_NOT_SUPPORTED;
}