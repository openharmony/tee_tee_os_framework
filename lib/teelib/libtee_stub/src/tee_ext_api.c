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
#include <tee_ext_api.h>

TEE_Result tee_ext_derive_ta_platfrom_keys(TEE_ObjectHandle object, uint32_t key_size, const TEE_Attribute *params,
    uint32_t params_count, const uint8_t *exinfo, uint32_t exinfo_size)
{   
    (void)object;
    (void)key_size;
    (void)params;
    (void)params_count;
    (void)exinfo;
    (void)exinfo_size;
    return TEE_ERROR_NOT_SUPPORTED;
}