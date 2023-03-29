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

#include <stdint.h>
#include "securec.h"
#include "tee_defines.h"
#include "tee_sharemem.h"
#include "tee_log.h"

__attribute__((visibility("default"))) \
uint32_t tee_hal_get_provision_key(uint8_t *oem_key, size_t key_size)
{
#ifdef CONFIG_TEE_MISC_DRIVER
    uint32_t ret = tee_get_oemkey_info(oem_key, key_size);
    return ret;
#else
    (void)oem_key;
    (void)key_size;
    return TEE_ERROR_NOT_SUPPORTED;
#endif
}
