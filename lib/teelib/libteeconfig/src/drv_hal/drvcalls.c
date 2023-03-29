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

#include <stdio.h>
#include <string.h>
#include <securec.h>
#include "tee_log.h"
#include "boot_sharedmem.h"
#include "tee_secfile_load_agent.h"
#include "tee_sharemem.h"
#include "drv_sharedmem.h"
#define MAX_NAME_LEN        32
#define DRV_MOD_PARAM_LEN   2
#define PRODCUT_MAX_LEN     64

int32_t get_tlv_sharedmem(const char *type, uint32_t type_size, void *buffer, uint32_t *buffer_size, bool clear_flag)
{
#ifdef CONFIG_TEE_MISC_DRIVER
    int32_t ret = tee_shared_mem(type, type_size, buffer, buffer_size, clear_flag);
    return ret;
#else
    (void)type;
    (void)type_size;
    (void)buffer;
    (void)buffer_size;
    (void)clear_flag;

    return TEE_ERROR_NOT_SUPPORTED;
#endif
}

#define CHIP_TYPE_NAME_STRLEN 10
int32_t tee_get_chip_type(char *buffer, uint32_t buffer_len)
{
#ifdef TEE_SUPPORT_DYN_CONF
    if (buffer == NULL || buffer_len == 0 || buffer_len > CHIP_TYPE_LEN_MAX) {
        tloge("invalid buffer while get chip type\n");
        return -1;
    }
    uint32_t size = buffer_len;
    char chip_type_name[CHIP_TYPE_NAME_STRLEN] = { "chip_type" };
    int32_t ret = get_tlv_sharedmem(chip_type_name, CHIP_TYPE_NAME_STRLEN, buffer, &size, 0);
    if (ret != TLV_SHAREDMEM_SUCCESS) {
        tloge("get chip type from share mem failed\n");
        return ret;
    }

    if (strnlen(buffer, CHIP_TYPE_LEN_MAX) >= CHIP_TYPE_LEN_MAX) {
        tloge("chip type length is invalid\n");
        return -1;
    }

    return 0;
#else
    (void)buffer;
    (void)buffer_len;
    return -1;
#endif
}

__attribute__((visibility("default"))) \
int32_t tee_ext_get_dieid(uint32_t *in_buffer)
{
    (void)in_buffer;
    return TEE_ERROR_NOT_SUPPORTED;
}
