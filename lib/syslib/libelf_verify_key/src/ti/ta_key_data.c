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
#include <tee_defines.h>
#include <tee_log.h>

#include "ta_load_key.h"
#if CONFIG_TA_DECRYPT_ECIES_MDC
#include "ecies_wrapped_key_tda4_mdc.h"
#endif

bool is_wb_protecd_ta_key(void)
{
    return false;
}

struct key_data g_key_data[] = {
#ifdef DYN_TA_SUPPORT_V3
    { ECIES_KEY, V3_TYPE_3072, (uint8_t *)&g_ecies_key, sizeof(g_ecies_key) },
#endif
};

TEE_Result get_ta_load_key(struct key_data *key)
{
    size_t i;

    if (key == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    for (i = 0; i < (sizeof(g_key_data) / sizeof(g_key_data[0])); i++) {
        if (g_key_data[i].ta_type == key->ta_type &&
            g_key_data[i].pro_type == key->pro_type) {
            key->key_len = g_key_data[i].key_len;
            key->key = g_key_data[i].key;
            return TEE_SUCCESS;
        }
    }

    tloge("invalid ta type:%d, or key protect type:%d\n", key->ta_type, key->pro_type);
    return TEE_ERROR_BAD_PARAMETERS;
}
