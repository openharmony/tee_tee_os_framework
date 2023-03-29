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
#include <tee_defines.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <tee_sharemem.h>
#include <securec.h>
#include <dlist.h>
#include "ta_load_key.h"
#include "drv_sharedmem.h"

static uint8_t *g_load_key = NULL;
bool is_wb_protecd_ta_key(void)
{
    return false;
}

#define WB_KEY_TAG "wb"
#define ECIES_KEY_TAG "ecies"

struct key_type_tag_info g_key_type_tag[] = {
#ifdef DYN_TA_SUPPORT_V3
    {"v3_2048", V3_TYPE_2048},
    {"v3_3072", V3_TYPE_3072},
#endif
};

static int32_t get_ta_type_tag(uint32_t key_type, char *tag, uint32_t tag_len)
{
    size_t i;
    errno_t ret;

    for (i = 0; i < array_size(g_key_type_tag); i++) {
        if (key_type == g_key_type_tag[i].ta_type) {
            ret = strcat_s(tag, tag_len, g_key_type_tag[i].key_type_str);
            if (ret == EOK)
                return 0;
            else
                return -1;
        }
    }
    return -1;
}

TEE_Result get_ta_load_key(struct key_data *key)
{
    int32_t ret;
    size_t key_len;
    char ta_load_key_tag[MAX_TAG_LEN] = "ta_decrypt_key_";
    errno_t err_ret;

    if (key == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (key->pro_type == WB_KEY) {
        if (g_load_key == NULL)
            g_load_key = TEE_Malloc(sizeof(struct wb_key_struct), 0);
        key_len = sizeof(struct wb_key_struct);
        err_ret = strcat_s(ta_load_key_tag, sizeof(ta_load_key_tag), WB_KEY_TAG);
    } else {
        if (g_load_key == NULL)
            g_load_key = TEE_Malloc(sizeof(struct ecies_key_struct), 0);
        key_len = sizeof(struct ecies_key_struct);
        err_ret = strcat_s(ta_load_key_tag, sizeof(ta_load_key_tag), ECIES_KEY_TAG);
    }

    if (err_ret != EOK)
        return TEE_ERROR_SECURITY;

    if (g_load_key == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    ret = get_ta_type_tag(key->ta_type, ta_load_key_tag, sizeof(ta_load_key_tag));
    if (ret != 0) {
        tloge("invalid ta type\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret =  get_tlv_sharedmem(ta_load_key_tag, sizeof(ta_load_key_tag), g_load_key, (uint32_t *)&key_len, false);
    if (ret == TLV_SHAREDMEM_SUCCESS) {
        key->key = g_load_key;
        key->key_len = key_len;
        return TEE_SUCCESS;
    } else {
        tloge("invalid ta type:%d, or key protect type:%d\n", key->ta_type, key->pro_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
}
