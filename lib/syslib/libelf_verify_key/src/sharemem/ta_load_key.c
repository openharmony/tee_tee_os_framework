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
#include "ta_load_key.h"

#include <tee_defines.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <tee_sharemem.h>
#include <dlist.h>
#include <securec.h>
#include "drv_sharedmem.h"

struct key_size_tag_info key_size_info[] = {
    {"4096", PUB_KEY_4096_BITS},
    {"2048", PUB_KEY_2048_BITS},
    {"256", PUB_KEY_256_BITS},
};

struct key_style_tag_info key_style_info[] = {
    {"debug", PUB_KEY_DEBUG},
    {"release", PUB_KEY_RELEASE},
};
rsa_pub_key_t *g_ta_verify_key;

static int32_t get_key_len_tag(uint32_t key_len, char *tag, uint32_t tag_len)
{
    size_t i;
    errno_t ret;
    for (i = 0; i < array_size(key_size_info); i++) {
        if (key_len == key_size_info[i].key_len) {
            ret = strcat_s(tag, tag_len, key_size_info[i].key_len_tag);
            if (ret == EOK)
                return 0;
            else
                return -1;
        }
    }

    return -1;
}

static int32_t get_key_style_tag(uint32_t key_len, char *tag, uint32_t tag_len)
{
    size_t i;
    errno_t ret;
    for (i = 0; i < array_size(key_style_info); i++) {
        if (key_len == key_style_info[i].key_style) {
            ret = strcat_s(tag, tag_len, key_style_info[i].key_style_tag);
            if (ret == EOK)
                return 0;
            else
                return -1;
        }
    }
    return -1;
}

static int32_t get_key_len_style_tag(uint32_t key_len, uint32_t key_style, char *tag, uint32_t tag_len)
{
    int32_t ret;
    ret = get_key_len_tag(key_len, tag, tag_len);
    if (ret != 0) {
        tloge("get key len tag failed, key len is %u\n", key_len);
        return ret;
    }

    ret = get_key_style_tag(key_style, tag, tag_len);
    if (ret != 0) {
        tloge("get key style tag failed, key style is %u\n", key_style);
        return ret;
    }
    return ret;
}

static void *query_key_info(uint32_t key_len, uint32_t key_style)
{
    int ret;
    char tag[MAX_TAG_LEN] = "ta_rsa_pub_";
    uint32_t size = sizeof(*g_ta_verify_key);
    ret = get_key_len_style_tag(key_len, key_style, tag, sizeof(tag));
    if (ret != 0) {
        tloge("key tag info failed\n");
        return NULL;
    }
    if (g_ta_verify_key == NULL)
        g_ta_verify_key = TEE_Malloc(sizeof(rsa_pub_key_t), 0);

    if (g_ta_verify_key == NULL)
        return NULL;

    ret =  get_tlv_sharedmem(tag, sizeof(tag), g_ta_verify_key, &size, false);
    if (ret != TLV_SHAREDMEM_SUCCESS) {
        TEE_Free(g_ta_verify_key);
        g_ta_verify_key = NULL;
        return NULL;
    } else {
        return g_ta_verify_key;
    }
}

TEE_Result query_ta_verify_pubkey(const struct ta_verify_key *all_key, size_t all_key_num,
    struct ta_verify_key *query_key)
{
    const void *key = NULL;

    (void)all_key;
    (void)all_key_num;
    key = query_key_info(query_key->key_len, query_key->key_style);
    if (key == NULL) {
        tloge("Get verify pub key failed, invalid cons, len:%u, sec style:%s\n",
            query_key->key_len, query_key->key_style == PUB_KEY_RELEASE ? "release" : "debug");
        tloge("This sec file can't be loaded, pls check sec file style and key len\n");
        return TEE_ERROR_BAD_FORMAT;
    }

    query_key->key = key;
    return TEE_SUCCESS;
}
