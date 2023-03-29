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
#include <dlist.h>
#include <securec.h>


TEE_Result query_ta_verify_pubkey(const struct ta_verify_key *all_key, size_t all_key_num,
    struct ta_verify_key *query_key)
{
    const void *key = NULL;

    if (query_key == NULL || all_key == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    for (size_t i = 0; i < all_key_num; i++) {
        if (query_key->key_len == all_key[i].key_len && query_key->key_style == all_key[i].key_style)
            key = all_key[i].key;
    }

    if (key == NULL) {
        tloge("Get verify pub key failed, invalid cons, len:%u, sec style:%s\n",
            query_key->key_len, query_key->key_style == PUB_KEY_RELEASE ? "release" : "debug");
        tloge("This sec file can't be loaded, pls check sec file style and key len\n");
        return TEE_ERROR_BAD_FORMAT;
    }

    query_key->key = key;
    return TEE_SUCCESS;
}
