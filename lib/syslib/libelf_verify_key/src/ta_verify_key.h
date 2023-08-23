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
#ifndef GTASK_TA_VERIFY_KEY_H
#define GTASK_TA_VERIFY_KEY_H

#include <crypto_wrapper.h>

enum verify_key_len {
    PUB_KEY_2048_BITS = 2048,
    PUB_KEY_4096_BITS = 4096,
    PUB_KEY_256_BITS  = 256
};

enum verify_key_style {
    PUB_KEY_DEBUG = 0,
    PUB_KEY_RELEASE = 1,
};

struct ta_verify_key {
    uint32_t key_len;
    uint32_t key_style;
    const void *key;
};

TEE_Result get_ta_verify_pubkey(struct ta_verify_key *key_info);
#endif
