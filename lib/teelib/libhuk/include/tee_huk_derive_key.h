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
#ifndef TEE_HUK_DERIVE_KEY_H
#define TEE_HUK_DERIVE_KEY_H

#include <tee_defines.h>

struct meminfo_t {
    uint64_t buffer;
    uint32_t size;
};

void *huk_alloc_shared_mem(uint32_t size);
void huk_free_shared_mem(uint8_t *p, uint32_t size);
TEE_Result tee_internal_derive_key(const uint8_t *salt, uint32_t saltsize, uint8_t *key, uint32_t keysize);

#endif