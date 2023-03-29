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


#ifndef TEE_LOADER_TLV_SHAREDMEM_H
#define TEE_LOADER_TLV_SHAREDMEM_H

#include <stdint.h>

#ifndef UINT64_MAX
#define UINT64_MAX  0xffffffffffffffffull
#endif

#define MAGIC_START 0xfd544c56
#define MAX_TAG_LEN 32
#define MIN_TAG_LEN 3
#define TLV_ITEM_DATA(item) ((void *)((char *)(item) + sizeof(struct tlv_item_tag)))

struct tlv_item_tag {
    char type[MAX_TAG_LEN];
    uint32_t owner_len;
    uint32_t length;
    uint32_t magic;
} __attribute__((__packed__));

struct tlv_item_data {
    char *type;
    uint32_t type_size;
    void *owner_list;
    uint32_t owner_len;
    void *value;
    uint32_t value_len;
} __attribute__((__packed__));

struct tlv_tag {
    uint32_t magic;
    uint32_t tlv_num;
    uint32_t total_len;
} __attribute__((__packed__));

uint32_t put_tlv_shared_mem(struct tlv_item_data tlv_item_data);
uint32_t update_share_mem_tlv(struct tlv_item_data tlv_item_data);

#endif
