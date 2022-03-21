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

#include "tlv_sharedmem.h"

#include <stdlib.h>
#include <string.h>
#include <securec.h>

#include "teeos_uuid.h"
#include "set_teeos_cfg.h"

static struct tlv_tag *g_tlv_start = NULL;
static uint64_t g_teeos_share_mem = 0;

static int32_t tlv_start_init()
{
    if (g_tlv_start != NULL) {
        teelog("tlv already started\n");
        return 0;
    }

    uint64_t sharedmem_start = get_sharedmem_start();
    uint64_t sharedmem_size = get_sharedmem_size();
    if (sharedmem_start == 0 || sharedmem_size == 0) {
        teelog("sharedmem start addr or size error\n");
        return -1;
    }

    if (sharedmem_size < sizeof(struct tlv_tag)) {
        teelog("sharedmem size not enough\n");
        return -1;
    }

    if (memset_s((void *)(uintptr_t)sharedmem_start, sizeof(struct tlv_tag),
                 0, sizeof(struct tlv_tag)) != EOK) {
        teelog("memset tlv start failed\n");
        return -1;
    }

    g_teeos_share_mem = sharedmem_start + sizeof(*g_tlv_start);
    struct tlv_tag *tlv = (struct tlv_tag *)(uintptr_t)sharedmem_start;
    tlv->magic = MAGIC_START;
    tlv->tlv_num = 0;
    g_tlv_start = tlv;

    return 0;
}

static int32_t alloc_teeos_shared_mem(uint64_t *addr, uint32_t length)
{
    if (addr == NULL || length == 0) {
        teelog("invalid params\n");
        return -1;
    }

    uint64_t teeos_mem_start = get_teeos_start();
    uint64_t teeos_mem_size = get_teeos_size();

    if (UINT64_MAX - g_teeos_share_mem < length) {
        teelog("tlv length too large\n");
        return -1;
    }

    if (g_teeos_share_mem + length > teeos_mem_start + teeos_mem_size) {
        teelog("tlv length too large\n");
        return -1;
    }

    if (memset_s((void *)(uintptr_t)g_teeos_share_mem, length, 0, length) != EOK) {
        teelog("memset sharedmem to zero failed\n");
        return -1;
    }

    *addr = g_teeos_share_mem;
    g_teeos_share_mem += length;

    return 0;
}

static int32_t share_mem_tlv_init_item(struct tlv_item_tag *new_item, struct tlv_item_data tlv_item_data)
{
    uint32_t magic = MAGIC_START + tlv_item_data.value_len + tlv_item_data.owner_len;
    struct tlv_item_tag tmp_item;
    if (new_item == NULL) {
        teelog("invalide params\n");
        return 1;
    }

    if (tlv_item_data.value_len == 0)
        return 1;

    (void)memset_s(&tmp_item, sizeof(tmp_item), 0, sizeof(tmp_item));
    if (memcpy_s(tmp_item.type, MAX_TAG_LEN,
                 tlv_item_data.type, tlv_item_data.type_size) != EOK) {
        teelog("memcpy to tmp_item failed\n");
        return -1;
    }
    tmp_item.length = tlv_item_data.value_len;
    tmp_item.owner_len = tlv_item_data.owner_len;
    tmp_item.magic = magic;

    if (memcpy_s(new_item, sizeof(struct tlv_item_tag), &tmp_item, sizeof(struct tlv_item_tag)) != EOK) {
        teelog("memcpy tag to new_item failed\n");
        return -1;
    }

    if (memcpy_s((uint8_t *)(uintptr_t)TLV_ITEM_DATA(new_item), tlv_item_data.owner_len,
                 (uint8_t *)tlv_item_data.owner_list, tlv_item_data.owner_len) != EOK) {
        teelog("memcpy owner_list to new_item failed\n");
        return -1;
    }

    if (memcpy_s((uint8_t *)(uintptr_t)(TLV_ITEM_DATA(new_item) + tlv_item_data.owner_len), tlv_item_data.value_len,
                 (uint8_t *)tlv_item_data.value, tlv_item_data.value_len) != EOK) {
        teelog("memcpy value to new_item failed\n");
        return -1;
    }
    return 0;
}

struct tlv_item_tag* share_mem_tlv_find(uint64_t start_share_mem,
                                        const struct tlv_tag *tlv, const char *type, uint32_t type_size)
{
    struct tlv_item_tag *pos = NULL;
    uint32_t len;
    uint64_t sharedmem_vaddr = g_teeos_share_mem + sizeof(struct tlv_tag);

    pos = (struct tlv_item_tag *)(uintptr_t)(start_share_mem + sizeof(struct tlv_tag));
    for (uint32_t i = 0; i < tlv->tlv_num; i++) {
        len = sizeof(struct tlv_item_tag) + pos->length + pos->owner_len;
        if (memcmp(pos->type, type, type_size) == 0 && strnlen(pos->type, MAX_TAG_LEN) <= type_size)
            return pos;
        if (i < tlv->tlv_num - 1)
            pos = (struct tlv_item_tag *)(uintptr_t)(sharedmem_vaddr + len);
    }

    return NULL;
}

uint32_t update_share_mem_tlv(struct tlv_item_data tlv_item_data)
{
    struct tlv_item_tag *new_item = NULL;

    new_item = share_mem_tlv_find(g_teeos_share_mem, g_tlv_start, tlv_item_data.type, tlv_item_data.type_size);
    if (new_item == NULL) {
        teelog("invalide params\n");
        return 1;
    }

    if (new_item->length == tlv_item_data.value_len)
        share_mem_tlv_init_item(new_item, tlv_item_data);
    else
        return 1;
    return 0;
}

static uint32_t share_mem_tlv_append(struct tlv_tag *tlv, struct tlv_item_data tlv_item_data)
{
    uint64_t addr;
    if (tlv == NULL) {
        teelog("invalide params\n");
        return 1;
    }

    if (tlv->magic != MAGIC_START) {
        teelog("append error, tlv format error\n");
        return 1;
    }

    /* length is the tlv length */
    uint32_t total_len = tlv_item_data.value_len + tlv_item_data.owner_len + sizeof(struct tlv_item_tag);
    uint32_t ret = alloc_teeos_shared_mem(&addr, total_len);
    if (ret != 0) {
        teelog("get share mem error\n");
        return 1;
    }

    share_mem_tlv_init_item((struct tlv_item_tag *)(uintptr_t)addr, tlv_item_data);
    tlv->tlv_num++;

    uint64_t sharedmem_size = get_sharedmem_size();
    if (tlv->total_len + sizeof(struct tlv_tag) >= sharedmem_size) {
        teelog("out of share mem size\n");
        return 1;
    }

    tlv->total_len += tlv_item_data.value_len + tlv_item_data.owner_len + sizeof(struct tlv_item_tag);
    return 0;
}

uint32_t put_tlv_shared_mem(struct tlv_item_data tlv_item_data)
{
    uint32_t ret;

    if (tlv_start_init() != 0) {
        teelog("tlv init failed\n");
        return 1;
    }

    if (tlv_item_data.type == NULL || tlv_item_data.value == NULL) {
        teelog("tlv_item data error\n");
        return 1;
    }

    if (tlv_item_data.owner_len % (uint32_t)(sizeof(TEE_UUID)) != 0) {
        teelog("tlv_item owner_len error\n");
        return 1;
    }

    if (tlv_item_data.type_size >= MAX_TAG_LEN || tlv_item_data.type_size < MIN_TAG_LEN) {
        teelog("tlv_item type_size error\n");
        return 1;
    }

    ret = share_mem_tlv_append(g_tlv_start, tlv_item_data);
    if (ret != 0) {
        teelog("add share mem error\n");
        return ret;
    }
    return ret;
}
