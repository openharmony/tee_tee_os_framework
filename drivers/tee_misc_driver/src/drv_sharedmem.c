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
#include "drv_sharedmem.h"
#include <securec.h>
#include "tee_log.h"
#include "sys/mman.h"
#include "shared_mem_api.h"
#include "tee_inner_uuid.h"
#ifndef CONFIG_MISC_DRIVER
#include "drv_thread.h"
#endif
#include "drv_module.h"
#include "drv_param_type.h"
#include "boot_sharedmem.h"
#include <unistd.h>

static uintptr_t g_sharedmem_vaddr = 0;
static uint32_t g_sharedmem_size = 0;
static bool g_sharedmem_flag = false;

static TEE_UUID g_allperm_uuid = { 0xffffffff, 0xffff, 0xffff, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }};

static TEE_UUID g_sys_uuid = { 0x0, 0x0, 0x0, { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 }};

static TEE_UUID g_sys_uuid_list[] = {
    TEE_SERVICE_GLOBAL,
    TEE_SERVICE_HUK,
    TEE_SERVICE_PERM,
    TEE_SERVICE_SSA,
    TEE_SERVICE_KEYMASTER,
};

int32_t sharedmem_addr_init(void)
{
    int32_t ret;
    uint32_t size = SHAREDMEM_DEFAULT_SIZE;
retry:
    g_sharedmem_vaddr = (uintptr_t)malloc(size);
    if (g_sharedmem_vaddr == 0) {
        tloge("malloc sharedmem buffer failed\n");
        return TLV_SHAREDMEM_ERROR_GENERIC;
    }
    ret = get_sharedmem_from_kernel((void *)g_sharedmem_vaddr, (void *)&size, (uint64_t)GET_SHAREDMEM_TYPE_STATIC);
    if (ret != 0) {
        if (size > SHAREDMEM_DEFAULT_SIZE) {
            tloge("sharedmem size is not enough, need to realloc\n");
            free((void *)g_sharedmem_vaddr);
            goto retry;
        }
        free((void *)g_sharedmem_vaddr);
        g_sharedmem_vaddr = 0;

        /* no sharedmem */
        if (size == 0)
            return TLV_SHAREDMEM_NO_DATA;
        tloge("get sharedmem form kernel failed\n");
        return TLV_SHAREDMEM_ERROR_GENERIC;
    }
    g_sharedmem_size = size;
    tlogd("get sharedmem from kernel success, size=0x%x\n", size);
    g_sharedmem_flag = true;
    return TLV_SHAREDMEM_SUCCESS;
}

static int32_t share_mem_value_check(const struct tlv_item_tag *item)
{
    uint32_t len = item->length;
    uint32_t uuid_len = item->uuid_len;

    if (item->magic == (MAIGC_WORD + len + uuid_len)) {
        return TLV_SHAREDMEM_SUCCESS;
    } else {
        tloge("magic check failed, item->magic is 0x%x len is 0x%x uuid_len is 0x%x\n",
              item->magic, len, uuid_len);
        return TLV_SHAREDMEM_ERROR_DATA;
    }
}

int32_t get_sharedmem_addr(uintptr_t *sharedmem_vaddr, bool *sharedmem_flag, uint32_t *sharedmem_size)
{
    if (sharedmem_vaddr == NULL || sharedmem_flag == NULL || sharedmem_size == NULL) {
        tloge("bad paras\n");
        return TLV_SHAREDMEM_ERROR_DATA;
    }

    *sharedmem_vaddr = g_sharedmem_vaddr;
    *sharedmem_flag = g_sharedmem_flag;
    *sharedmem_size = g_sharedmem_size;

    return TLV_SHAREDMEM_SUCCESS;
}

static struct tlv_item_tag *share_mem_tlv_find(const struct tlv_tag *tlv, const char *type, const uint32_t type_size)
{
    struct tlv_item_tag *pos = NULL;
    uint32_t len = 0;
    uintptr_t sharedmem_vaddr = g_sharedmem_vaddr + sizeof(struct tlv_tag);

    if (tlv == NULL)
        return NULL;
    pos = (struct tlv_item_tag *)sharedmem_vaddr;
    for (uint32_t i = 0; i < tlv->tlv_num; i++) {
        int32_t ret = share_mem_value_check(pos);
        if (ret != TLV_SHAREDMEM_SUCCESS)
            return NULL;

        len += pos->length + pos->uuid_len + sizeof(struct tlv_item_tag);

        if (len > tlv->total_len) {
            tloge("the length is large then the total len\n");
            return NULL;
        }

        if (memcmp(pos->type, type, type_size) == 0 && strnlen(pos->type, TYPE_LEN) <= type_size)
            return pos;
        if (i < tlv->tlv_num - 1)
            pos = (struct tlv_item_tag *)(sharedmem_vaddr + len);
    }

    tloge("The type value is null\n");
    return NULL;
}

#ifndef CONFIG_MISC_DRIVER
int32_t get_caller_uuid(spawn_uuid_t *uuid)
{
    tid_t tid;
    int32_t pid;
    int32_t pid_call = INVALID_CALLER_PID;

    if (uuid == NULL)
        return TLV_SHAREDMEM_BAD_PARAMETERS;

    tid = gettid();
    if (tid < 0) {
        tloge("failed to get tid\n");
        return TLV_SHAREDMEM_ERROR_GENERIC;
    }

    /* for invalid pid, return "No such process" */
    ret = get_callerpid_by_tid(tid, (pid_t *)&pid_call);
    if (ret != 0)
        return TLV_SHAREDMEM_ERROR_GENERIC;

    pid = (int)((uint32_t)pid_call & LOW_MASK_16BIT);

    if (getuuid(pid, uuid) != 0) {
        tloge("get uuid error, pid:%d\n", pid);
        return TLV_SHAREDMEM_ERROR_GENERIC;
    }

    return TLV_SHAREDMEM_SUCCESS;
}
#endif

static int32_t check_caller_is_system_service(TEE_UUID *current_uuid)
{
    int sys_list_size = sizeof(g_sys_uuid_list) / sizeof(TEE_UUID);
    for (int i = 0; i < sys_list_size; i++) {
        if (memcmp(current_uuid, &(g_sys_uuid_list[i]), sizeof(TEE_UUID)) == 0)
            return TLV_SHAREDMEM_SUCCESS;
    }
    return TLV_SHAREDMEM_ACCESS_DENIED;
}

static int32_t allperm_and_sys_uuid_check(TEE_UUID *current_uuid, TEE_UUID *caller_uuid)
{
    return memcmp(current_uuid, &g_allperm_uuid, sizeof(TEE_UUID)) == 0 ||
           (memcmp(current_uuid, &g_sys_uuid, sizeof(TEE_UUID)) == 0 &&
           check_caller_is_system_service(caller_uuid) == TLV_SHAREDMEM_SUCCESS);
}

static int32_t share_mem_uuid_check(const void *uuid_buffer, uint32_t length)
{
    spawn_uuid_t spawn_uuid = { 0 };
    if (uuid_buffer == NULL)
        return TLV_SHAREDMEM_BAD_PARAMETERS;
    if ((length == 0) || (length % sizeof(TEE_UUID) != 0))
        return TLV_SHAREDMEM_BAD_PARAMETERS;

#ifndef CONFIG_MISC_DRIVER
    if (get_caller_uuid(&spawn_uuid) != 0) {
        tloge("get uuid error");
        return TLV_SHAREDMEM_ERROR_GENERIC;
    }
#else
    get_current_caller_uuid(&(spawn_uuid.uuid));
#endif

    TEE_UUID *uuid = (TEE_UUID *)uuid_buffer;

    for (uint32_t i = 0; i < length / sizeof(TEE_UUID); i++) {
        if (allperm_and_sys_uuid_check(uuid, &(spawn_uuid.uuid)))
            return TLV_SHAREDMEM_SUCCESS;
        if (memcmp(uuid, &(spawn_uuid.uuid), sizeof(TEE_UUID)) == 0)
            return TLV_SHAREDMEM_SUCCESS;
        uuid++;
    }

    return TLV_SHAREDMEM_ACCESS_DENIED;
}

static int32_t check_tlv_paras(struct tlv_paras tlv_paras)
{
    if (!g_sharedmem_flag || g_sharedmem_vaddr == 0) {
        tloge("no shared mem at this platform or sharedmem init failed\n");
        return TLV_SHAREDMEM_ERROR_DATA;
    }

    if (tlv_paras.buffer == NULL || tlv_paras.type == NULL) {
        tloge("invalid param\n");
        return TLV_SHAREDMEM_BAD_PARAMETERS;
    }

    if (tlv_paras.type_size == 0 || tlv_paras.type_size > TYPE_LEN) {
        tloge("invalid type_size param\n");
        return TLV_SHAREDMEM_BAD_PARAMETERS;
    }

    return TLV_SHAREDMEM_SUCCESS;
}

static int32_t get_tlv_msg(struct tlv_paras tlv_paras, uint32_t *size, bool uuid_check, bool clear_flag)
{
    errno_t rc;
    int32_t ret;

    if (check_tlv_paras(tlv_paras) != TLV_SHAREDMEM_SUCCESS)
        return TLV_SHAREDMEM_BAD_PARAMETERS;

    struct tlv_tag *tlv = (struct tlv_tag *)g_sharedmem_vaddr;
    if (tlv->magic != MAIGC_WORD) {
        tloge("magic is error magic is 0x%x\n", tlv->magic);
        return TLV_SHAREDMEM_ERROR_DATA;
    }

    if (tlv->total_len + sizeof(struct tlv_tag) > g_sharedmem_size) {
        tloge("the tlv total len is too large, length is 0x%x\n", tlv->total_len);
        return TLV_SHAREDMEM_ERROR_DATA;
    }

    struct tlv_item_tag *item = share_mem_tlv_find(tlv, tlv_paras.type, tlv_paras.type_size);
    if (item == NULL)
        return TLV_SHAREDMEM_NO_DATA;

    uint32_t len = item->length;
    uint32_t uuid_len = item->uuid_len;
    void *value = tlv_item_data(item);

    if (uuid_check == true) {
        ret = share_mem_uuid_check(value, uuid_len);
        if (ret != TLV_SHAREDMEM_SUCCESS)
            return TLV_SHAREDMEM_ACCESS_DENIED;
    }

    if (len > *size) {
        tloge("buffer length should big than put in value 0x%x\n", len);
        return TLV_SHAREDMEM_BAD_PARAMETERS;
    }

    rc = memcpy_s(tlv_paras.buffer, *size, value + uuid_len, len);
    if (rc != EOK) {
        tloge("copy sharedmem failed type is %s\n", tlv_paras.type);
        return TLV_SHAREDMEM_ERROR_GENERIC;
    }

    *size = len;

    if (clear_flag) {
        rc = memset_s(value + uuid_len, len, 0, len);
        if (rc != EOK) {
            tloge("clear tlv buffer failed\n");
            return TLV_SHAREDMEM_ERROR_GENERIC;
        }
    }

    return TLV_SHAREDMEM_SUCCESS;
}

int32_t get_tlv_shared_mem(const char *type, uint32_t type_size, void *buffer, uint32_t *size, bool clear_flag)
{
    int32_t ret;
    if (type == NULL || buffer == NULL || size == NULL)
        return TLV_SHAREDMEM_BAD_PARAMETERS;
    struct tlv_paras tlv_paras = { type, type_size, buffer, 0};
    ret = get_tlv_msg(tlv_paras, size, true, clear_flag);
    if (ret != 0) {
        tloge("get sharedmem error 0x%x\n", ret);
        return ret;
    }
    return TLV_SHAREDMEM_SUCCESS;
}

int32_t get_tlv_shared_mem_drv(const char *type, uint32_t type_size, void *buffer, uint32_t *size, bool clear_flag)
{
    int32_t ret;

    if (type == NULL || buffer == NULL || size == NULL)
        return TLV_SHAREDMEM_BAD_PARAMETERS;

    struct tlv_paras tlv_paras = { type, type_size, buffer, 0 };

    ret = get_tlv_msg(tlv_paras, size, false, clear_flag);
    if (ret != 0) {
        tloge("get sharedmem drv error 0x%x\n", ret);
        return ret;
    }

    return TLV_SHAREDMEM_SUCCESS;
}

uint32_t get_sharedmem_vaddr()
{
    return g_sharedmem_vaddr;
}

bool get_sharedmem_flag()
{
    return g_sharedmem_flag;
}
