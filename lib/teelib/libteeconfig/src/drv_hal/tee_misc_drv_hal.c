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
#include <mem_ops.h>
#include "tee_log.h"
#include "boot_sharedmem.h"
#include "tee_drv_client.h"
#include "tee_inner_uuid.h"
#include "tee_sharemem.h"

#define TYPE_LEN 32

static void release_resource(int64_t fd, char *buffer, uint32_t buffer_size, char *type, uint32_t type_size)
{
    if (buffer != NULL) {
        (void)memset_s(buffer, buffer_size + sizeof(buffer_size), 0, buffer_size + sizeof(buffer_size));
        (void)free_sharemem(buffer, buffer_size);
    }
    if (type != NULL)
        (void)free_sharemem(type, type_size);
    int64_t ret = tee_drv_close(fd);
    if (ret != 0)
        tloge("close fd failed\n");
}

int32_t tee_shared_mem(const char *type, uint32_t type_size, void *buffer, uint32_t *buffer_size, bool clear_flag)
{
    TEE_UUID uuid = TEE_MISC_DRIVER;
    const char *drv_name = "tee_misc_driver";
    struct shared_buffer_args ioctl_buffer;

    if (type == NULL || buffer == NULL || buffer_size == NULL || type_size > TYPE_LEN) {
        tloge("the args is error\n");
        return -1;
    }

    int64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("call other drv open %s fail\n", drv_name);
        return -1;
    }

    char *tmp_type = alloc_sharemem_aux(&uuid, type_size);
    if (tmp_type == NULL) {
        tloge("alloc type buffer failed\n");
        release_resource(fd, NULL, 0, tmp_type, type_size);
        return -1;
    }

    (void)memset_s(tmp_type, type_size, 0, type_size);
    (void)memcpy_s(tmp_type, type_size, type, type_size);

    char *tmp_buffer = alloc_sharemem_aux(&uuid, *buffer_size + sizeof(*buffer_size));
    if (tmp_buffer == NULL) {
        tloge("alloc tmp buffer failed\n");
        release_resource(fd, tmp_buffer, *buffer_size, tmp_type, type_size);
        return -1;
    }
    (void)memset_s(tmp_buffer, *buffer_size + sizeof(*buffer_size), 0, *buffer_size + sizeof(*buffer_size));

    ioctl_buffer.type_buffer = (uint64_t)(uintptr_t)tmp_type;
    ioctl_buffer.type_size = type_size;
    ioctl_buffer.buffer_size = *buffer_size;
    ioctl_buffer.buffer = (uint64_t)(uintptr_t)tmp_buffer;
    ioctl_buffer.clear_flag = clear_flag;

    int64_t ret = tee_drv_ioctl(fd, IOCTRL_GET_TLV_SHARED_MEM, (const void *)(&ioctl_buffer), sizeof(ioctl_buffer));
    if (ret != 0)
        tloge("call ioctl failed\n");

    buffer_size = (uint32_t *)(tmp_buffer + *buffer_size);
    errno_t rc = memcpy_s(buffer, *buffer_size, tmp_buffer, *buffer_size);
    if (rc != EOK) {
        tloge("memcpy tmp type failed\n");
        release_resource(fd, tmp_buffer, *buffer_size, tmp_type, type_size);
        return rc;
    }

    release_resource(fd, tmp_buffer, *buffer_size, tmp_type, type_size);
    return ret;
}

static void release_oemkey_buffer(char *buffer, size_t key_size, int64_t fd)
{
    (void)memset_s(buffer, key_size, 0, key_size);
    (void)free_sharemem(buffer, key_size);
    int64_t ret = tee_drv_close(fd);
    if (ret != 0)
        tloge("call other drv failed\n");
}

static int32_t tee_get_oemkey(const char *drv_name, TEE_UUID uuid, uint8_t *oem_key, size_t key_size)
{
    int64_t fd = tee_drv_open(drv_name, NULL, 0);
    if (fd <= 0) {
        tloge("call other drv open %s fail\n", drv_name);
        return -1;
    }

    struct oemkey_buffer_args oemkey_buffer;

    char *tmp_buffer = alloc_sharemem_aux(&uuid, key_size);
    if (tmp_buffer == NULL) {
        (void)tee_drv_close(fd);
        return -1;
    }
    (void)memset_s(tmp_buffer, key_size, 0, key_size);

    oemkey_buffer.key_size = key_size;
    oemkey_buffer.oemkey_buffer = (uint64_t)(uintptr_t)tmp_buffer;

    int64_t ret = tee_drv_ioctl(fd, IOCTRL_GET_OEM_KEY, (const void *)(&oemkey_buffer), sizeof(oemkey_buffer));
    if (ret != 0)
        tloge("call ioctl failed\n");

    errno_t rc = memcpy_s(oem_key, key_size, tmp_buffer, key_size);
    if (rc != EOK) {
        tloge("memcpy tmp type failed\n");
        release_oemkey_buffer(tmp_buffer, key_size, fd);
        return -1;
    }

    release_oemkey_buffer(tmp_buffer, key_size, fd);
    return ret;
}

int32_t tee_get_oemkey_info(uint8_t *oem_key, size_t key_size)
{
    TEE_UUID uuid = TEE_MISC_DRIVER;
    const char *drv_name = "tee_misc_driver";

    if (oem_key == NULL)
        return -1;

    int32_t ret = tee_get_oemkey(drv_name, uuid, oem_key, key_size);
    if (ret != 0) {
        tloge("get oem key failed\n");
        return -1;
    }

    return ret;
}

int32_t tee_ext_get_advsecmode(uint32_t *advsecmode)
{
    (void)advsecmode;
    return TEE_ERROR_NOT_SUPPORTED;
}