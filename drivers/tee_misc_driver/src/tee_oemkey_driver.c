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
#include "tee_oemkey_driver.h"
#include <string.h>
#include <tee_log.h>
#include <securec.h>
#include "drv_module.h"
#include "drv_sharedmem.h"
#include "drv_param_type.h"
#include "drv_param_ops.h"
#include "mem_ops.h"
#include "boot_sharedmem.h"
#include "drv_sharedmem.h"
#include "tee_drv_client.h"
#include "base_drv_node.h"
#include "crypto_mgr_syscall.h"
#include "drv_sharedmem.h"

static int32_t oemkey_check_valid(struct tee_oemkey_info *secinfo)
{
    if (secinfo->head_magic != OEMKEY_MAGIC_NUM || secinfo->tail_magic != OEMKEY_MAGIC_NUM) {
        tloge("secinfo error, maybe uninitialized or modified, head magic 0x%x, tail magic 0x%x\n",
              secinfo->head_magic, secinfo->tail_magic);
        return -1;
    }
    return 0;
}

static int32_t copy_from_shared_buffer(void *buf, uint32_t *buf_size, uint8_t *shared_buf)
{
    if (buf_size == NULL) {
        tloge("the buf size is invalid\n");
        return -1;
    }

    if (memcpy_s(buf_size, sizeof(uint32_t), shared_buf, sizeof(uint32_t)) != EOK) {
        tloge("copy buf size failed\n");
        return -1;
    }

    shared_buf += sizeof(uint32_t);
    if (memcpy_s(buf, *buf_size, shared_buf, *buf_size) != EOK) {
        tloge("copy buf failed\n");
        return -1;
    }
    return 0;
}

static int32_t copy_to_shared_buf(uint32_t size, uint8_t *shared_buf)
{
    if (memcpy_s(shared_buf, sizeof(uint32_t), (void *)&size, sizeof(uint32_t)) != EOK) {
        tloge("copy buf size failed\n");
        return -1;
    }
    return 0;
}

static int32_t get_oemkey_buffer(uint32_t cmd_id, uint64_t fd, void *buffer, uint32_t size)
{
    int32_t ret;
    struct crypto_ioctl input = { 0 };
    uint32_t ioctl_size = size + sizeof(uint32_t);
    TEE_UUID uuid = CRYPTOMGR;

    uint8_t *shared_buf = alloc_sharemem_aux(&uuid, ioctl_size);
    if (shared_buf == NULL) {
        tloge("hamc init alloc share mem failed\n");
        return -1;
    }

    (void)memset_s(shared_buf, ioctl_size, 0, ioctl_size);

    ret = copy_to_shared_buf(size, shared_buf);
    if (ret != 0) {
        tloge("copy to shared buffer failed\n");
        goto end;
    }

    input.buf = (uint64_t)(uintptr_t)shared_buf;
    input.buf_len = ioctl_size;
    input.total_nums = 1;

    ret = tee_drv_ioctl(fd, cmd_id, (void *)(&input), sizeof(input));
    if (ret != 0) {
        tloge("share buffer failed\n");
        goto end;
    }

    ret = copy_from_shared_buffer(buffer, &size, shared_buf);
    if (ret != 0) {
        tloge("copy from shared mem failed\n");
        goto end;
    }
end:
    if (shared_buf != NULL)
        free_sharemem(shared_buf, ioctl_size);

    return ret;
}

static int32_t tee_crypto_get_oemkey(void *buf, uint32_t size)
{
    if (buf == NULL) {
        tloge("the buffer is null\n");
        return -1;
    }
    const char *drv_name = TEE_CRYPTO_DRIVER_NAME;
    uint32_t args = (uint32_t)(uintptr_t)(&drv_name);

    uint64_t fd = tee_drv_open(drv_name, &args, sizeof(args));
    if (fd <= 0) {
        tloge("open fd failed\n");
        return -1;
    }

    int32_t ret = get_oemkey_buffer(IOCTRL_CRYPTO_GET_OEMKEY, fd, buf, size);
    if (ret != 0)
        tloge("get oemkey from crypto engine failed\n");

    (void)tee_drv_close(fd);

    return ret;
}

static struct tee_oemkey_info *g_secinfo = NULL;

static int32_t tee_sharemem_get_oemkey(struct tee_oemkey_info *secinfo)
{
    uint32_t size = sizeof(struct tee_oemkey_info);
    int32_t ret;

    if (g_secinfo == NULL) {
        g_secinfo = (struct tee_oemkey_info *)malloc(sizeof(struct tee_oemkey_info));
        if (g_secinfo == NULL)
            return -1;
        ret = get_tlv_shared_mem(SHARED_MEM_OEMKEY, strlen(SHARED_MEM_OEMKEY), g_secinfo, &size, true);
        if (ret != TLV_SHAREDMEM_SUCCESS) {
            tloge("get certkey failed\n");
            free(g_secinfo);
            g_secinfo = NULL;
            return -1;
        }
    }

    if (memcpy_s(secinfo, sizeof(struct tee_oemkey_info), g_secinfo, size) != EOK) {
        tloge("copy buf secinfo failed\n");
        return -1;
    }
    ret = oemkey_check_valid(secinfo);
    if (ret != 0) {
        tloge("get info fail\n");
        return -1;
    }
    return ret;
}

int32_t get_oemkey_info(unsigned long args, uint32_t args_len)
{
    int32_t ret;
    struct tee_oemkey_info secinfo;
    if (args == 0 || args_len != sizeof(struct oemkey_buffer_args)) {
        tloge("invalid args args_len:%u\n", args_len);
        return -1;
    }

    struct oemkey_buffer_args *input_arg = (struct oemkey_buffer_args *)(uintptr_t)args;

    ret = tee_crypto_get_oemkey((void *)&secinfo.provision_key, OEMKEY_SIZE);
    if (ret != 0) {
        tlogi("get oem key from shared mem\n");
        ret = tee_sharemem_get_oemkey(&secinfo);
        if (ret != 0) {
            tloge("get oemkey from shared mem failed\n");
            (void)memset_s(secinfo.provision_key, OEMKEY_SIZE, 0, OEMKEY_SIZE);
            return -1;
        }
    }
    ret = copy_to_client((uintptr_t)secinfo.provision_key, OEMKEY_SIZE, input_arg->oemkey_buffer, OEMKEY_SIZE);
    if (ret != 0) {
        (void)memset_s(secinfo.provision_key, OEMKEY_SIZE, 0, OEMKEY_SIZE);
        tloge("copy to client failed\n");
        return -1;
    }
    (void)memset_s(secinfo.provision_key, OEMKEY_SIZE, 0, OEMKEY_SIZE);
    return 0;
}
