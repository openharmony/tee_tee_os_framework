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
#include <sys/mman.h>
#include <malloc.h>
#include <securec.h>
#include <mem_ops.h>
#include <tee_log.h>
#include <ipclib.h>
#include <mem_page_ops.h>
#include <drv.h>
#include <tee_sharemem_ops.h>

static int32_t copy_task_param_check(uint64_t src, uint32_t src_size, uint64_t dst, uint32_t dst_size)
{
    if (src == 0 || dst == 0 || src_size == 0 || dst_size == 0 || src_size > dst_size) {
        tloge("invalid param src size:0x%x dst size:0x%x\n", src_size, dst_size);
        return -1;
    }

    if (src + src_size < src) {
        tloge("invalid src buffer size:0x%x\n", src_size);
        return -1;
    }

    if (dst + dst_size < dst) {
        tloge("invalid dst buffer size:0x%x\n", dst_size);
        return -1;
    }

    return 0;
}

int32_t copy_from_sharemem(uint32_t src_task, uint64_t src, uint32_t src_size, uintptr_t dst, uint32_t dst_size)
{
    int32_t ret;
    uint64_t temp_dst;

    ret = copy_task_param_check(src, src_size, dst, dst_size);
    if (ret != 0)
        return -1;

    ret = map_sharemem(src_task, src, src_size, &temp_dst);
    if (ret != 0) {
        tloge("map sharemem failed, src_task:0x%x\n", src_task);
        return -1;
    }

    ret = memcpy_s((void *)dst, dst_size, (void *)(uintptr_t)temp_dst, src_size);
    if (ret != EOK) {
        tloge("copy buffer from sharemem failed\n");
        if (unmap_sharemem((void *)(uintptr_t)temp_dst, src_size) != 0)
            tloge("unmap temp dst failed in from sharemem\n");
        return -1;
    }

    if (unmap_sharemem((void *)(uintptr_t)temp_dst, src_size) != 0) {
        tloge("something wrong, unmap temp dst failed in from sharemem\n");
        return -1;
    }

    return 0;
}

int32_t copy_to_sharemem(uintptr_t src, uint32_t src_size, uint32_t dst_task, uint64_t dst, uint32_t dst_size)
{
    int32_t ret;
    uint64_t temp_dst;

    ret = copy_task_param_check(src, src_size, dst, dst_size);
    if (ret != 0)
        return -1;

    ret = map_sharemem(dst_task, dst, dst_size, &temp_dst);
    if (ret != 0) {
        tloge("map sharemem failed, dst_task:0x%x\n", dst_task);
        return -1;
    }

    ret = memcpy_s((void *)(uintptr_t)temp_dst, dst_size, (void *)src, src_size);
    if (ret != EOK) {
        tloge("copy buffer to sharemem failed\n");
        if (unmap_sharemem((void *)(uintptr_t)temp_dst, dst_size) != 0)
            tloge("unmap temp dst failed in to sharemem\n");
        return -1;
    }

    if (unmap_sharemem((void *)(uintptr_t)temp_dst, dst_size) != 0) {
        tloge("something wrong, unmap temp dst failed in to sharemem\n");
        return -1;
    }

    return 0;
}

void *tee_alloc_coherent_sharemem_aux(const struct tee_uuid *uuid, uint32_t size)
{
    (void)uuid;
    (void)size;
    return NULL;
}

void *tee_alloc_sharemem_aux(const struct tee_uuid *uuid, uint32_t size)
{
    return alloc_sharemem_aux(uuid, size);
}

uint32_t tee_free_sharemem(void *addr, uint32_t size)
{
    return free_sharemem(addr, size);
}