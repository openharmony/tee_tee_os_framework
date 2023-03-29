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

#include <mem_ops.h>
#include <stdint.h>
#include "drv_io_share.h"
#include "drv_addr_share.h"
#include "iomgr_ext.h"
#include "drv_thread.h"

void *ioremap(uintptr_t phys_addr, unsigned long size, int32_t prot)
{
    return hm_io_remap((uintptr_t)phys_addr, NULL, size, prot);
}

int32_t iounmap(uintptr_t pddr, const void *addr)
{
    return hm_io_unmap(pddr, addr);
}

uint64_t drv_virt_to_phys(uintptr_t addr)
{
    return virt_to_phys(addr);
}
