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

#ifndef DYN_CONG_BUILDED_DRVCALL_DYN_CONF_BUILDER_H
#define DYN_CONG_BUILDED_DRVCALL_DYN_CONF_BUILDER_H

#include <dyn_conf_common.h>
#include "dyn_conf_dispatch_inf.h"

enum drv_perm_tags {
    DRV_PERM = 0x0,
    DRV_PERM_DRVCALL_PERM_APPLY = 0x1,
    DRV_PERM_DRVCALL_PERM_APPLY_ITEM,
    DRV_PERM_DRVCALL_PERM_APPLY_ITEM_NAME,
    DRV_PERM_DRVCALL_PERM_APPLY_ITEM_PERMISSION,
    DRV_PERM_DRV_BASIC_INFO,
    DRV_PERM_DRV_BASIC_INFO_THREAD_LIMIT,
    DRV_PERM_DRV_BASIC_INFO_UPGRADE,
    DRV_PERM_DRV_BASIC_INFO_VIRT2PHYS,
    DRV_PERM_DRV_BASIC_INFO_EXCEPTION_MODE,
    DRV_PERM_DRV_IO_MAP,
    DRV_PERM_DRV_IO_MAP_ITEM,
    DRV_PERM_DRV_IO_MAP_ITEM_CHIP_TYPE,
    DRV_PERM_DRV_IO_MAP_ITEM_IOMAP,
    DRV_PERM_IRQ,
    DRV_PERM_IRQ_ITEM,
    DRV_PERM_IRQ_ITEM_CHIP_TYPE,
    DRV_PERM_IRQ_ITEM_IRQ,
    DRV_PERM_MAP_SECURE,
    DRV_PERM_MAP_SECURE_ITEM,
    DRV_PERM_MAP_SECURE_ITEM_CHIP_TYPE,
    DRV_PERM_MAP_SECURE_ITEM_UUID,
    DRV_PERM_MAP_SECURE_ITEM_REGION,
    DRV_PERM_MAP_NOSECURE,
    DRV_PERM_MAP_NOSECURE_ITEM,
    DRV_PERM_MAP_NOSECURE_ITEM_CHIP_TYPE,
    DRV_PERM_MAP_NOSECURE_ITEM_UUID,
    DRV_PERM_DRV_CMD_PERM_INFO,
    DRV_PERM_DRV_CMD_PERM_INFO_ITEM,
    DRV_PERM_DRV_CMD_PERM_INFO_ITEM_CMD,
    DRV_PERM_DRV_CMD_PERM_INFO_ITEM_PERMISSION,
    DRV_PERM_DRV_MAC_INFO,
    DRV_PERM_DRV_MAC_INFO_ITEM,
    DRV_PERM_DRV_MAC_INFO_ITEM_UUID,
    DRV_PERM_DRV_MAC_INFO_ITEM_PERMISSION,
    DRV_PERM_UNUSED,
};

int32_t install_drvcall_permission(void *obj, uint32_t obj_size, const struct conf_queue_t *conf_queue);
void uninstall_drvcall_permission(const void *obj, uint32_t obj_size);
void dump_drvcall_conf(void);
int32_t combine_perms(uint64_t *perm, uint32_t size, const char *value);

int32_t init_drvcall_conf(struct drvcall_perm_apply_t *drvcall_perm_apply,
                          const struct conf_queue_t *conf_queue);

void free_drvcall_perm(struct drvcall_perm_apply_t *drvcall_perm);

int32_t build_drvcall_perm_apply(struct dlist_node **pos, const struct conf_node_t *node,
                                 void *obj, uint32_t obj_size);
#endif
