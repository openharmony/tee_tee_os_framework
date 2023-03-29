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

#ifndef DYN_CONG_BUILDED_DRV_DYN_CONF_BUILDER_H
#define DYN_CONG_BUILDED_DRV_DYN_CONF_BUILDER_H

#include "dyn_conf_dispatch_inf.h"

struct tag_crew {
    uint32_t item_tag;
    uint32_t data_tag;
    uint32_t type_tag;
    char split_tag;
};

int32_t install_drv_permission(void *obj, uint32_t obj_size, const struct conf_queue_t *conf_queue);
void uninstall_drv_permission(const void *obj, uint32_t obj_size);
void dump_drv_conf(void);

#endif
