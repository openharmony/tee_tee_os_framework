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
#ifndef DRVMGR_DYN_CONF_COMMON_H
#define DRVMGR_DYN_CONF_COMMON_H

#include <stdint.h>
#include <tee_defines.h>
#include <tee_driver_module.h>

struct drv_mani_t {
    struct tee_uuid srv_uuid;
    char service_name[DRV_NAME_MAX_LEN + 1];
    uint32_t service_name_size;
    bool keep_alive;
    uint32_t data_size;
    uint32_t stack_size;
    uint16_t hardware_type;
};

struct drvcall_perm_apply_item_t {
    char name[DRV_NAME_MAX_LEN + 1];
    uint32_t name_size;
    uint64_t perm;
};

struct drvcall_perm_apply_t {
    union {
        struct drvcall_perm_apply_item_t *drvcall_perm_apply_list; /* drvcall_perm_apply items list */
        uint64_t temp_drvcall_perm_list;
    };
    uint32_t drvcall_perm_apply_list_size;
    bool base_perm;
};

#endif
