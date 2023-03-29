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
#ifndef BASE_DRV_NODE_H
#define BASE_DRV_NODE_H
#include <stdio.h>
#include "task_mgr.h"

#define TEE_MISC_DRIVER                                    \
    {                                                      \
        0x5bb40be1, 0x6b49, 0x421c,                        \
        {                                                  \
            0x9d, 0xd5, 0x79, 0xf5, 0xcb, 0xde, 0x3f, 0xb3 \
        }                                                  \
    }

#define CRYPTOMGR                                     \
    {                                                      \
        0x2427f879, 0x4655, 0x4367,                        \
        {                                                  \
            0x82, 0x31, 0xe5, 0x8e, 0x29, 0x45, 0xc9, 0xb8 \
        }                                                  \
    }

#define TEE_MISC_DRIVER_NAME "tee_misc_driver"
#define TEE_CRYPTO_DRIVER_NAME   "crypto_mgr"
#define TEE_MISC_DRV_SIZE 15
struct base_driver_node {
    struct tee_uuid uuid;
    struct drv_mani_t mani;
    struct drv_basic_info_t drv_basic_info;
};

bool get_base_drv_flag(const char *drv_name, uint32_t drv_name_size);
#endif
