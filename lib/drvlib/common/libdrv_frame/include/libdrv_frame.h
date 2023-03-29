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
#ifndef LIBDRV_FRAME_DRV_FRAME_H
#define LIBDRV_FRAME_DRV_FRAME_H

#include <stdbool.h>

typedef int32_t (*drv_frame_init_t)(void);

struct drv_frame_t {
    const char *name;
    bool is_irq_triggered;
    drv_frame_init_t init;
};

int32_t drv_framework_init(const struct drv_frame_t *drv_frame);
int32_t register_drv_framework(const struct drv_frame_t *drv_frame, cref_t *ch, bool new_frame);
#endif
