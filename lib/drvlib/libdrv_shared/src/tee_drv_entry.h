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
#ifndef LIBDRV_SHARED_SRC_TEE_DRV_ENTRY_H
#define LIBDRV_SHARED_SRC_TEE_DRV_ENTRY_H

#include <stdio.h>
#include <spawn_init.h>
#include <tee_driver_module.h>
#include <ipclib.h>

typedef void (*drv_entry_func)(const struct tee_driver_module *drv_func, const char *drv_name,
    cref_t channel, const struct env_param *param);

taskid_t get_drv_mgr_pid(void);
const struct tee_driver_module *get_drv_func(void);
uint32_t get_drv_index(void);

#endif
