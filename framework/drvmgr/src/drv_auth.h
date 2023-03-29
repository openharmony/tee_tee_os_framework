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
#ifndef DRVMGR_SRC_DRV_AUTH_H
#define DRVMGR_SRC_DRV_AUTH_H
#include <stdint.h>
#include <stdbool.h>
#include <tee_defines.h>
#include "drvcall_dyn_conf_mgr.h"
#include "drv_dyn_conf_mgr.h"
#include "task_mgr.h"

bool drv_mac_open_auth_check(const struct drv_conf_t *drv_conf, const struct tee_uuid *uuid);
bool caller_open_auth_check(const struct task_node *call_node, const char *drv_name, uint32_t name_len);
int32_t get_drvcaller_cmd_perm(const struct task_node *call_node, const struct task_node *dnode, uint64_t *perm);

#endif
