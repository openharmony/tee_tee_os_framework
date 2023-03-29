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

#ifndef GTASK_CONFIG_HAL_H
#define GTASK_CONFIG_HAL_H
#include <ta_framework.h>

bool ta_no_uncommit(const TEE_UUID *uuid);
bool ta_vsroot_flush(const TEE_UUID *uuid);

uint32_t get_build_in_services_property(const TEE_UUID *uuid, struct ta_property *property);
bool is_build_in_service(const TEE_UUID *uuid);
const struct task_info_st *get_builtin_task_info_by_index(uint32_t index);
uint32_t get_builtin_task_nums(void);

#endif
