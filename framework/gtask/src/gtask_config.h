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
#ifndef GTASK_CONFIG_H
#define GTASK_CONFIG_H
#include <stdint.h>

/* for builtin task */
uint32_t get_teeos_builtin_task_nums(void);
const struct task_info_st *get_teeos_builtin_task_infos(void);

/* for service property */
uint32_t get_teeos_service_property_num(void);
const struct ta_property *get_teeos_service_property_config(void);

#endif
