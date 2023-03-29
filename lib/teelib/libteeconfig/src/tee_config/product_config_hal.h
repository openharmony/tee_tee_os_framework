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
#ifndef PRODUCT_CONFIG_HAL_H
#define PRODUCT_CONFIG_HAL_H

#include <stdint.h>
#include <stddef.h>

const struct dynamic_mem_uuid_item *get_dyn_mem_config(void);
uint32_t get_dyn_mem_config_num(void);

const struct drvlib_load_caller_info *get_drvlib_load_caller_infos(void);
uint32_t get_drvlib_load_caller_nums(void);

const struct task_info_st *get_product_builtin_task_infos(void);
uint32_t get_product_builtin_task_num(void);

const struct rsv_mem_pool_uuid_item *get_rsv_mem_pool_config(void);
uint32_t get_rsv_mem_pool_config_num(void);

uint32_t get_product_service_property_num(void);
const struct ta_property *get_product_service_property_config(void);

uint32_t get_product_dynamic_ta_num(void);
#endif
