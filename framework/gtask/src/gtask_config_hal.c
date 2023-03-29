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
#include "gtask_config_hal.h"
#include "gtask_config.h"
#include <tee_mem_mgmt_api.h>
#include <tee_log.h>
#include <string.h>
#include <tee_config.h>
#include "gtask_config.h"
#include "product_config_hal.h"
#include "tee_inner_uuid.h"

static const TEE_UUID g_uncommit_whitelist[] = {
    TEE_SERVICE_SSA,
    TEE_SERVICE_PERM
};

static const TEE_UUID g_vsroot_flush_whitelist[] = {
};

bool ta_no_uncommit(const TEE_UUID *uuid)
{
    if (uuid != NULL) {
        size_t nr = sizeof(g_uncommit_whitelist) / sizeof(TEE_UUID);
        for (size_t i = 0; i < nr; ++i) {
            if (!TEE_MemCompare(g_uncommit_whitelist + i, uuid, sizeof(TEE_UUID)))
                return true;
        }
    }
    return false;
}

bool ta_vsroot_flush(const TEE_UUID *uuid)
{
    if (uuid == NULL)
        return false;
    size_t nr = sizeof(g_vsroot_flush_whitelist) / sizeof(TEE_UUID);
    if (nr == 0)
        return false;

    for (size_t i = 0; i < nr; ++i) {
        if (!TEE_MemCompare(g_vsroot_flush_whitelist + i, uuid, sizeof(TEE_UUID)))
            return true;
    }
    return false;
}

/* next 3 functions for builtin task */
uint32_t get_builtin_task_nums(void)
{
    return get_product_builtin_task_num() + get_teeos_builtin_task_nums();
}

const struct task_info_st *get_builtin_task_info_by_index(uint32_t index)
{
    uint32_t builtin_task_num = get_builtin_task_nums();
    uint32_t teeos_builtin_nums = get_teeos_builtin_task_nums();
    const struct task_info_st *teeos_builtin_infos = NULL;
    const struct task_info_st *product_builtin_infos = NULL;

    if (index >= builtin_task_num)
        return NULL;

    if (index < teeos_builtin_nums) {
        teeos_builtin_infos = get_teeos_builtin_task_infos();
        if (teeos_builtin_infos == NULL)
            return NULL;
        return &teeos_builtin_infos[index];
    }

    product_builtin_infos = get_product_builtin_task_infos();
    if (product_builtin_infos == NULL)
        return NULL;
    return &product_builtin_infos[index - teeos_builtin_nums];
}

bool is_build_in_service(const TEE_UUID *uuid)
{
    uint32_t i;
    TEE_UUID global = TEE_SERVICE_GLOBAL;
    TEE_UUID reet = TEE_SERVICE_REET;
    uint32_t teeos_built_in_nums = get_teeos_builtin_task_nums();
    const struct task_info_st *teeos_builtin_infos = NULL;
    uint32_t product_builtin_task_num = get_product_builtin_task_num();
    const struct task_info_st *product_builtin_infos = NULL;

    if (uuid == NULL)
        return false;

    if (TEE_MemCompare(uuid, &global, sizeof(global)) == 0 ||
        TEE_MemCompare(uuid, &reet, sizeof(reet)) == 0)
        return true;

    for (i = 0; i < teeos_built_in_nums; i++) {
        teeos_builtin_infos = get_teeos_builtin_task_infos();
        if (teeos_builtin_infos == NULL)
            break;
        if (TEE_MemCompare(uuid, &(teeos_builtin_infos[i].uuid),
            sizeof(teeos_builtin_infos[0].uuid)) == 0)
            return true;
    }

    for (i = 0; i < product_builtin_task_num; i++) {
        product_builtin_infos = get_product_builtin_task_infos();
        if (product_builtin_infos == NULL)
            break;
        if (TEE_MemCompare(uuid, &(product_builtin_infos[i].uuid),
            sizeof(product_builtin_infos[0].uuid)) == 0)
            return true;
    }

    return false;
}

/* next 1 functions for service property */
uint32_t get_build_in_services_property(const TEE_UUID *uuid, struct ta_property *property)
{
    uint32_t i;
    uint32_t teeos_property_num = get_teeos_service_property_num();
    const struct ta_property *teeos_service_property = NULL;
    uint32_t product_property_num = get_product_service_property_num();
    const struct ta_property *product_service_property = NULL;

    if (uuid == NULL || property == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    for (i = 0; i < product_property_num; i++) {
        product_service_property = get_product_service_property_config();
        if (product_service_property == NULL)
            break;
        if (TEE_MemCompare(uuid, &product_service_property[i].uuid, sizeof(TEE_UUID)) == 0) {
            *property = product_service_property[i];
            return TEE_SUCCESS;
        }
    }

    for (i = 0; i < teeos_property_num; i++) {
        teeos_service_property = get_teeos_service_property_config();
        if (teeos_service_property == NULL)
            break;
        if (TEE_MemCompare(uuid, &teeos_service_property[i].uuid, sizeof(TEE_UUID)) == 0) {
            *property = teeos_service_property[i];
            return TEE_SUCCESS;
        }
    }
    return TEE_ERROR_GENERIC;
}

