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
#include "gtask_config.h"
#include "tee_config.h"
#include <priorities.h> /* for HM_PRIO_TEE_* */

const struct task_info_st g_teeos_builtin_task_infos[] = {
#ifdef TEE_SUPPORT_SSA_64BIT
    { TEE_SERVICE_SSA, SSA_SERVICE_NAME, "/ssa.elf", HM_PRIO_TEE_AGENT, true },
#elif TEE_SUPPORT_SSA_32BIT
    { TEE_SERVICE_SSA, SSA_SERVICE_NAME, "/ssa.elf", HM_PRIO_TEE_AGENT, false },
#endif
#ifdef TEE_SUPPORT_HUK_SERVICE_64BIT
    { TEE_SERVICE_HUK, HUK_TASK_NAME, "/huk_service.elf", HM_PRIO_TEE_AGENT, true },
#elif TEE_SUPPORT_HUK_SERVICE_32BIT
    { TEE_SERVICE_HUK, HUK_TASK_NAME, "/huk_service.elf", HM_PRIO_TEE_AGENT, false },
#endif
#ifdef TEE_SUPPORT_PERM_64BIT
    {TEE_SERVICE_PERM, PERM_SERVICE_NAME, "/permission_service.elf", HM_PRIO_TEE_AGENT, true},
#elif TEE_SUPPORT_PERM_32BIT
    {TEE_SERVICE_PERM, PERM_SERVICE_NAME, "/permission_service.elf", HM_PRIO_TEE_AGENT, false},
#endif
};

static const uint32_t g_teeos_builtin_task_num =
    sizeof(g_teeos_builtin_task_infos) / sizeof(g_teeos_builtin_task_infos[0]);

uint32_t get_teeos_builtin_task_nums(void)
{
    return g_teeos_builtin_task_num;
}

const struct task_info_st *get_teeos_builtin_task_infos(void)
{
    return g_teeos_builtin_task_infos;
}

#define SSA_SHRINK_STACK_DIV  4
#define SSA_DEFAULT_STACK_MUL 8
#define SSA_DEFAULT_HEAP_MUL  8
#define RPMB_DEFAULT_HEAP_MUL 8
#define RPMB_HUK_STACK_DIV    4
#define RPMB_HUK_HEAP_DIV     2
#define SSA_DEFAULT_HEAP_HEAPMGR_MUL  24
#define HUK_DEFAULT_HEAP_HEAPMGR_MUL  24
#define PERM_SRV_STACK_SIZE (DEFAULT_STACK_SIZE * 8)
#define PERM_SRV_HEAP_SIZE  (DEFAULT_HEAP_SIZE * 3)
#define PERM_SRV_DEFAULT_HEAP_HEAPMGR_MUL  (DEFAULT_HEAP_SIZE * 24)

/* build in service propertys for teeos */
const struct ta_property g_teeos_service_property[] = {
    /* uuid  stack  heap  instance multi_session  alive ssa_enum_enable other_property other_property_len */
    { TEE_SERVICE_REET, DEFAULT_STACK_SIZE, DEFAULT_HEAP_SIZE, true, false, false, false, NULL, 0 },
#if (defined TEE_SUPPORT_SSA_64BIT || defined TEE_SUPPORT_SSA_32BIT)
    { TEE_SERVICE_SSA, DEFAULT_STACK_SIZE * SSA_DEFAULT_STACK_MUL, DEFAULT_HEAP_SIZE * SSA_DEFAULT_HEAP_MUL,
      true, false, false, false, NULL, 0 },
#endif
#if (defined TEE_SUPPORT_HUK_SERVICE_32BIT || defined TEE_SUPPORT_HUK_SERVICE_64BIT)
    { TEE_SERVICE_HUK, DEFAULT_STACK_SIZE / RPMB_HUK_STACK_DIV, DEFAULT_HEAP_SIZE / RPMB_HUK_HEAP_DIV,
      true, false, false, false, NULL, 0 },
#endif
#if (defined TEE_SUPPORT_PERM_64BIT || defined TEE_SUPPORT_PERM_32BIT)
    { TEE_SERVICE_PERM, PERM_SRV_STACK_SIZE, PERM_SRV_HEAP_SIZE, true, false, false, false, NULL, 0 },
#endif
};

static const uint32_t g_teeos_service_property_num =
    sizeof(g_teeos_service_property) / sizeof(g_teeos_service_property[0]);

uint32_t get_teeos_service_property_num(void)
{
    return g_teeos_service_property_num;
}

const struct ta_property *get_teeos_service_property_config(void)
{
    return g_teeos_service_property;
}

