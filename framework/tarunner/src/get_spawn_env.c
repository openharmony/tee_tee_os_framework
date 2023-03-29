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
#include "get_spawn_env.h"
#include <stdlib.h>
#include <alltypes.h>
#include <errno.h>
#include <tee_log.h>
#include <target_type.h>
#include "load_init.h"

static uint32_t get_u32_env(const char *env_name)
{
    uint32_t val = UINT32_MAX;
    char *env_var = getenv(env_name);

    if (env_var == NULL) {
        tloge("get %s env fail\n", env_name);
    } else {
        errno = 0;
        unsigned long temp = strtoul(env_var, NULL, DECIMAL_BASE);
        if (errno != 0) {
            tloge("%s invalid env:%s\n", env_name, env_var);
            return UINT32_MAX;
        }

#ifdef __aarch64__
        if (temp > UINT32_MAX) {
            tloge("%s value is invalid\n", env_name);
            return UINT32_MAX;
        }
#endif

        val = (uint32_t)temp;
    }

    return val;
}

static int32_t get_drv_env_param(struct env_param *param)
{
    param->drv_index = get_u32_env("drv_index");
    if (param->drv_index == UINT32_MAX)
        return -1;

    param->thread_limit = get_u32_env("thread_limit");
    if (param->thread_limit == UINT32_MAX)
        return -1;

    param->stack_size = get_u32_env("stack_size");
    if (param->stack_size == UINT32_MAX)
        return -1;

    return 0;
}

int32_t get_env_param(struct env_param *param)
{
    if (param == NULL) {
        tloge("invalid env param\n");
        return -1;
    }

    param->priority = get_priority();

    param->target_type = get_u32_env("target_type");
    if (param->target_type >= MAX_TARGET_TYPE) {
        tloge("invalid target_type:0x%x\n", param->target_type);
        return -1;
    }

    if (param->target_type == DRV_TARGET_TYPE)
        return get_drv_env_param(param);

    return 0;
}
