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

#include "spawn_init.h"
#include <stdint.h>
#include <stddef.h>
#include <securec.h>
#include <tee_log.h>

int32_t set_env_for_task(const struct env_param *param, const struct tee_uuid *uuid, struct env_base_buffer *env)
{
    if ((param == NULL) || (uuid == NULL) || (env == NULL)) {
        tloge("set env invalid param\n");
        return -1;
    }

    int32_t ret = snprintf_s(env->priority, sizeof(env->priority), sizeof(env->priority) - 1,
        "priority=%d", param->priority);
    if (ret < 0) {
        tloge("set priority:%d failed:0x%x\n", param->priority, ret);
        return -1;
    }

    ret = snprintf_s(env->target_type, sizeof(env->target_type), sizeof(env->target_type) - 1,
        "target_type=%u", param->target_type);
    if (ret < 0) {
        tloge("set target type:%u failed:0x%x\n", param->target_type, ret);
        return -1;
    }

    return 0;
}

int32_t set_drv_env_for_task(const struct env_param *param, struct env_drv_base_buffer *env)
{
    if (param == NULL || env == NULL) {
        tloge("invalid drv param or env\n");
        return -1;
    }

    int32_t ret = snprintf_s(env->drv_index, sizeof(env->drv_index), sizeof(env->drv_index) - 1,
        "drv_index=%u", param->drv_index);
    if (ret < 0) {
        tloge("set drv index:%u failed:0x%x\n", param->drv_index, ret);
        return -1;
    }

    ret = snprintf_s(env->thread_limit, sizeof(env->thread_limit), sizeof(env->thread_limit) - 1,
        "thread_limit=%u", param->thread_limit);
    if (ret < 0) {
        tloge("set thread limit:%u failed:0x%x\n", param->thread_limit, ret);
        return -1;
    }

    ret = snprintf_s(env->stack_size, sizeof(env->stack_size), sizeof(env->stack_size) - 1,
        "stack_size=%u", param->stack_size);
    if (ret < 0) {
        tloge("set stack size:%u failed:0x%x\n", param->stack_size, ret);
        return -1;
    }

    return 0;
}
