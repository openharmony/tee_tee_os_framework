/*
 * Copyright (C) 2024 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "tee_rtc_time_api.h"

TEE_Result tee_ext_create_timer(uint32_t time_seconds, TEE_timer_property *timer_property)
{
    (void)time_seconds;
    (void)timer_property;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_destory_timer(TEE_timer_property *timer_property)
{
    (void)timer_property;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_get_timer_expire(TEE_timer_property *timer_property, uint32_t *time_seconds)
{
    (void)time_seconds;
    (void)timer_property;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_get_timer_remain(TEE_timer_property *timer_property, uint32_t *time_seconds)
{
    (void)time_seconds;
    (void)timer_property;
    return TEE_ERROR_NOT_SUPPORTED;
}

unsigned int tee_get_secure_rtc_time(void)
{
    return TEE_ERROR_NOT_SUPPORTED;
}