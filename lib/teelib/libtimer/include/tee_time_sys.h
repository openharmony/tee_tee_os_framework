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
#ifndef LIBTIMER_TEE_TIME_SYS_H
#define LIBTIMER_TEE_TIME_SYS_H
#include <tee_time_defines.h>

uint64_t tee_read_time_stamp(void);
void get_sys_date_time(tee_date_time_kernel *time_date);
void gen_sys_date_time(uint32_t secs, tee_date_time_kernel *date_time);
struct tm *__localtime_r(const time_t *restrict, struct tm *restrict);
uint32_t adjust_sys_time(const struct tee_time_t *time);
int set_ta_timer_permission(const TEE_UUID *uuid, uint64_t permission);
void release_timer_event(const TEE_UUID *uuid);
int tee_timer_init(void);
#endif
