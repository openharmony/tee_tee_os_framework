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
#ifndef LIBTIMER_GENERIC_TIMER_H
#define LIBTIMER_GENERIC_TIMER_H
#include <stdint.h>

static inline uint64_t get_cntpct_el0(void)
{
    uint64_t val;
    __asm__ volatile("mrs %0, CNTPCT_EL0" : "=r"(val));
    return val;
}

static inline uint64_t get_cntfrq_el0(void)
{
    uint64_t val;
    __asm__ volatile("mrs %0, CNTFRQ_EL0" : "=r"(val));
    return val;
}
#endif
