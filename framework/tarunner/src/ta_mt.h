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
#ifndef TA_MT_TA_MT_H
#define TA_MT_TA_MT_H

#include <stdint.h>
#include <ta_routine.h> /* for ta_routine_info */

#define INIT_BUILD 0
#define NON_INIT_BUILD 1

#define SECOND_CHANNEL 1
#define DEFAULT_MSG_HANDLE 0
#define CREATE_THREAD_FAIL 0xFFFFFFFFU /* same to gtask */
void tee_task_entry_mt(ta_entry_type ta_entry, int32_t priority, const char *name,
    const struct ta_routine_info *append_args);

#endif
