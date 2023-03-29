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
#ifndef LIBTIMER_TIMER_EVENT_H
#define LIBTIMER_TIMER_EVENT_H
#include <sys_timer.h>

timer_event *tee_time_event_create(sw_timer_event_handler handler, int32_t timer_class, void *priv_data);
uint32_t tee_time_event_destroy(timer_event *t_event);
uint32_t tee_time_event_start(timer_event *t_event, timeval_t *time);
uint32_t tee_time_event_stop(timer_event *t_event);
uint32_t tee_time_event_check(timer_notify_data_kernel *timer_data);
uint64_t tee_time_event_get_expire(timer_event *t_event);

#endif
