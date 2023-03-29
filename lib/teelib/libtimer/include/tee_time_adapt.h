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
#ifndef LIBTIMER_TIMER_ADAPT_H
#define LIBTIMER_TIMER_ADAPT_H

#define SHIFT_32        32U

typedef uint64_t (*timer_read_time_stamp)(void);
typedef void (*timer_get_sys_rtc_time)(TEE_Time *time);
typedef uint32_t (*timer_get_rtc_seconds)(void);
typedef uint32_t (*timer_sleep)(uint32_t msec);
typedef timer_event *(*timer_time_event_create)(sw_timer_event_handler handler, int32_t timer_class, void *priv_data);
typedef uint32_t (*timer_time_event_destroy)(timer_event *t_event);
typedef uint32_t (*timer_time_event_start)(timer_event *t_event, timeval_t *time);
typedef uint32_t (*timer_time_event_stop)(timer_event *t_event);
typedef uint64_t (*timer_time_event_get_expire)(timer_event *t_event);
typedef uint32_t (*timer_time_event_check)(timer_notify_data_kernel *timer_data);
typedef void (*timer_release_timer_event)(const TEE_UUID *uuid);
typedef int32_t (*timer_set_ta_timer_permission)(const TEE_UUID *uuid, uint64_t permission);
typedef uint32_t (*timer_adjust_sys_time)(const struct tee_time_t *time);
typedef int (*timer_tee_timer_init)(void);
typedef int (*timer_renew_hmtimer_job_handler)(void);

struct timer_ops_t {
    timer_read_time_stamp read_time_stamp;
    timer_get_sys_rtc_time get_sys_rtc_time;
    timer_get_rtc_seconds get_rtc_seconds;
    timer_sleep sleep;
    timer_time_event_create time_event_create;
    timer_time_event_destroy time_event_destroy;
    timer_time_event_start time_event_start;
    timer_time_event_stop time_event_stop;
    timer_time_event_get_expire time_event_get_expire;
    timer_time_event_check time_event_check;
    timer_release_timer_event release_timer_event;
    timer_set_ta_timer_permission set_ta_timer_permission;
    timer_adjust_sys_time adjust_sys_time;
    timer_tee_timer_init tee_timer_init;
    timer_renew_hmtimer_job_handler renew_hmtimer_job_handler;
};

struct timer_event_private_data {
    uint32_t dev_id;
    TEE_UUID uuid;
    uint32_t session_id;
    uint32_t type;
    uint32_t expire_time;
};

static inline struct timer_ops_t *get_time_ops(void)
{
    return NULL;
}
#endif