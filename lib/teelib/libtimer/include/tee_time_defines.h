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
#ifndef LIBTIMER_TIMER_DEFINES_H
#define LIBTIMER_TIMER_DEFINES_H

#include <dlist.h>
#include <limits.h>
#include <tee_defines.h>
#include <ipclib.h>
#include "tee_msg_type.h"
#define TIMER_PATH    "hmtimer"

#define TMR_OK  0
#define TMR_ERR 1

#define TIMER_INDEX_RTC   0
#define TIMER_INDEX_TIMER 1

#define IPC_NAME_MAX      32
#define MAX_NUM_OF_TIMERS 2

#define TIMER_CREATE_SECONDS_THRESHOLD 2
#define MAX_SECONDS_PER_YEAR 31622400LL
#define NS_PER_SECONDS 1000000000L
#define NS_PER_MSEC    1000000
#define US_PER_SECONDS 1000000
#define MS_PER_SECONDS 1000
#define US_PER_MSEC    1000
#define NS_PER_USEC    1000

#define TIMER_INV_VALUE   0
#define TIMEVAL_MAX       ((int64_t) ((~((uint64_t)1 << 63)) & (~((uint64_t)0xFFFFFFFF))))
#define UPPER_32_BITS(n) ((uint32_t)(((uint64_t)(n)) >> 32))
#define LOWER_32_BITS(n) ((uint32_t)(n))

#define INVALID_SESSION_ID             0

/* The timer event is Inactive */
#define TIMER_STATE_INACTIVE 0x00U
/* The timer event is active and is waiting for expiration */
#define TIMER_STATE_ACTIVE 0x01U
/* The timer is expired and is waiting on the callback list to be executed */
#define TIMER_STATE_PENDING 0x02U
/* The timer event is currently being executed */
#define TIMER_STATE_EXECUTING 0x04U
/* The timer event is currently being destroy */
#define TIMER_STATE_DESTROY 0x05U

#define CMD_TIMER_GENERIC 0xDDEA
#define CMD_TIMER_RTC     0xDDEB

#define EPOCH_YEAR      1970
#define DAYSPERLYEAR    366
#define DAYSPERNYEAR    365

#define MINSPERHOUR     60
#define SECSPERMIN      60
#define SECSPERHOUR     (SECSPERMIN * MINSPERHOUR)
#define SECSPERDAY      (SECSPERHOUR * HOURSPERDAY)

#define DAYSPERWEEK     7
#define HOURSPERDAY     24

#define MONSPERYEAR     12
#define TIME_ZONE_EIGHT 8


#define TIMER_MSG_NUM_MAX            16
#define TIMER_RMSG_MAX_NUM           4
#define TIME_OUT_NEVER (-1)

struct timer_req_msg_t {
    msg_header header;
    uint64_t args[TIMER_MSG_NUM_MAX];
    cref_t job_handler;
} __attribute__((__packed__));

struct timer_reply_msg_t {
    msg_header header;
    cref_t tcb_cref;
    uint64_t regs[TIMER_RMSG_MAX_NUM];
} __attribute__((__packed__));

#define TIMER_REQ_MSG_SIZE (sizeof(struct timer_req_msg_t))
#define TIMER_REP_MSG_SIZE (sizeof(struct timer_reply_msg_t))

/*
 * Some functions have been exported to other module use this struct as a parameter,
 * so we cannot modify the typdef, and cannot delete the struct also.
 */
typedef union {
    int64_t tval64;
    struct {
        int32_t nsec;
        int32_t sec;
    } tval;
} timeval_t;

/*
 * The elements of this structure are useful
 * for implementing the sw_timer
 */
struct sw_timer_info {
    timeval_t sw_timestamp;
    uint64_t abs_cycles_count;
    uint64_t cycles_count_old;
    uint64_t cycles_count_new;
    timeval_t timer_period;
    timeval_t clock_period;
};

enum timer_class_type {
    /* timer event using timer10 */
    TIMER_GENERIC,
    /* timer event using RTC */
    TIMER_RTC,
    TIMER_CLASSIC,
};

enum timer_callback_mode {
    /* The handler function should be run in softirq */
    TIMER_CALLBACK_SOFTIRQ,
    /* The handler function should be run in hardirq context itself */
    TIMER_CALLBACK_HARDIRQ,
    /* The handler function should be executed in hardirq and it should not
     * restart the timer */
    TIMER_CALLBACK_HARDIRQ_NORESTART,
    /* A special callback mode for timeout notification */
    TIMER_CALLBACK_TIMEOUT
};

typedef int32_t (*sw_timer_event_handler)(void *);

struct sw_timer_event_hdl_info {
    sw_timer_event_handler hdl;
    void *priv_data;
};

struct timer_clock_info {
    struct timer_cpu_info *cpu_info;
    int clock_id;
    /* list for active timer event */
    struct dlist_node active;
    /* list for created timer event */
    struct dlist_node avail;
    timeval_t clock_period;
    timeval_t timer_period;
    int shift;
    uint32_t mult;
};

struct timer_cpu_info {
    /* 0 for RTC, 1 for timer60 */
    struct timer_clock_info clock_info[MAX_NUM_OF_TIMERS];
    timeval_t expires_next[MAX_NUM_OF_TIMERS];
};

struct timer_private_data_kernel {
    uint32_t dev_id;
    struct tee_uuid uuid;
    uint32_t session_id;
    uint32_t type;
    uint32_t expire_time;
};

typedef struct {
    /* node for active timer event */
    struct dlist_node node;
    struct dlist_node callback_entry;
    /* node for created timer event */
    struct dlist_node c_node;
    uint64_t handle;
    timeval_t expires;
    struct timer_clock_info *clk_info;
    int32_t (*handler)(void *);
    uint32_t state;
    int callback_mode;
    /* 0:timer60, 1:RTC */
    int32_t timer_class;
    struct timer_private_data_kernel timer_attr;
    int32_t pid;
    uint32_t app_handler;
    cref_t timer_channel;
    char path_name[IPC_NAME_MAX];
    void *data;
} timer_event;

struct timer_attr_data_kernel {
    uint32_t type;
    uint32_t timer_id;
    uint32_t timer_class;
    uint64_t handle;
};

/*
 * Some functions have been exported to other module use this struct as a parameter,
 * so we cannot modify the typdef, and cannot delete the struct also.
 */
typedef struct {
    uint32_t dev_id;
    struct tee_uuid uuid;
    uint32_t session_id;
    struct timer_attr_data_kernel property;
    uint32_t expire_time;
} timer_notify_data_kernel;

typedef struct tee_time_t {
    int32_t seconds;
    int32_t millis;
} tee_time_kernel;

typedef struct tee_date_t {
    int32_t seconds;
    int32_t millis;
    int32_t min;
    int32_t hour;
    int32_t day;
    int32_t month;
    int32_t year;
} tee_date_time_kernel;

struct tee_time_stamp {
    uint32_t seconds;
    uint32_t nanos;
};

void release_timer_event(const TEE_UUID *uuid);
#endif
