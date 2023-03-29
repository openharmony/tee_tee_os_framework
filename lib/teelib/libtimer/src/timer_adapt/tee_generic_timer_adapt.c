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
#include <securec.h>
#include <pthread.h>
#include <sys_timer.h>
#include <tee_log.h>
#include <timemgr_api.h>
#include <generic_timer.h>
#include <tee_time_adapt.h>
#include <tee_mem_mgmt_api.h>
#include <ipclib.h>

enum classic_timer_msg {
    CREATE_TIMER,
    START_TIMER,
    STOP_TIMER,
    DESTORY_TIMER,
    TIMER_OPS_SUCCESS,
    TIMER_OPS_FAIL,
};

struct timer_event_msg {
    msg_header hdr;
};

static struct tee_time_t g_rtc_offset;

static uint64_t tee_read_time_stamp(void)
{
    uint64_t cur_count;
    uint32_t freq;
    uint64_t timestamp;
    uint32_t sec;
    uint32_t nsec;

    cur_count = get_cntpct_el0();
    freq = get_cntfrq_el0();
    if (freq == 0)
        return TIMER_INV_VALUE;

    sec = cur_count / freq;
    nsec = ((cur_count % freq) * NS_PER_SECONDS) / freq;
    timestamp = ((uint64_t)sec << SHIFT_32) + nsec;
    return timestamp;
}

static uint32_t tee_sleep(msec)
{
    TEE_Result ret;
    cref_t timer_ref;

    timer_ref = create_timer();
    if (!check_ref_valid(timer_ref))
        return TMR_ERR;

    ret = timer_start(timer_ref, msec);
    delete_timer(timer_ref);
    return ret;
}

static int64_t timer_value_add(const timeval_t *time_val_1, const timeval_t *time_val_2)
{
    timeval_t time_val_sum;

    if (time_val_1 == NULL || time_val_2 == NULL) {
        tloge("invalid param\n");
        return TIMEVAL_MAX;
    }

    if ((time_val_1->tval64 > 0 && time_val_2->tval64 > 0 && INT64_MAX - time_val_1->tval64 < time_val_2->tval64) ||
        (time_val_1->tval64 < 0 && time_val_2->tval64 < 0 && INT64_MIN - time_val_1->tval64 > time_val_2->tval64)) {
        tloge("Time value add result overflow\n");
        return TIMEVAL_MAX;
    }

    if ((time_val_1->tval.nsec >= NS_PER_SECONDS) || (time_val_2->tval.nsec >= NS_PER_SECONDS)) {
        tlogw("timer value add:invalid nsec value\n");
        time_val_sum.tval.sec = time_val_1->tval.sec + time_val_2->tval.sec;
        time_val_sum.tval.nsec = 0;
    } else {
        time_val_sum.tval64 = time_val_1->tval64 + time_val_2->tval64;
        if (time_val_sum.tval.nsec > (NS_PER_SECONDS - 1)) {
            time_val_sum.tval.nsec -= NS_PER_SECONDS;
            time_val_sum.tval.sec += 1;
        }
    }

    return time_val_sum.tval64;
}

static int64_t timer_value_sub(const timeval_t *time_val_1, const timeval_t *time_val_2)
{
    timeval_t time_val_sub;

    if ((time_val_1 == NULL) || (time_val_2 == NULL))
        return TIMER_INV_VALUE;

    if ((time_val_1->tval64 > 0 && time_val_2->tval64 < 0 && INT64_MAX + time_val_2->tval64 < time_val_1->tval64) ||
        (time_val_1->tval64 < 0 && time_val_2->tval64 > 0 && INT64_MIN + time_val_2->tval64 > time_val_1->tval64)) {
        tloge("Time value sub result overflow\n");
        return TIMER_INV_VALUE;
    }

    if ((time_val_1->tval.nsec >= NS_PER_SECONDS) || (time_val_2->tval.nsec >= NS_PER_SECONDS)) {
        tlogw("timer value sub:invalid nsec value\n");
        time_val_sub.tval.sec = time_val_1->tval.sec - time_val_2->tval.sec;
        time_val_sub.tval.nsec = 0;
    } else {
        time_val_sub.tval64 = time_val_1->tval64 - time_val_2->tval64;
        if (time_val_sub.tval.nsec < 0)
            time_val_sub.tval.nsec += NS_PER_SECONDS;
    }

    return time_val_sub.tval64;
}

static int32_t get_timeout_value(int32_t status, timer_event *t_event)
{
    int32_t mills = OS_WAIT_FOREVER;
    timeval_t current_time;
    timeval_t expire_time;
    timeval_t diff_time;

    if (status == START_TIMER) {
        t_event->state = TIMER_STATE_ACTIVE;
        current_time.tval64 = tee_read_time_stamp();
        expire_time.tval64 = t_event->expires.tval64;
        diff_time.tval64 = timer_value_sub(&expire_time, &current_time);
        if (diff_time.tval.sec < 0) {
            mills = 1;
        } else {
            mills = diff_time.tval.sec * MS_PER_SECONDS + diff_time.tval.nsec / NS_PER_MSEC;
            mills = mills > 0 ? mills : OS_WAIT_FOREVER;
        }
    }
    return mills;
}

static void classic_thread_reply(int32_t status, const timer_event *t_event, cref_t msg_hdl)
{
    int32_t ret;
    struct timer_event_msg rsp_msg = {{{ 0 }}};

    rsp_msg.hdr.send.msg_id = TIMER_OPS_SUCCESS;
    if (status == STOP_TIMER && t_event->state == TIMER_STATE_EXECUTING)
        rsp_msg.hdr.send.msg_id = TIMER_OPS_FAIL;

    ret = ipc_msg_reply(msg_hdl, &rsp_msg, sizeof(rsp_msg));
    if (ret != TMR_OK)
        tloge("classic timer reply fail\n");
}

static int32_t get_time_event_status(uint32_t state)
{
    int32_t status;
    if (state == TIMER_STATE_ACTIVE)
        status = START_TIMER;
    else if (state == TIMER_STATE_INACTIVE)
        status = STOP_TIMER;
    else if (state == TIMER_STATE_DESTROY)
        status = DESTORY_TIMER;
    else
        status = CREATE_TIMER;
    return status;
}

static void *classic_thread(void *arg)
{
    int32_t ret;
    uint32_t mills = OS_WAIT_FOREVER;
    int32_t status = CREATE_TIMER;
    timer_event *t_event = (timer_event*)arg;
    struct timer_event_msg req_msg = {{{ 0 }}};

    if (t_event == NULL) {
        tloge("invalid timer event\n");
        return NULL;
    }

    cref_t msg_hdl = ipc_msg_create_hdl();
    if (!check_ref_valid(msg_hdl)) {
        tloge("create message failed\n");
        return NULL;
    }

    t_event->pid = (int32_t)get_self_taskid();
    while (status != DESTORY_TIMER) {
        ret = ipc_msg_receive(t_event->timer_channel, &req_msg, sizeof(req_msg), msg_hdl, NULL, mills);
        if (ret != TMR_OK && ret != E_EX_TIMER_TIMEOUT) {
            (void)ipc_msg_delete_hdl(msg_hdl);
            return NULL;
        }

        if (ret == E_EX_TIMER_TIMEOUT && t_event->state == TIMER_STATE_ACTIVE && t_event->handler != NULL) {
            t_event->state = TIMER_STATE_EXECUTING;
            t_event->handler(t_event->data);
            status = get_time_event_status(t_event->state);
        } else if (ret == TMR_OK) {
            status = req_msg.hdr.send.msg_id;
        }

        mills = get_timeout_value(status, t_event);
        if (status == START_TIMER)
            t_event->state = TIMER_STATE_ACTIVE;
        else if (status == STOP_TIMER && t_event->state != TIMER_STATE_EXECUTING)
            t_event->state = TIMER_STATE_INACTIVE;

        if (ret == TMR_OK)
            classic_thread_reply(status, t_event, msg_hdl);
    }

    ret = ipc_msg_delete_hdl(msg_hdl);
    if (ret != TMR_OK)
        tloge("delete obj failed!\n");
    return NULL;
}

static uint32_t classic_thread_create(timer_event *t_event)
{
    pthread_attr_t thread_attr;
    int32_t ret;
    pthread_t thread_id;

    ret = pthread_attr_init(&thread_attr);
    if (ret != TMR_OK) {
        tloge("init failed %d\n", ret);
        return ret;
    }

    ret = pthread_create(&thread_id, &thread_attr, classic_thread, t_event);
    if (ret != TMR_OK) {
        (void)pthread_attr_destroy(&thread_attr);
        tloge("create failed %d\n", ret);
        return ret;
    }

    ret = pthread_attr_destroy(&thread_attr);
    if (ret != TMR_OK) {
        tloge("destroy failed: err=%d\n", ret);
        return ret;
    }

    return TMR_OK;
}

static timer_event *tee_classic_timer_event_create(sw_timer_event_handler handler,
                                                   int32_t timer_class, void *priv_data)
{
    uint32_t ret;
    timer_event *t_event = NULL;
    cref_t timer_channel;

    if (handler == NULL) {
        tloge("bad parameters\n");
        return NULL;
    }

    t_event = TEE_Malloc(sizeof(*t_event), 0);
    if (t_event == NULL) {
        tloge("no enough memory\n");
        return NULL;
    }

    timer_channel = hm_msg_channel_create();
    if (!check_ref_valid(timer_channel)) {
        TEE_Free(t_event);
        return NULL;
    }

    t_event->timer_class = timer_class;
    t_event->state = TIMER_STATE_INACTIVE;
    t_event->timer_channel = timer_channel;
    t_event->expires.tval64 = 0;
    t_event->handler = handler;
    t_event->data = priv_data;

    ret = classic_thread_create(t_event);
    if (ret != TMR_OK) {
        (void)hm_msg_channel_remove(t_event->timer_channel);
        TEE_Free(t_event);
        tloge("create classic thread fail\n");
        return NULL;
    }

    return t_event;
}

static timer_event *tee_time_event_create(sw_timer_event_handler handler, int32_t timer_class, void *priv_data)
{
    if (handler == NULL || timer_class != TIMER_CLASSIC) {
        tloge("bad param\n");
        return NULL;
    }

    return tee_classic_timer_event_create(handler, TIMER_CLASSIC, priv_data);
}

static uint32_t tee_classic_timer_event_start(timer_event *t_event, timeval_t *time)
{
    uint32_t ret;
    timeval_t current_time;
    timeval_t expire_time;
    struct timer_event_msg req_msg = {{{ 0 }}};
    struct timer_event_msg rsp_msg = {{{ 0 }}};
    req_msg.hdr.send.msg_id = START_TIMER;

    if ((time->tval.nsec > (NS_PER_SECONDS - 1)) || (time->tval.nsec < 0) ||
        (time->tval.sec < 0) ||
        (time->tval.sec == 0 && time->tval.nsec == 0))
        return TMR_ERR;

    if (t_event->state == TIMER_STATE_ACTIVE)
        return TMR_ERR;

    current_time.tval64 = tee_read_time_stamp();
    expire_time.tval64 = timer_value_add(&current_time, time);
    t_event->state = TIMER_STATE_ACTIVE;
    t_event->expires.tval64 = expire_time.tval64;

    if (t_event->pid == (int32_t)get_self_taskid())
        return TMR_OK;

    ret = ipc_msg_call(t_event->timer_channel, &req_msg, sizeof(req_msg), &rsp_msg, sizeof(rsp_msg), OS_WAIT_FOREVER);
    if (ret != TMR_OK || rsp_msg.hdr.send.msg_id != TIMER_OPS_SUCCESS) {
        ret = TMR_ERR;
        tloge("start timer event fail\n");
    }

    return ret;
}

static uint32_t tee_time_event_start(timer_event *t_event, timeval_t *time)
{
    if (t_event == NULL || time == NULL) {
        tloge("bad parameters\n");
        return TMR_ERR;
    }

    return tee_classic_timer_event_start(t_event, time);
}

static uint32_t tee_classic_timer_event_stop(timer_event *t_event)
{
    uint32_t ret;
    struct timer_event_msg req_msg = {{{ 0 }}};
    struct timer_event_msg rsp_msg = {{{ 0 }}};
    req_msg.hdr.send.msg_id = STOP_TIMER;

    if (t_event->state != TIMER_STATE_ACTIVE)
        return TMR_ERR;

    t_event->state = TIMER_STATE_INACTIVE;
    if (t_event->pid == (int32_t)get_self_taskid())
        return TMR_OK;

    ret = ipc_msg_call(t_event->timer_channel, &req_msg, sizeof(req_msg), &rsp_msg, sizeof(rsp_msg), OS_WAIT_FOREVER);
    if (ret != TMR_OK || rsp_msg.hdr.send.msg_id != TIMER_OPS_SUCCESS) {
        ret = TMR_ERR;
        tloge("stop timer event fail\n");
    }

    return ret;
}

static uint32_t tee_time_event_stop(timer_event *t_event)
{
    if (t_event == NULL) {
        tloge("bad parameters\n");
        return TMR_ERR;
    }

    return tee_classic_timer_event_stop(t_event);
}

static uint32_t tee_classic_timer_event_destroy(timer_event *t_event)
{
    int32_t ret;
    struct timer_event_msg req_msg = {{{ 0 }}};
    struct timer_event_msg rsp_msg = {{{ 0 }}};
    req_msg.hdr.send.msg_id = DESTORY_TIMER;

    if (t_event->state != TIMER_STATE_INACTIVE && t_event->state != TIMER_STATE_EXECUTING) {
        tloge("invalid timer event state %d\n", t_event->state);
        return TMR_ERR;
    }

    if (t_event->pid == (int32_t)get_self_taskid()) {
        ret = TMR_OK;
    } else {
        ret = ipc_msg_call(t_event->timer_channel, &req_msg, sizeof(req_msg),
                          &rsp_msg, sizeof(rsp_msg), OS_WAIT_FOREVER);
        if (ret != TMR_OK || rsp_msg.hdr.send.msg_id != TIMER_OPS_SUCCESS)
            tloge("stop timer event fail\n");
    }

    if (hm_msg_channel_remove(t_event->timer_channel))
        tloge("channel remove failed\n");

    (void)memset_s(t_event, sizeof(*t_event), 0, sizeof(*t_event));
    TEE_Free(t_event);
    return ret;
}

static uint32_t tee_time_event_destroy(timer_event *t_event)
{
    if (t_event == NULL) {
        tloge("bad parameters\n");
        return TMR_ERR;
    }

    return tee_classic_timer_event_destroy(t_event);
}

static uint64_t tee_time_event_get_expire(timer_event *t_event)
{
    if (t_event == NULL) {
        tloge("bad parameters\n");
        return TIMER_INV_VALUE;
    }

    return t_event->expires.tval64;
}

static uint32_t tee_time_event_check(timer_notify_data_kernel *timer_data)
{
    if (timer_data == NULL) {
        tloge("bad parameters\n");
        return TMR_ERR;
    }

    return TMR_OK;
}

static uint32_t tee_get_secure_rtc_time(void)
{
    timeval_t cur_time;
    cur_time.tval64 = tee_read_time_stamp();
    return cur_time.tval.sec;
}

static void tee_release_timer_event(const TEE_UUID *uuid)
{
    (void)uuid;
    return;
}

static int32_t tee_set_ta_timer_permission(const TEE_UUID *uuid, uint64_t permission)
{
    (void)uuid;
    (void)permission;
    return TMR_OK;
}

static uint32_t tee_adjust_sys_time(const struct tee_time_t *time)
{
    if (time == NULL) {
        tloge("time is NULL\n");
        return TMR_ERR;
    }

    return TMR_OK;
}

static void tee_get_system_time(TEE_Time *time)
{
    uint64_t time_value;

    if (time == NULL) {
        tloge("invalid param\n");
        return;
    }

    time_value = tee_read_time_stamp();
    if (time_value == 0) {
        tloge("time value is zero\n");
        return;
    }

    time->seconds = UPPER_32_BITS(time_value);
    time->millis  = LOWER_32_BITS(time_value) / NS_PER_MSEC;
}

static void tee_get_sys_rtc_time(TEE_Time *time)
{
    TEE_Time cur_time;
    if (time == NULL) {
        tloge("invalid param\n");
        return;
    }

    timer_get_offset(&g_rtc_offset.seconds, &g_rtc_offset.millis);
    tee_get_system_time(&cur_time);

    if (cur_time.millis + (uint32_t)g_rtc_offset.millis > MS_PER_SECONDS) {
        cur_time.seconds += (uint32_t)(g_rtc_offset.seconds + 1);
        cur_time.millis += (uint32_t)(g_rtc_offset.millis - MS_PER_SECONDS);
    } else {
        cur_time.seconds += (uint32_t)g_rtc_offset.seconds;
        cur_time.millis += (uint32_t)g_rtc_offset.millis;
    }

    time->seconds = (uint32_t)cur_time.seconds;
    time->millis  = (uint32_t)cur_time.millis;
}

struct timer_ops_t g_timer_ops = {
    tee_read_time_stamp,
    tee_get_sys_rtc_time,
    tee_get_secure_rtc_time,
    tee_sleep,
    tee_time_event_create,
    tee_time_event_destroy,
    tee_time_event_start,
    tee_time_event_stop,
    tee_time_event_get_expire,
    tee_time_event_check,
    tee_release_timer_event,
    tee_set_ta_timer_permission,
    tee_adjust_sys_time,
    NULL,
    NULL,
};

struct timer_ops_t *get_time_ops(void)
{
    return &g_timer_ops;
}
