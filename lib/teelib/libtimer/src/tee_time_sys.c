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
#include <sys_timer.h>
#include <tee_log.h>
#include <tee_time_adapt.h>
#include <tee_misc.h>
#include <time.h>
#include <tee_time_sys.h>

#define is_leap_year(year)  ((((year) % 4 == 0) && ((year) % 100 != 0)) || ((year) % 400 == 0))
#define leap_days_get(year) (((year) / 4) - ((year) / 100) + ((year) / 400))

static const uint32_t g_mon_lengths[][MONSPERYEAR] = {
    { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
    { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};
static const uint32_t g_year_lengths[] = { DAYSPERNYEAR, DAYSPERLYEAR };

int tee_timer_init(void)
{
    struct timer_ops_t *time_ops = NULL;
    time_ops = get_time_ops();
    if (time_ops == NULL || time_ops->tee_timer_init == NULL)
        return TMR_OK;

    return time_ops->tee_timer_init();
}

static uint32_t increment_overflow(uint32_t *year, uint32_t carry)
{
    if (carry > (UINT_MAX - *year)) {
        tloge("overflow, year=%u, carry=%u\n", *year, carry);
        return TMR_ERR;
    }

    *year += carry;
    return TMR_OK;
}

static uint32_t get_days_and_year(uint32_t *days, uint32_t *year)
{
    uint32_t ret;
    uint32_t new_year;
    uint32_t leap_days;
    uint32_t carry_over;

    while (*days >= g_year_lengths[is_leap_year(*year)]) {
        carry_over = *days / DAYSPERLYEAR;
        if (carry_over == 0)
            carry_over = 1;

        new_year = *year;
        ret = increment_overflow(&new_year, carry_over);
        if (ret != TMR_OK)
            return TMR_ERR;

        leap_days = leap_days_get(new_year - 1) - leap_days_get(*year - 1);
        if (new_year < *year)
            return TMR_ERR;
        *days -= (new_year - *year) * DAYSPERNYEAR;
        *days -= leap_days;
        *year = new_year;
    }

    return TMR_OK;
}

void gen_sys_date_time(const uint32_t rtc_time, struct tee_date_t *time)
{
    uint32_t seconds;
    uint32_t tdays;
    uint32_t idays;
    uint32_t rem_secs;
    uint32_t year;
    const uint32_t *ip = NULL;
    uint32_t ret;

    if (time == NULL) {
        tloge("Error:time is null\n");
        return;
    }

    seconds = rtc_time;
    year = EPOCH_YEAR;
    tdays = seconds / SECSPERDAY;
    rem_secs = seconds - tdays * SECSPERDAY;

    ret = get_days_and_year(&tdays, &year);
    if (ret != TMR_OK) {
        tloge("failed to get the day and year\n");
        return;
    }

    time->month = 0;
    idays = tdays;
    time->year = (int32_t)year;
    time->hour = (int32_t)(rem_secs / SECSPERHOUR);
    rem_secs %= SECSPERHOUR;
    time->min = (int32_t)(rem_secs / SECSPERMIN);
    time->seconds = (int32_t)(rem_secs % SECSPERMIN);
    ip = g_mon_lengths[is_leap_year(year)];

    for (int i = 0; i < MONSPERYEAR; i++) {
        time->month++;
        if (idays < ip[i])
            break;
        idays -= ip[i];
    }

    time->day = (int32_t)(idays + 1);
}

struct tm *tee_localtime_r(const time_t *restrict t, struct tm *restrict value)
{
    tee_date_time_kernel date_time;

    if ((value == NULL) || (t == NULL))
        return NULL;

    gen_sys_date_time((uint32_t)*t, &date_time);

    /*
     * Shift tee_date_time_kernel to libc struct tm
     * tm_year: Year - 1900, that's why we minus 1900 here.
     * tm_mon: Month (0-11), that's why we minus 1 here.
     * tm_wday: Days of the week, has not implemented yet(could not get from date_time).
     * tm_yday: Days in the year, has not implemented yet(could not get from date_time).
     */
    if (date_time.year == 0 || date_time.month == 0) {
        tloge("invalid parameters, please check\n");
        return NULL;
    }

    value->tm_year     = date_time.year - 1900; /* start year 1900 */
    value->tm_mon      = date_time.month - 1;
    value->tm_mday     = date_time.day;
    value->tm_hour     = date_time.hour;
    value->tm_min      = date_time.min;
    value->tm_sec      = date_time.seconds;
    value->tm_wday     = 0;
    value->tm_yday     = 0;
    value->tm_isdst    = 0;
    value->__tm_gmtoff = 0;
    value->__tm_zone   = NULL;

    return value;
}

struct tm *__localtime_r(const time_t *restrict t, struct tm *restrict value)
{
    struct tm *tmp = NULL;
#ifdef __LP64__
    /*
     * Reject time_t values whose year would overflow int because
     * __secs_to_zone cannot safely handle them.
     */
    if ((t != NULL) && ((*t < INT_MIN * MAX_SECONDS_PER_YEAR) || (*t > INT_MAX * MAX_SECONDS_PER_YEAR)))
        return NULL;
#endif

    if (t == NULL || value == NULL)
        return NULL;

    tmp = tee_localtime_r(t, value);
    if (tmp == NULL) {
        tloge("localtime: get value is NULL\n");
        return NULL;
    }
    return value;
}

struct tm *localtime(const time_t *t)
{
    static struct tm value;
    return __localtime_r(t, &value);
}

void get_sys_rtc_time(TEE_Time *time)
{
    struct timer_ops_t *time_ops = NULL;
    if (time == NULL) {
        tloge("invalid param\n");
        return;
    }

    time_ops = get_time_ops();
    if (time_ops == NULL)
        return;

    time_ops->get_sys_rtc_time(time);
}

void get_sys_date_time(tee_date_time_kernel *time_date)
{
    TEE_Time time;
    get_sys_rtc_time(&time);
    time.seconds += TIME_ZONE_EIGHT * SECSPERHOUR; /* CST */
    if (time_date != NULL) {
        gen_sys_date_time(time.seconds, time_date);
        time_date->millis = time.millis;
    }
}

uint32_t adjust_sys_time(const struct tee_time_t *time)
{
    struct timer_ops_t *time_ops = NULL;
    if (time == NULL) {
        tloge("invalid param\n");
        return TMR_ERR;
    }

    time_ops = get_time_ops();
    if (time_ops == NULL)
        return TMR_OK;

    return time_ops->adjust_sys_time(time);
}

void release_timer_event(const TEE_UUID *uuid)
{
    struct timer_ops_t *time_ops = NULL;
    if (uuid == NULL) {
        tloge("invalid param\n");
        return;
    }

    time_ops = get_time_ops();
    if (time_ops == NULL)
        return;

    return time_ops->release_timer_event(uuid);
}

int32_t set_ta_timer_permission(const TEE_UUID *uuid, uint64_t permission)
{
    struct timer_ops_t *time_ops = NULL;
    if (uuid == NULL) {
        tloge("invalid param\n");
        return TMR_ERR;
    }

    time_ops = get_time_ops();
    if (time_ops == NULL)
        return TMR_ERR;

    return time_ops->set_ta_timer_permission(uuid, permission);
}

void get_ree_time_str(char *time_str, uint32_t time_str_len)
{
    int32_t ret;

    if ((time_str == NULL) || (time_str_len == 0)) {
        tloge("invalid param\n");
        return;
    }

    ret = get_time_of_data(NULL, NULL, time_str, time_str_len);
    if (ret != TMR_OK)
        tloge("get time of data failed\n");
}

uint64_t tee_read_time_stamp(void)
{
    struct timer_ops_t *time_ops = NULL;
    time_ops = get_time_ops();
    if (time_ops == NULL)
        return TMR_ERR;

    return time_ops->read_time_stamp();
}
