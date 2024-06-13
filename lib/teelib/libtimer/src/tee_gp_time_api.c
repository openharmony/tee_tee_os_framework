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
#include <sys_timer.h>
#include <tee_log.h>
#include <tee_trusted_storage_api.h>
#include <tee_time_adapt.h>
#include <tee_misc.h>

#define PERSISTENT_TIME_BASE_FILE      "sec_storage/persistent_time"
#define POSITIVE_DIR                   1
#define NEGATIVE_DIR                   (-1)
struct time_offset {
    int16_t dir;
    uint32_t offset;
    uint32_t base_sys_time;
};

void TEE_GetSystemTime(TEE_Time *time)
{
#ifdef CONFIG_TEE_TIME_STUB
    (void)time;
#else
    struct timer_ops_t *time_ops = NULL;
    uint64_t time_stamp;

    if (time == NULL)
        return;

    time_ops = get_time_ops();
    if (time_ops == NULL)
        return;

    time_stamp = time_ops->read_time_stamp();
    time->seconds = UPPER_32_BITS(time_stamp);
    time->millis  = LOWER_32_BITS(time_stamp) / NS_PER_MSEC;
#endif
}

void TEE_GetREETime(TEE_Time *time)
{
#ifdef CONFIG_TEE_TIME_STUB
    (void)time;
#else
    int32_t ret;
    if (time == NULL) {
        tloge("invalid param\n");
        return;
    }

    ret = get_time_of_data(&time->seconds, &time->millis, NULL, 0);
    if (ret != TMR_OK) {
        tloge("get time of data failed\n");
        return;
    }
#endif
}

void TEE_GetREETimeStr(char *time_str, uint32_t time_str_len)
{
    (void)memset_s(time_str, time_str_len, '0', time_str_len);
}

TEE_Result TEE_Wait(uint32_t mill_second)
{
#ifdef CONFIG_TEE_TIME_STUB
    (void)mill_second;
    return TEE_ERROR_NOT_SUPPORTED;
#else
    struct timer_ops_t *time_ops = NULL;
    time_ops = get_time_ops();
    if (time_ops == NULL)
        return TMR_ERR;

    return time_ops->sleep(mill_second);
#endif
}

#ifndef CONFIG_TEE_TIME_STUB
static uint32_t get_rtc_time(void)
{
    struct timer_ops_t *time_ops = NULL;
    time_ops = get_time_ops();
    if (time_ops == NULL)
        return TIMER_INV_VALUE;

    return time_ops->get_rtc_seconds();
}
#endif

TEE_Result TEE_SetTAPersistentTime(TEE_Time *time)
{
#ifdef CONFIG_TEE_TIME_STUB
    (void)time;
    return TEE_ERROR_NOT_SUPPORTED;
#else
    struct time_offset offset_val = { 0 };
    uint32_t seconds;
    TEE_Result ret;
    TEE_ObjectHandle object = NULL;

    if (time == NULL) {
        tloge("invalid param\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /*
     * Get sys time from RTC:always increase even if power off.
     * Use TEE_SetTAPersistentTime and TEE_GetTAPersistentTime
     * to get the true time that has past. A typical usecase in DRM.
     */
    seconds = get_rtc_time();
    if (seconds == TIMER_INV_VALUE) {
        tloge("Failed to get rtc time\n");
        return TEE_ERROR_TIME_NEEDS_RESET;
    }

    offset_val.base_sys_time = seconds;
    if (time->seconds >= seconds) {
        offset_val.dir    = POSITIVE_DIR;
        offset_val.offset = time->seconds - seconds;
    } else {
        offset_val.dir    = NEGATIVE_DIR;
        offset_val.offset = seconds - time->seconds;
    }

    ret = TEE_CreatePersistentObject(TEE_OBJECT_STORAGE_PRIVATE, PERSISTENT_TIME_BASE_FILE,
                                     strlen(PERSISTENT_TIME_BASE_FILE), TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL,
                                     &offset_val, sizeof(offset_val), &object);
    if (ret != TEE_SUCCESS) {
        tloge("set TA persistent time error: ret is 0x%x\n", ret);
        return ret;
    }

    TEE_CloseObject(object);
    return ret;
#endif
}

#ifndef CONFIG_TEE_TIME_STUB
static TEE_Result persistent_time_check(TEE_Time *time, const struct time_offset *offset_val)
{
    uint32_t seconds;
    seconds = get_rtc_time();
    if (seconds == TIMER_INV_VALUE) {
        tloge("failed to get rtc time\n");
        return TEE_ERROR_TIME_NEEDS_RESET;
    }

    if (seconds < offset_val->base_sys_time) {
        tloge("time rollback\n");
        return TEE_ERROR_TIME_NEEDS_RESET;
    }

    /*
     * millis is always 0, because rtc accuracy is 1s.
     * Depends on GP spec, even if time overflow we should return the actually time.
     */
    time->millis = 0;
    if (offset_val->dir == NEGATIVE_DIR) {
        time->seconds = seconds - offset_val->offset;
        if (time->seconds > seconds) {
            tloge("persistent time overflow\n");
            return TEE_ERROR_OVERFLOW;
        }
    } else {
        time->seconds = seconds + offset_val->offset;
        if (time->seconds < seconds) {
            tloge("persistent time overflow\n");
            return TEE_ERROR_OVERFLOW;
        }
    }

    return TEE_SUCCESS;
}
#endif

TEE_Result TEE_GetTAPersistentTime(TEE_Time *time)
{
#ifdef CONFIG_TEE_TIME_STUB
    (void)time;
    return TEE_ERROR_NOT_SUPPORTED;
#else
    struct time_offset offset_val = { 0 };
    TEE_ObjectHandle object = NULL;
    uint32_t count = 0;
    TEE_Result ret;

    if (time == NULL) {
        tloge("invalid param\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /*
     *  For an error different
     *  from TEE_ERROR_OVERFLOW, this placeholder is filled with zeros.
     */
    time->seconds = 0;
    time->millis  = 0;
    ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, PERSISTENT_TIME_BASE_FILE,
                                   strlen(PERSISTENT_TIME_BASE_FILE), TEE_DATA_FLAG_ACCESS_READ, &object);
    if (ret != TEE_SUCCESS) {
        tloge("failed to open persistent object\n");
        return TEE_ERROR_TIME_NOT_SET;
    }

    ret = TEE_ReadObjectData(object, &offset_val, sizeof(offset_val), &count);
    TEE_CloseObject(object);
    if ((ret != TEE_SUCCESS) || (count != sizeof(offset_val))) {
        tloge("read failed\n");
        return TEE_ERROR_TIME_NOT_SET;
    }

    ret = persistent_time_check(time, &offset_val);
    if (ret != TEE_SUCCESS) {
        tloge("failed to check\n");
        return ret;
    }

    return TEE_SUCCESS;
#endif
}
