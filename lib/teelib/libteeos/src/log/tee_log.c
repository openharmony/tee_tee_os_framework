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
#include "tee_log.h"
#include <stdio.h>
#include <stdarg.h>
#include <securec.h>
#include "tee_mem_mgmt_api.h"
#include "tee_init.h"
#include "timer_export.h"
#include "tee_tag.h"
#include "teecall.h"

enum log_source_type {
    COMMON_SOURCE = 0,
    DRIVER_SOURCE = 1,
    MAX_SOURCE = 2,
};

/*
 * HEAD
 * 32 Bytes New head of record 4 Bytes 0x5A5AA5A5
 *     UUID 		                  16 Bytes        TEE_UUID
 *     effect length of data         2 Bytes    real length of characters
 *     total length of data          2 Bytes    total length, multiple of 16 Bytes
 *     operation mark of log file    1 Byte    0x00000001 means have written to log file
 *     reserve segment               7 Bytes   default is 0
 *     data segment                  description of log terminated with \0, total length is multiple of 16
 *     using 0 to pad the data length
 */
#define LOG_ITEM_MAGIC     0x5A5A
#define LOG_ITEM_LEN_ALIGN 64
#define LOG_ITEM_MAX_LEN   384

enum {
    LOG_OPER_NEW,
    LOG_OPER_READ,
};
#define LOG_ITEM_NEVER_USED_SIZE 32
#define LOG_ITEM_UUID_SIZE       16
#define LOG_ITEM_RESERVED_SIZE   1
/* 64 Bytes of head + logs of user */
typedef struct {
    uint8_t never_used[LOG_ITEM_NEVER_USED_SIZE];

    uint16_t magic;
    uint16_t reserved0;

    uint32_t serial_no;

    uint16_t log_real_len;    /* real length of log */
    uint16_t log_buffer_len; /* length of log buffer multiple of 32 bytes */

    uint8_t uuid[LOG_ITEM_UUID_SIZE];
    uint8_t log_source_type;
    uint8_t reserved[LOG_ITEM_RESERVED_SIZE];
    uint8_t log_level;
    uint8_t new_line; /* it is \n,which makes it easier to read log from bbox.bin */

    uint8_t log_buffer[0];
} log_item_t;

void tee_log_init(const TEE_UUID *uuid)
{
    (void)uuid;
}

void tee_log_exit(void)
{
}

static bool is_ta_uuid(const uint8_t *uuid, size_t len)
{
    uint32_t i;
    const uint8_t *p = uuid;

    for (i = 0; i < len; i++) {
        if (p[i] != 0)
            return true;
    }

    return false;
}

static void fill_uuid(log_item_t *m_logitem, bool *is_ta)
{
    TEE_UUID uuid = { 0 };

    *is_ta = false;

    void *current_uuid = get_current_uuid();
    if (current_uuid == NULL) {
        printf("current uuid is NULL\n");
        current_uuid = &uuid;
    }

    if (memmove_s((void *)m_logitem->uuid, sizeof(m_logitem->uuid), current_uuid, sizeof(TEE_UUID)) != EOK) {
        printf("memmove_s uuid ret is not EOK\n");
        current_uuid = &uuid;
        return;
    }
    *is_ta = is_ta_uuid(m_logitem->uuid, sizeof(m_logitem->uuid));
}

#ifdef CONFIG_KLOG_TIMESTAMP
static int32_t fill_tee_log_buffer(char *log_buffer, size_t log_max_len, const char *log_tag)
{
    int32_t count;
    uint16_t thread_tag = get_log_thread_tag() & 0xffff;
    if (thread_tag != 0)
        count = snprintf_s(log_buffer, log_max_len, log_max_len - 1,
                           "                                 [%s-%u] ", log_tag, thread_tag);
    else
        count = snprintf_s(log_buffer, log_max_len, log_max_len - 1,
                           "                                 [%s] ", log_tag);

    return count;
}
#else
static int32_t fill_tee_log_buffer(char *log_buffer, size_t log_max_len, const char *log_tag)
{
    int32_t count;
    tee_date_time_kernel time  = { 0 };
    uint16_t thread_tag = get_log_thread_tag() & 0xffff;

    get_sys_date_time(&time);

    if (thread_tag != 0)
        count = snprintf_s(log_buffer, log_max_len, log_max_len - 1,
                           "            %02d/%02d %02d:%02d:%02d.%03d [%s-%u] ", time.month, time.day, time.hour,
                           time.min, time.seconds, time.millis, log_tag, thread_tag);
    else
        count = snprintf_s(log_buffer, log_max_len, log_max_len - 1,
                           "            %02d/%02d %02d:%02d:%02d.%03d [%s] ", time.month, time.day, time.hour, time.min,
                           time.seconds, time.millis, log_tag);

    return count;
}
#endif

static void fill_logitem(log_item_t *m_logitem, size_t m_logmaxlen, int count, int real_len)
{
    m_logitem->log_real_len = (uint16_t)(real_len + count);

    if (m_logitem->log_real_len + 1 >= m_logmaxlen) {
        printf("print too long %d\n", (int)m_logitem->log_real_len);
        return;
    }

    while (m_logitem->log_real_len > 1 && m_logitem->log_buffer[m_logitem->log_real_len - 1] == (uint8_t)' ') {
        m_logitem->log_buffer[m_logitem->log_real_len - 1] = 0;
        m_logitem->log_real_len--;
    }

    if (m_logitem->log_buffer[m_logitem->log_real_len - 1] != (uint8_t)'\n')
        m_logitem->log_buffer[m_logitem->log_real_len++] = (uint8_t)'\n';

    m_logitem->log_buffer_len =
        (m_logitem->log_real_len + LOG_ITEM_LEN_ALIGN - 1) / LOG_ITEM_LEN_ALIGN * LOG_ITEM_LEN_ALIGN;

    m_logitem->magic = LOG_ITEM_MAGIC;

    /* append in the rdr memory */
    if (debug_rdr_logitem((char *)m_logitem, sizeof(log_item_t) + m_logitem->log_buffer_len) != 0)
        printf("append rdr logitem debug_rdr_logitem ret is not successful\n");
}
#define LOG_RESERVED_SIZE 1
static void tee_print_helper(const char *log_tag, enum log_source_type source_type, LOG_LEVEL log_level,
                             const char *fmt, va_list arglist)
{
    int32_t count;
    int32_t real_len;
    uint8_t log_buffer[LOG_ITEM_MAX_LEN] = { 0 };
    log_item_t *log_item = NULL;
    size_t log_max_len;
    bool is_ta = false;

    if (fmt == NULL)
        return;

    log_item   = (log_item_t *)log_buffer;
    log_max_len = LOG_ITEM_MAX_LEN - sizeof(log_item_t);

    log_item->log_level = log_level;
    fill_uuid(log_item, &is_ta);

    /* ta not support this source category */
    if (!is_ta && (source_type > COMMON_SOURCE && source_type < MAX_SOURCE)) {
        log_item->log_source_type = get_log_source(log_tag);

        char *final_tag = get_log_tag(log_tag, g_debug_prefix);
        final_tag = ((final_tag == NULL) ? ((char *)log_tag) : final_tag);
        count = fill_tee_log_buffer((char *)log_item->log_buffer, log_max_len, final_tag);

        if (final_tag != log_tag) {
            TEE_Free(final_tag);
            final_tag = NULL;
        }
    } else {
        count = fill_tee_log_buffer((char *)log_item->log_buffer, log_max_len, log_tag);
    }
    if (count < 0)
        return;

    real_len = vsnprintf_s((char *)log_item->log_buffer + count, (size_t)(log_max_len - count - LOG_RESERVED_SIZE),
                           (size_t)(log_max_len - count - LOG_RESERVED_SIZE - 1), fmt, arglist);
    /* vsnprintf_s returns -1 directly when it fails */
    if (real_len == -1) {
        printf("vsnprintf_s failed: format string is \"%s\"\n", fmt);
        return;
    }

    fill_logitem(log_item, log_max_len, count, real_len);
}

void __attribute__((weak)) tee_print(LOG_LEVEL log_level, const char *fmt, ...)
{
    va_list ap;

    if (fmt == NULL)
        return;
    va_start(ap, fmt);

    tee_print_helper(g_debug_prefix, COMMON_SOURCE, log_level, fmt, ap);

    va_end(ap);
}

void __attribute__((weak)) tee_print_driver(LOG_LEVEL log_level, const char *log_tag, const char *fmt, ...)
{
    va_list ap;

    if (log_tag == NULL || fmt == NULL)
        return;
    va_start(ap, fmt);

    tee_print_helper(log_tag, DRIVER_SOURCE, log_level, fmt, ap);

    va_end(ap);
}

void uart_cprintf(const char *fmt, ...)
{
    va_list ap;
    if (fmt == NULL)
        return;
    va_start(ap, fmt);

    tee_print_helper(g_debug_prefix, COMMON_SOURCE, LOG_LEVEL_INFO, fmt, ap);

    va_end(ap);
}
void uart_printf_func(const char *fmt, ...)
{
    va_list ap;
    if (fmt == NULL)
        return;
    va_start(ap, fmt);

    tee_print_helper(g_debug_prefix, COMMON_SOURCE, LOG_LEVEL_INFO, fmt, ap);

    va_end(ap);
}