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

#ifndef __TEE_LOG_H
#define __TEE_LOG_H

#include <stdio.h>
#include <stdlib.h>
#include "tee_defines.h"
#include "tee_log_legacy.h"

#define TA_LOG_LEVEL_ERROR   0
#define TA_LOG_LEVEL_WARNING 1
#define TA_LOG_LEVEL_INFO    2
#define TA_LOG_LEVEL_DEBUG   3
#define TA_LOG_LEVEL_VERBO   4

#define TA_LOG_LEVEL_DEFAULT  TA_LOG_LEVEL_INFO
// TA_LOG_LEVEL can be redefined by TA developers
#ifndef TA_LOG_LEVEL
#define TA_LOG_LEVEL TA_LOG_LEVEL_DEFAULT
#endif

#define TAG_VERB  "[verb]"
#define TAG_DEBUG "[debug]"
#define TAG_INFO  "[info]"
#define TAG_WARN  "[warn]"
#define TAG_ERROR "[error]"
#define TAG_PANIC "[panic]"

typedef enum {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_WARN  = 1,
    LOG_LEVEL_INFO  = 2,
    LOG_LEVEL_DEBUG = 3,
    LOG_LEVEL_VERBO = 4,
    LOG_LEVEL_ON    = 5,
} LOG_LEVEL;

void tee_print(LOG_LEVEL log_level, const char *fmt, ...);
extern const char *g_debug_prefix;

/* tlogv */
#if (TA_LOG_LEVEL >= TA_LOG_LEVEL_VERBO)
#ifdef TLOG_USE_TEE_PRINT
#define tlogv(fmt, args...) tee_print(LOG_LEVEL_VERBO, "%s %d:" fmt "", TAG_VERB, __LINE__, ##args)
#else
#define tlogv(fmt, args...) printf("[%s] %s %d:" fmt " ", g_debug_prefix, TAG_VERB, __LINE__, ##args)
#endif /* TLOG_USE_TEE_PRINT */
#else
#define tlogv(fmt, args...) \
    do {                    \
    } while (0)
#endif /* TA_LOG_LEVEL >= TA_LOG_LEVEL_VERBO */

/* tlogd */
#if (TA_LOG_LEVEL >= TA_LOG_LEVEL_DEBUG)
#ifdef TLOG_USE_TEE_PRINT
#define tlogd(fmt, args...) tee_print(LOG_LEVEL_DEBUG, "%s %d:" fmt "", TAG_DEBUG, __LINE__, ##args)
#else
#define tlogd(fmt, args...) printf("[%s] %s %d:" fmt " ", g_debug_prefix, TAG_DEBUG, __LINE__, ##args)
#endif /* TLOG_USE_TEE_PRINT */
#else
#define tlogd(fmt, args...) \
    do {                    \
    } while (0)
#endif /* TA_LOG_LEVEL >= TA_LOG_LEVEL_DEBUG */

/* tlogi */
#if (TA_LOG_LEVEL >= TA_LOG_LEVEL_INFO)
#ifdef TLOG_USE_TEE_PRINT
#define tlogi(fmt, args...) tee_print(LOG_LEVEL_INFO, "%s %d:" fmt "", TAG_INFO, __LINE__, ##args)
#else
#define tlogi(fmt, args...) printf("[%s] %s %d:" fmt " ", g_debug_prefix, TAG_INFO, __LINE__, ##args)
#endif /* TLOG_USE_TEE_PRINT */
#else
#define tlogi(fmt, args...) \
    do {                    \
    } while (0)
#endif /* TA_LOG_LEVEL >= TA_LOG_LEVEL_INFO */

/* tlogw */
#if (TA_LOG_LEVEL >= TA_LOG_LEVEL_WARNING)
#ifdef TLOG_USE_TEE_PRINT
#define tlogw(fmt, args...) tee_print(LOG_LEVEL_WARN, "%s %d:" fmt "", TAG_WARN, __LINE__, ##args)
#else
#define tlogw(fmt, args...) printf("[%s] %s %d:" fmt " ", g_debug_prefix, TAG_WARN, __LINE__, ##args)
#endif /* TLOG_USE_TEE_PRINT */
#else
#define tlogw(fmt, args...) \
    do {                    \
    } while (0)
#endif /* TA_LOG_LEVEL >= TA_LOG_LEVEL_WARNING */

/* tloge */
#if (TA_LOG_LEVEL >= TA_LOG_LEVEL_ERROR) // Always meet this condition
#ifdef TLOG_USE_TEE_PRINT
#define tloge(fmt, args...) tee_print(LOG_LEVEL_ERROR, "%s %d:" fmt " ", TAG_ERROR, __LINE__, ##args)
#else
#define tloge(fmt, args...) printf("[%s] %s %d:" fmt " ", g_debug_prefix, TAG_ERROR, __LINE__, ##args)
#endif /* TLOG_USE_TEE_PRINT */
#else
#define tloge(fmt, args...) \
    do {                    \
    } while (0)
#endif /* TA_LOG_LEVEL >= TA_LOG_LEVEL_ERROR */

#define tee_abort(fmt, args...) \
    do {                        \
        printf("[%s] %s %d:" fmt " ", g_debug_prefix, TAG_PANIC, __LINE__, ##args); \
        abort(); \
    }while (0)

#endif /* __TEE_LOG_H */
