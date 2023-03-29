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
#include "tee_tag.h"

#include <securec.h>
#include <pthread.h>
#include "tee_mem_mgmt_api.h"
#include "tee_init.h"
#include <ipclib.h>
#include <unistd.h>

#define DRIVER_TAG_MAX_LEN      25
#define DRIVER_TAGS_NUM         40

static pthread_mutex_t g_driver_tag_lock = PTHREAD_MUTEX_INITIALIZER;

static uint8_t g_source_num = 0;

struct driver_tag_info {
    uint8_t source_type;
    const char *tag_name;
};

static struct driver_tag_info g_driver_tags[DRIVER_TAGS_NUM];

static int32_t lock_tag_list(void)
{
    int32_t ret;

    ret = pthread_mutex_lock(&g_driver_tag_lock);
    if (ret == EOWNERDEAD) /* owner died, use consistent to recover and lock the mutex */
        ret = pthread_mutex_consistent(&g_driver_tag_lock);

    if (ret != 0)
        printf("lock driver tag ret 0x%x\n", ret);

    return ret;
}

static void unlock_tag_list(void)
{
    int32_t ret;

    ret = pthread_mutex_unlock(&g_driver_tag_lock);
    if (ret != 0)
        printf("mutex unlock ret 0x%x\n", ret);

    return;
}

static uint8_t insert_log_source(const char *driver_tag)
{
    uint8_t source;

    if (g_source_num == DRIVER_TAGS_NUM) {
        printf("source type is overflow, max source type is %u\n", g_source_num);
        return 0;
    }

    if (g_source_num == 0)
        (void)memset_s(g_driver_tags, sizeof(g_driver_tags), 0, sizeof(g_driver_tags));

    g_driver_tags[g_source_num].tag_name = driver_tag;
    /* For source type 0 is common teeos log, the driver source type number starts from 1 */
    g_driver_tags[g_source_num].source_type = g_source_num + 1;

    source = g_driver_tags[g_source_num].source_type;
    g_source_num++;
    return source;
}

uint8_t get_log_source(const char *driver_tag)
{
    int32_t ret;
    size_t len;
    uint8_t source;
    uint8_t i;

    if (driver_tag == NULL)
        return 0;

    len = strnlen(driver_tag, DRIVER_TAG_MAX_LEN + 1);
    if (len > DRIVER_TAG_MAX_LEN) {
        printf("invalid driver tag len:%zu\n", len);
        return 0;
    }

    ret = lock_tag_list();
    if (ret != 0) {
        source = 0;
        return source;
    }

    for (i = 0; i <= g_source_num; i++) {
        if (g_driver_tags[i].tag_name == NULL)
            continue;

        if (len != strnlen(g_driver_tags[i].tag_name, DRIVER_TAG_MAX_LEN + 1))
            continue;

        ret = TEE_MemCompare(driver_tag, g_driver_tags[i].tag_name, len);
        if (ret == 0) {
            unlock_tag_list();
            return g_driver_tags[i].source_type;
        }
    }

    source = insert_log_source(driver_tag);
    unlock_tag_list();
    return source;
}

#define SERVICE_NAME_MAX      100
#define OTHER_CHAR_LEN        2

char *get_log_tag(const char *driver_tag, const char *debug_prefix)
{
    int32_t ret;
    size_t len1;
    size_t len2;

    if (driver_tag == NULL || debug_prefix == NULL)
        return NULL;

    len1 = strnlen(driver_tag, DRIVER_TAG_MAX_LEN + 1);
    if (len1 > DRIVER_TAG_MAX_LEN) {
        printf("invalid driver tag len:%zu\n", len1);
        return NULL;
    }

    len2 = strnlen(debug_prefix, SERVICE_NAME_MAX + 1);
    if (len2 > SERVICE_NAME_MAX) {
        printf("invalid debug prefix len:%zu\n", len2);
        return NULL;
    }

    char *tag = TEE_Malloc(len1 + len2 + OTHER_CHAR_LEN, 0);
    if (tag == NULL) {
        printf("malloc tag buffer is null\n");
        return NULL;
    }

    ret = snprintf_s(tag, len1 + len2 + OTHER_CHAR_LEN, len1 + len2 + OTHER_CHAR_LEN - 1,
        "%s_%s", debug_prefix, driver_tag);
    if (ret < 0) {
        printf("snprintf_s for driver tag name is failed:0x%x\n", ret);
        TEE_Free(tag);
        return NULL;
    }

    return tag;
}

static bool g_use_tid_flag = false;

void set_log_use_tid_flag(void)
{
    g_use_tid_flag = true;
}

/*
 * this function is used to declare which thread print the log
 * default use is the session_id of TA
 * it can be changed when the user redefine this function
 */
uint32_t get_log_thread_tag(void)
{
    if (g_use_tid_flag) {
        tid_t tid;
        tid = gettid();
        if (tid < 0)
            return 0;
        return tid;
    } else {
        return get_current_session_id();
    }
}
