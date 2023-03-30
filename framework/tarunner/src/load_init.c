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

#include "load_init.h"
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>
#include <tee_log.h>
#include <priorities.h>
#include <tee_secfile_load_agent.h>

static void *g_libtee = NULL;

int32_t get_priority(void)
{
    char *prio_var = getenv("priority");
    int32_t priority;

    if (prio_var != NULL) {
        errno = 0;
        priority = strtol(prio_var, NULL, 10); /* Convert priority to decimal */
        if ((errno != 0) || (priority < PRIO_TEE_MIN) || (priority > PRIO_TEE_MAX)) {
            tlogw("bad priority set, use default PRIO_TEE_TA\n");
            priority = PRIO_TEE_TA;
        }
    } else {
        tlogw("no priority set, use default PRIO_TEE_TA\n");
        priority = PRIO_TEE_TA;
    }

    return priority;
}

int32_t extend_utables(void)
{
    return 0;
}

void clear_libtee(void)
{
    if (g_libtee == NULL) {
        tloge("libtee handle is NULL\n");
        return;
    }

    dlclose(g_libtee);
    g_libtee = NULL;
}

void *get_libtee_handle(void)
{
    if (g_libtee == NULL) {
        tloge("libtee handle is NULL\n");
        return NULL;
    }

    return g_libtee;
}

void *ta_mt_dlopen(const char *name, int32_t flag)
{
    if (name == NULL) {
        tloge("dlopen name is invalied\n");
        return NULL;
    }

    size_t length = strnlen(name, LIB_NAME_MAX);
    if (length == 0 || length >= LIB_NAME_MAX) {
        tloge("dlopen name length is invalied\n");
        return NULL;
    }

    g_libtee = dlopen(name, flag);
    if (g_libtee == NULL) {
        tloge("load library failed: %s\n", dlerror());
        return NULL;
    }

    return g_libtee;
}
