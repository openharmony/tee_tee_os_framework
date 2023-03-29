/*
 * Copyright (C) 2023 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <pthread.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>
#include <errno.h>
#include <unistd.h>

#include "test_libc_func.h"

#define TEST "4-1"
#define FUNCTION "pthread_attr_setstacksize"
#define ERROR_PREFIX "unexpected error: " FUNCTION " " TEST ": "

int pthread_attr_setstacksize_4_1(void)
{
    pthread_attr_t attr;
    //    void *saddr;
    size_t stack_size;
    int rc;

    /* Initialize attr */
    rc = pthread_attr_init(&attr);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_attr_init");
        return PTS_UNRESOLVED;
    }

    stack_size = 1024;

    rc = pthread_attr_setstacksize(&attr, stack_size);
    if (rc != EINVAL) {
        printf(ERROR_PREFIX "Got the wrong return value");
        return PTS_FAIL;
    }

    rc = pthread_attr_destroy(&attr);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_attr_destroy");
        return PTS_UNRESOLVED;
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}

