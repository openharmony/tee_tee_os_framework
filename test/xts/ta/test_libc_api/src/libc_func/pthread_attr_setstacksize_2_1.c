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

#define TEST "2-1"
#define FUNCTION "pthread_attr_setstacksize"
#define ERROR_PREFIX "unexpected error: " FUNCTION " " TEST ": "

static size_t stack_size;

static void *thread_func(void *args)
{
    pthread_attr_t attr;
    size_t ssize;

    pthread_attr_getstacksize(&attr, &ssize);
    if (ssize != stack_size) {
        printf(ERROR_PREFIX "got the wrong stacksize or stackaddr");
        return (void *)PTS_FAIL;
    }

    pthread_exit(0);
    return NULL;
}

int pthread_attr_setstacksize_2_1(void)
{
    pthread_t new_th;
    pthread_attr_t attr;
    size_t ssize;
    //    void *saddr;
    int rc;

    /* Initialize attr */
    rc = pthread_attr_init(&attr);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_attr_init");
        return PTS_UNRESOLVED;
    }

    stack_size = PTHREAD_STACK_MIN;
    
    rc = pthread_attr_setstacksize(&attr, stack_size);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_attr_setstacksize");
        return PTS_UNRESOLVED;
    }

    rc = pthread_attr_getstacksize(&attr, &ssize);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_attr_getstacksize");
        return PTS_UNRESOLVED;
    }

    rc = pthread_create(&new_th, &attr, thread_func, NULL);
    if (rc != 0) {
        printf(ERROR_PREFIX "failed to create a thread");
        return PTS_FAIL;
    }

    rc = pthread_join(new_th, NULL);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_join");
        return PTS_UNRESOLVED;
    }

    rc = pthread_attr_destroy(&attr);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_attr_destroy");
        return PTS_UNRESOLVED;
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}

