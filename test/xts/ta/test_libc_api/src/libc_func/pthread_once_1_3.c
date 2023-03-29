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

#define _POSIX_C_SOURCE 200112L

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_libc_func.h"

#ifndef VERBOSE
#define VERBOSE 1
#endif

#define NTHREADS 3

static int control;
static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

static void my_init(void)
{
    int ret = 0;
    ret = pthread_mutex_lock(&mtx);

    if (ret != 0) {
        printf("Failed to lock mutex in initializer\n");
        return;
    }

    control++;

    ret = pthread_mutex_unlock(&mtx);

    if (ret != 0) {
        printf("Failed to unlock mutex in initializer\n");
        return;
    }

    return ;
}

/* Thread function */
static void *threaded(void *arg)
{
    int ret;

    ret = pthread_once(arg, my_init);

    if (ret != 0) {
        printf("pthread_once failed\n");
        return PTS_FAIL;
    }

    return NULL;
}

/* The main test function. */
int pthread_once_1_3(void)
{
    int ret, i;

    pthread_once_t myctl = PTHREAD_ONCE_INIT;

    pthread_t th[ NTHREADS ];

    control = 0;

    /* Create the children */

    for (i = 0; i < NTHREADS; i++) {
        ret = pthread_create(&th[ i ], NULL, threaded, &myctl);

        if (ret != 0) {
            printf("Failed to create a thread\n");
            return PTS_FAIL;
        }
    }

    /* Then join */
    for (i = 0; i < NTHREADS; i++) {
        ret = pthread_join(th[ i ], NULL);

        if (ret != 0) {
            printf("Failed to join a thread\n");
            return PTS_FAIL;
        }
    }

    /* Fetch the memory */
    ret = pthread_mutex_lock(&mtx);

    if (ret != 0) {
        printf("Failed to lock mutex in initializer\n");
        return PTS_FAIL;
    }

    if (control != 1) {
        printf("Control: %d\n", control);
        printf("The initializer function did not execute once\n");
        return PTS_FAIL;
    }

    ret = pthread_mutex_unlock(&mtx);

    if (ret != 0) {
        printf("Failed to unlock mutex in initializer\n");
        return PTS_FAIL;
    }

    return PTS_PASS;
}
