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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "test_libc_func.h"

#define TEST "3-1"
#define FUNCTION "pthread_exit"
#define ERROR_PREFIX "unexpected error: " FUNCTION " " TEST ": "

/* Flag to indicate that the destructor was called */
int cleanup_flag = 0;

static void destructor(void *tmp)
{
    cleanup_flag = 1;
}

/* Thread's function. */
static void *a_thread_func(void *tmp)
{
    pthread_key_t    key;
    int              value = 1;
    int              rc = 0;

    rc = pthread_key_create(&key, destructor);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_key_create\n");
        return (void *)PTS_UNRESOLVED;
    }

    rc = pthread_setspecific(key, &value);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_setspecific\n");
        return (void *)PTS_UNRESOLVED;
    }

    pthread_exit(0);
    return NULL;
}

int pthread_exit_3_1(void)
{
    pthread_t new_th;
    int       rc = 0;

    /* Create a new thread. */
    rc = pthread_create(&new_th, NULL, a_thread_func, NULL);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_create\n");
        return PTS_UNRESOLVED;
    }

    /* Wait for thread to return */
    rc = pthread_join(new_th, NULL);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_join\n");
        return PTS_UNRESOLVED;
    }

    if (cleanup_flag != 1) {
        printf("Test FAIL: Destructor was not called.\n");
        return PTS_FAIL;
    }

    printf("Test PASS\n");
    return PTS_PASS;

}
