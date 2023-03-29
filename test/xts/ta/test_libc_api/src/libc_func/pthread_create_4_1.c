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

#include "test_libc_func.h"

static void *a_thread_func(void *args);

pthread_t self_th;     /* Save the value of the function call pthread_self()
               within the thread.  Keeping it global so 'main' can
               see it too. */

int pthread_create_4_1(void)
{
    pthread_t new_th;

    /* Create a new thread */
    if (pthread_create(&new_th, NULL, a_thread_func, NULL) != 0) {
        printf("Error creating thread\n");
        return PTS_UNRESOLVED;
    }

    /* Wait for the thread function to return to make sure we got
     * the thread ID value from pthread_self(). */
    if (pthread_join(new_th, NULL) != 0) {
        printf("Error calling pthread_join()\n");
        return PTS_UNRESOLVED;
    }

    /* If the value of pthread_self() and the return value from
     * pthread_create() is equal, then the test passes. */
    if (pthread_equal(new_th, self_th) == 0) {
        printf("Test FAILED\n");
        return PTS_FAIL;
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}

/* The thread function that calls pthread_self() to obtain its thread ID */
static void *a_thread_func(void *args)
{
    self_th = pthread_self();
    pthread_exit(0);
    return NULL;
}
