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
#include <errno.h>

#include "test_libc_func.h"

#define NUM_THREADS    5

static void *a_thread_func(void *args)
{
    pthread_exit(NULL);
    return NULL;
}

int pthread_attr_init_3_1(void)
{
    pthread_t new_threads[NUM_THREADS];
    pthread_attr_t new_attr;
    int i, ret;

    /* Initialize attribute */
    if (pthread_attr_init(&new_attr) != 0) {
        printf("Cannot initialize attribute object\n");
        return PTS_UNRESOLVED;
    }

    /* Create [NUM_THREADS] number of threads with the same attribute
     * object. */
    for (i = 0; i < NUM_THREADS; i++) {
        ret = pthread_create(&new_threads[i], &new_attr, a_thread_func, NULL);
        if ((ret != 0) && (ret == EINVAL)) {
            printf("Test FAILED\n");
            return PTS_FAIL;
        } else if (ret != 0) {
            printf("Error creating thread\n");
            return PTS_UNRESOLVED;
        }
    }

    printf("Test PASSED\n");
    return PTS_PASS;

}


