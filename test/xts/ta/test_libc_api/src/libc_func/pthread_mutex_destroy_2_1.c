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

int pthread_mutex_destroy_2_1(void)
{
    pthread_mutex_t mutex;

    /* Initialize a mutex attributes object */
    if (pthread_mutex_init(&mutex, NULL) != 0) {
        fprintf(stderr, "Cannot initialize mutex object\n");
        return PTS_UNRESOLVED;
    }

    /* Destroy the mutex attributes object */
    if (pthread_mutex_destroy(&mutex) != 0) {
        fprintf(stderr, "Cannot destroy the mutex object\n");
        return PTS_UNRESOLVED;
    }

    /* Initialize the mutex attributes object again.  This shouldn't result in an error. */
    if (pthread_mutex_init(&mutex, NULL) != 0) {
        printf("Test FAILED\n");
        return PTS_FAIL;
    } else {
        printf("Test PASSED\n");
        return PTS_PASS;
    }
}
