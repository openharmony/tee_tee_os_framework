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

static pthread_mutex_t    mutex = PTHREAD_MUTEX_INITIALIZER;

int pthread_mutex_unlock_1_1(void)
{
    int  rc;

    /* Get the mutex using pthread_mutex_lock() */
    if ((rc = pthread_mutex_lock(&mutex)) != 0) {
        fprintf(stderr, "Error at pthread_mutex_lock(), rc=%d\n", rc);
        return PTS_UNRESOLVED;
    }

    /* Release the mutex using pthread_mutex_unlock() */
    if ((rc = pthread_mutex_unlock(&mutex)) != 0) {
        printf("Test FAILED\n");
        return PTS_FAIL;
    }

    /* Get the mutex using pthread_mutex_trylock() */
    if ((rc = pthread_mutex_trylock(&mutex)) != 0) {
        printf("Test FAILED\n");
        return PTS_FAIL;
    }

    /* Release the mutex using pthread_mutex_unlock() */
    if ((rc = pthread_mutex_unlock(&mutex)) != 0) {
        printf("Test FAILED\n");
        return PTS_FAIL;
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}
