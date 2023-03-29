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

static pthread_mutex_t  mutex1, mutex2;
static pthread_mutex_t  mutex3 = PTHREAD_MUTEX_INITIALIZER;

int pthread_mutex_destroy_1_1_0(void)
{
    pthread_mutexattr_t mta;
    int rc;

    /* Initialize a mutex attributes object */
    if ((rc = pthread_mutexattr_init(&mta)) != 0) {
        fprintf(stderr, "Error at pthread_mutexattr_init(), rc=%d\n", rc);
        return PTS_UNRESOLVED;
    }

    /* Initialize mutex1 with the default mutex attributes */
    if ((rc = pthread_mutex_init(&mutex1, &mta)) != 0) {
        fprintf(stderr, "Fail to initialize mutex1, rc=%d\n", rc);
        return PTS_UNRESOLVED;
    }

    /* Initialize mutex2 with NULL attributes */
    if ((rc = pthread_mutex_init(&mutex2, NULL)) != 0) {
        fprintf(stderr, "Fail to initialize mutex2, rc=%d\n", rc);
        return PTS_UNRESOLVED;
    }

    /* Destroy the mutex attributes object */
    if ((rc = pthread_mutexattr_destroy(&mta)) != 0) {
        fprintf(stderr, "Error at pthread_mutexattr_destroy(), rc=%d\n", rc);
        return PTS_UNRESOLVED;
    }

    /* Destroy mutex1 */
    if ((rc = pthread_mutex_destroy(&mutex1)) != 0) {
        fprintf(stderr, "Fail to destroy mutex1, rc=%d\n", rc);
        printf("Test FAILED\n");
        return PTS_FAIL;
    }

    /* Destroy mutex2 */
    if ((rc = pthread_mutex_destroy(&mutex2)) != 0) {
        fprintf(stderr, "Fail to destroy mutex2, rc=%d\n", rc);
        printf("Test FAILED\n");
        return PTS_FAIL;
    }

    /* Destroy mutex3 */
    if ((rc = pthread_mutex_destroy(&mutex3)) != 0) {
        fprintf(stderr, "Fail to destroy mutex3, rc=%d\n", rc);
        printf("Test FAILED\n");
        return PTS_FAIL;
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}
