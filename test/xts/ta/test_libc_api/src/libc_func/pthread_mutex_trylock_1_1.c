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
#include <unistd.h>
#include "test_libc_func.h"

static void *func(void *parm);

static pthread_mutex_t    mutex = PTHREAD_MUTEX_INITIALIZER;
static int     t1_start = 0;
static int    t1_pause = 1;

int pthread_mutex_trylock_1_1(void)
{
    int               i, rc;
    pthread_t       t1;

    /* Create a secondary thread and wait until it has locked the mutex */
    pthread_create(&t1, NULL, func, NULL);
    while (!t1_start) {
        printf("i2222Test PASSED\n");
        (void)sched_yield();
    }


    printf("333i2222Test PASSED\n");
    /* Trylock the mutex and expect it returns EBUSY */
    rc = pthread_mutex_trylock(&mutex);
    if (rc != EBUSY) {
        //if(rc!=0) {
        fprintf(stderr, "Expected %d(EBUSY), got %d\n", EBUSY, rc);
        printf("Test FAILED\n");
        return PTS_FAIL;
    }

    /* Allow the secondary thread to go ahead */
    t1_pause = 0;

    /* Trylock the mutex for N times */
    for (i = 0; i < 5; i++) {
        rc = pthread_mutex_trylock(&mutex);
        if (rc == 0) {
            pthread_mutex_unlock(&mutex);
            break;
        } else if (rc == EBUSY) {
            (void)sched_yield();
            continue;
        } else {
            fprintf(stderr, "Unexpected error code(%d) for pthread_mutex_lock()\n", rc);
            return PTS_UNRESOLVED;
        }
    }

    /* Clean up */
    pthread_join(t1, NULL);
    pthread_mutex_destroy(&mutex);

    if (i >= 5) {
        fprintf(stderr, "Have tried %d times but failed to get the mutex\n", i);
        return PTS_UNRESOLVED;
    }
    printf("Test PASSED\n");
    return PTS_PASS;
}

static void *func(void *parm)
{
    int rc;
    //    struct timespec time1;
    //    time1.tv_sec = 1;
    //    time1.tv_nsec = 0;

    if ((rc = pthread_mutex_lock(&mutex)) != 0) {
        fprintf(stderr, "Error at pthread_mutex_lock(), rc=%d\n", rc);
        pthread_exit((void *)PTS_UNRESOLVED);
    }
    t1_start = 1;

    while (t1_pause) {
        (void)(void)sched_yield();
#if 0
        if (nanosleep(&time1, NULL) == -1) {
            printf("Failed to nanosleep");
        }
#endif
    }
    printf("666666Test PASSED\n");

    if ((rc = pthread_mutex_unlock(&mutex)) != 0) {
        fprintf(stderr, "Error at pthread_mutex_unlock(), rc=%d\n", rc);
        pthread_exit((void *)PTS_UNRESOLVED);
    }

    printf("99666666Test PASSED\n");
    pthread_exit(0);
    return (void *)(0);
}
