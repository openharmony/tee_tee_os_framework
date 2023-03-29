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

#define _XOPEN_SOURCE 600

#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>

#include "test_libc_func.h"

struct testdata {
    pthread_mutex_t mutex;
    pthread_mutex_t mutex2;
    pthread_cond_t  cond;
    pthread_cond_t cond2;
};

static struct testdata td;
static pthread_t thread1;
static pthread_t thread2;

static int t1_start = 0;
static int signaled = 0;
static int t1_start2 = 0;
static int signaled2 = 0;


static void *t1_func(void *arg)
{
    int rc;

    if (pthread_mutex_lock(&td.mutex) != 0) {
        fprintf(stderr, "Thread1 failed to acquire mutex\n");
        pthread_exit((void *)PTS_UNRESOLVED);
    }
    fprintf(stderr, "Thread1 started\n");
    t1_start = 1;    /* let main thread continue */

    fprintf(stderr, "Thread1 is waiting for the cond\n");
    rc = pthread_cond_wait(&td.cond, &td.mutex);
    if (rc != 0) {
        fprintf(stderr, "pthread_cond_wait return %d\n", rc);
        pthread_exit((void *)PTS_UNRESOLVED);
    }

    fprintf(stderr, "Thread1 wakened\n");
    if (signaled == 0) {
        fprintf(stderr, "Thread1 did not block on the cond at all\n");
        printf("Test FAILED\n");
        pthread_exit((void *)PTS_FAIL);
    }
    pthread_mutex_unlock(&td.mutex);
    return NULL;
}

static void *t2_func(void *arg)
{
    int rc;

    if (pthread_mutex_lock(&td.mutex2) != 0) {
        fprintf(stderr, "Thread1 failed to acquire mutex\n");
        pthread_exit((void *)PTS_UNRESOLVED);
    }
    fprintf(stderr, "Thread1 started\n");
    t1_start2 = 1;    /* let main thread continue */

    fprintf(stderr, "Thread1 is waiting for the cond\n");
    rc = pthread_cond_wait(&td.cond2, &td.mutex2);
    if (rc != 0) {
        fprintf(stderr, "pthread_cond_wait return %d\n", rc);
        pthread_exit((void *)PTS_UNRESOLVED);
    }

    fprintf(stderr, "Thread1 wakened\n");
    if (signaled2 == 0) {
        fprintf(stderr, "Thread1 did not block on the cond at all\n");
        printf("Test FAILED\n");
        pthread_exit((void *)PTS_FAIL);
    }
    pthread_mutex_unlock(&td.mutex2);
    return NULL;
}

int pthread_cond_wait_0_1(void)
{
    if (pthread_mutex_init(&td.mutex, NULL) != 0) {
        fprintf(stderr, "Fail to initialize mutex\n");
        return PTS_UNRESOLVED;
    }
    if (pthread_cond_init(&td.cond, NULL) != 0) {
        fprintf(stderr, "Fail to initialize cond\n");
        return PTS_UNRESOLVED;
    }
    if (pthread_mutex_init(&td.mutex2, NULL) != 0) {
        fprintf(stderr, "Fail to initialize mutex\n");
        return PTS_UNRESOLVED;
    }
    if (pthread_cond_init(&td.cond2, NULL) != 0) {
        fprintf(stderr, "Fail to initialize cond\n");
        return PTS_UNRESOLVED;
    }

    if (pthread_create(&thread1, NULL, t1_func, NULL) != 0) {
        fprintf(stderr, "Fail to create thread 1\n");
        return PTS_UNRESOLVED;
    }
    if (pthread_create(&thread2, NULL, t2_func, NULL) != 0) {
        fprintf(stderr, "Fail to create thread 1\n");
        return PTS_UNRESOLVED;
    }
    while (!t1_start) {    /* wait for thread1 started */
        tee_msleep(1);
        (void)sched_yield();
    }
    while (!t1_start2) {    /* wait for thread1 started */
        tee_msleep(1);
        (void)sched_yield();
    }

    /* acquire the mutex released by pthread_cond_wait() within thread 1 */
    if (pthread_mutex_lock(&td.mutex) != 0) {
        fprintf(stderr, "Main: Fail to acquire mutex\n");
        return PTS_UNRESOLVED;
    }
    if (pthread_mutex_unlock(&td.mutex) != 0) {
        fprintf(stderr, "Main: Fail to release mutex\n");
        return PTS_UNRESOLVED;
    }
    if (pthread_mutex_lock(&td.mutex2) != 0) {
        fprintf(stderr, "Main: Fail to acquire mutex\n");
        return PTS_UNRESOLVED;
    }
    if (pthread_mutex_unlock(&td.mutex2) != 0) {
        fprintf(stderr, "Main: Fail to release mutex\n");
        return PTS_UNRESOLVED;
    }
    (void)sched_yield();
    tee_msleep(1000);
    (void)sched_yield();
    tee_msleep(1000);
    (void)sched_yield();


    fprintf(stderr, "Time to wake up thread1 by signaling a condition\n");
    signaled = 1;
    signaled2 = 1;
    if (pthread_cond_signal(&td.cond) != 0) {
        fprintf(stderr, "Main: Fail to signal cond\n");
        return PTS_UNRESOLVED;
    }
    (void)sched_yield();
    if (pthread_cond_signal(&td.cond2) != 0) {
        fprintf(stderr, "Main: Fail to signal cond\n");
        return PTS_UNRESOLVED;
    }
    (void)sched_yield();

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    if (pthread_mutex_destroy(&td.mutex) != 0) {
        fprintf(stderr, "Fail to destroy mutex\n");
        return PTS_UNRESOLVED;
    }
    if (pthread_cond_destroy(&td.cond) != 0) {
        fprintf(stderr, "Fail to destroy cond\n");
        return PTS_UNRESOLVED;
    }
    if (pthread_mutex_destroy(&td.mutex2) != 0) {
        fprintf(stderr, "Fail to destroy mutex\n");
        return PTS_UNRESOLVED;
    }
    if (pthread_cond_destroy(&td.cond2) != 0) {
        fprintf(stderr, "Fail to destroy cond\n");
        return PTS_UNRESOLVED;
    }
    printf("Test PASSED\n");
    return PTS_PASS;
}
