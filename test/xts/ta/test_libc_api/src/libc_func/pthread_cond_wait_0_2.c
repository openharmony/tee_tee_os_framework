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

static pthread_mutex_t mutex;
static pthread_cond_t  cond;

#define THREAD_NUM 8
#define LOOP 50

static pthread_t  thread[THREAD_NUM];

static int t1_start = 0;
static int cnt[THREAD_NUM];

static void *t1_func(void *arg)
{
    int rc;
    int i = (int)(intptr_t)arg;

    if (pthread_mutex_lock(&mutex) != 0) {
        fprintf(stderr, "Thread1 failed to acquire mutex\n");
        pthread_exit((void *)PTS_UNRESOLVED);
    }
    //fprintf(stderr,"Thread1 started\n");
    t1_start ++;    /* let main thread continue */

    //fprintf(stderr,"Thread1 is waiting for the cond\n");
    rc = pthread_cond_wait(&cond, &mutex);
    if (rc != 0) {
        fprintf(stderr, "pthread_cond_wait return %d\n", rc);
        pthread_exit((void *)PTS_UNRESOLVED);
    }
    cnt[i] ++;
    //fprintf(stderr,"Thread1 wakened\n");
    pthread_mutex_unlock(&mutex);
    return NULL;
}


int pthread_cond_wait_0_2(void)
{
    int i, j;

    if (pthread_mutex_init(&mutex, NULL) != 0) {
        fprintf(stderr, "Fail to initialize mutex\n");
        return PTS_UNRESOLVED;
    }

    for (i = 0; i < LOOP; i++) {
        printf("loop:%d\n", i);
        t1_start = 0;
        if (pthread_cond_init(&cond, NULL) != 0) {
            fprintf(stderr, "Fail to initialize cond\n");
            return PTS_UNRESOLVED;
        }
        printf("loop2:%d\n", i);

        for (j = 0; j < THREAD_NUM; j++) {
            if (pthread_create(&thread[j], NULL, t1_func, (void *)(intptr_t)j) != 0) {
                fprintf(stderr, "Fail to create thread 1\n");
                return PTS_UNRESOLVED;
            }
        }
        printf("loop3:%d\n", i);
        while (t1_start < THREAD_NUM) {    /* wait for thread1 started */
            tee_msleep(1);
            (void)sched_yield();
        }

        /* acquire the mutex released by pthread_cond_wait() within thread 1 */
        if (pthread_mutex_lock(&mutex) != 0) {
            fprintf(stderr, "Main: Fail to acquire mutex\n");
            return PTS_UNRESOLVED;
        }
        if (pthread_mutex_unlock(&mutex) != 0) {
            fprintf(stderr, "Main: Fail to release mutex\n");
            return PTS_UNRESOLVED;
        }


        fprintf(stderr, "Time to wake up thread1 by signaling a condition\n");
        if (pthread_cond_broadcast(&cond) != 0) {
            fprintf(stderr, "Main: Fail to signal cond\n");
            return PTS_UNRESOLVED;
        }
        (void)sched_yield();
        for (j = 0; j < THREAD_NUM; j++) {
            pthread_join(thread[j], NULL);
        }
        for (j = 0; j < THREAD_NUM; j++) {
            if (!cnt[j])
                return PTS_FAIL;
        }
        if (pthread_cond_destroy(&cond) != 0) {
            fprintf(stderr, "Fail to destroy cond\n");
            return PTS_UNRESOLVED;
        }
    }
    if (pthread_mutex_destroy(&mutex) != 0) {
        fprintf(stderr, "Fail to destroy mutex\n");
        return PTS_UNRESOLVED;
    }
    printf("Test PASSED\n");
    return PTS_PASS;
}
