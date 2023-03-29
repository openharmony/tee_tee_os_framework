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


#define THREAD_NUM 8
#define COND_NUM 2
#define LOOP 10

static pthread_mutex_t mutex[COND_NUM];
static pthread_cond_t  cond[COND_NUM];
static pthread_t  thread[THREAD_NUM][COND_NUM];

static int t1_start = 0;
static int cnt[THREAD_NUM];

static void *t1_func(void *arg)
{
    int rc;
    int i = (int)(intptr_t)arg;

    if (pthread_mutex_lock(&mutex[i]) != 0) {
        fprintf(stderr, "Thread1 failed to acquire mutex\n");
        pthread_exit((void *)PTS_UNRESOLVED);
    }
    //fprintf(stderr,"Thread1 started\n");
    t1_start ++;    /* let main thread continue */

    //fprintf(stderr,"Thread1 is waiting for the cond\n");
    rc = pthread_cond_wait(&cond[i], &mutex[i]);
    if (rc != 0) {
        fprintf(stderr, "pthread_cond_wait return %d\n", rc);
        pthread_exit((void *)PTS_UNRESOLVED);
    }
    cnt[i] ++;
    //fprintf(stderr,"Thread1 wakened\n");
    pthread_mutex_unlock(&mutex[i]);
    return NULL;
}


int pthread_cond_wait_0_3(void)
{
    int i, j, k;

    for (k = 0; k < COND_NUM; k++) {
        if (pthread_mutex_init(&mutex[k], NULL) != 0) {
            printf("Fail to initialize mutex\n");
            return PTS_UNRESOLVED;
        }
    }

    for (i = 0; i < LOOP; i++) {

        t1_start = 0;
        printf("loop:%d\n", i);

        for (k = 0; k < COND_NUM; k++) {
            cnt[k] = 0;
            if (pthread_cond_init(&cond[k], NULL) != 0) {
                printf("Fail to initialize cond\n");
                return PTS_UNRESOLVED;
            }
        }

        for (j = 0; j < THREAD_NUM; j++) {
            for (k = 0; k < COND_NUM; k++) {
                if (pthread_create(&thread[j][k], NULL, t1_func, (void *)(intptr_t)k) != 0) {
                    printf("Fail to create thread 1\n");
                    return PTS_UNRESOLVED;
                }
            }
        }
        while (t1_start < THREAD_NUM * COND_NUM) {    /* wait for thread1 started */
            tee_msleep(1);
            (void)sched_yield();
        }
        //printf("start to aquire lock\n");

        for (k = 0; k < COND_NUM; k++) {
            /* acquire the mutex released by pthread_cond_wait() within thread 1 */
            if (pthread_mutex_lock(&mutex[k]) != 0) {
                fprintf(stderr, "Main: Fail to acquire mutex\n");
                return PTS_UNRESOLVED;
            }
            if (pthread_mutex_unlock(&mutex[k]) != 0) {
                fprintf(stderr, "Main: Fail to release mutex\n");
                return PTS_UNRESOLVED;
            }
        }

        //fprintf(stderr,"Time to wake up thread1 by signaling a condition\n");
        for (k = 0; k < COND_NUM; k++) {
            if (pthread_cond_broadcast(&cond[k]) != 0) {
                fprintf(stderr, "Main: Fail to signal cond\n");
                return PTS_UNRESOLVED;
            }
            (void)sched_yield();
        }
        (void)sched_yield();
        for (j = 0; j < THREAD_NUM; j++) {
            for (k = 0; k < COND_NUM; k++) {
                pthread_join(thread[j][k], NULL);
            }
        }
        for (j = 0; j < COND_NUM; j++) {
            if (cnt[j] != THREAD_NUM) {
                printf("result wrong\n");
                return PTS_FAIL;
            }
        }
        for (k = 0; k < COND_NUM; k++) {
            if (pthread_cond_destroy(&cond[k]) != 0) {
                printf("Fail to destroy cond\n");
                return PTS_UNRESOLVED;
            }
        }
    }

    for (k = 0; k < COND_NUM; k++) {
        if (pthread_mutex_destroy(&mutex[k]) != 0) {
            printf("Fail to destroy mutex\n");
            return PTS_UNRESOLVED;
        }
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}
