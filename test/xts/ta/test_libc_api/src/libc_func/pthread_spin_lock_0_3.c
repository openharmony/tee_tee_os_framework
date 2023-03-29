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
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>

#include "test_libc_func.h"

#define    THREAD_NUM      16
#define    LOOPS         1000

static void *f1(void *parm);

static pthread_spinlock_t    spinlock1;//mutex1 = PTHREAD_MUTEX_INITIALIZER;
static pthread_spinlock_t    spinlock2;//mutex2 = PTHREAD_MUTEX_INITIALIZER;
static pthread_spinlock_t    spinlock3;//mutex3 = PTHREAD_MUTEX_INITIALIZER;
static int                value;    /* value protected by mutex */

int pthread_spin_lock_0_3(void)
{
    int                   i, rc;
    pthread_attr_t        pta;
    pthread_t             threads[THREAD_NUM];

    pthread_attr_init(&pta);
    pthread_attr_setdetachstate(&pta, PTHREAD_CREATE_JOINABLE);

    pthread_spin_init(&spinlock1, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_init(&spinlock2, PTHREAD_PROCESS_PRIVATE);
    pthread_spin_init(&spinlock3, PTHREAD_PROCESS_PRIVATE);
    /* Create threads */
    fprintf(stderr, "Creating %d threads\n", THREAD_NUM);
    for (i = 0; i < THREAD_NUM; ++i)
        rc = pthread_create(&threads[i], &pta, f1, (void *)(i + 1));

    /* Wait to join all threads */
    for (i = 0; i < THREAD_NUM; ++i)
        pthread_join(threads[i], NULL);
    pthread_attr_destroy(&pta);
    pthread_spin_destroy(&spinlock1);
    pthread_spin_destroy(&spinlock2);
    pthread_spin_destroy(&spinlock3);

    /* Check if the final value is as expected */
    if (value != (1 + THREAD_NUM) * THREAD_NUM / 2 * LOOPS) {
        fprintf(stderr, "Using %d threads and each loops %d times\n", THREAD_NUM,
            LOOPS);
        fprintf(stderr, "Final value must be %d instead of %d\n",
            (1 + THREAD_NUM) * THREAD_NUM / 2 * LOOPS, value);
        printf("Test FAILED\n");
        return PTS_FAIL;
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}

void *f1(void *parm)
{
    int   i, tmp;
    int   rc = 0;
    int  step = (int)parm;

    /* Loopd M times to acquire the mutex, increase the value,
       and then release the mutex. */

    for (i = 0; i < LOOPS; ++i) {
        rc = pthread_spin_lock(&spinlock1);
        if (rc != 0) {
            fprintf(stderr, "Error on pthread_mutex_lock(), rc=%d\n", rc);
            return (void *)(PTS_FAIL);
        }
        rc = pthread_spin_lock(&spinlock2);
        if (rc != 0) {
            fprintf(stderr, "Error on pthread_mutex_lock(), rc=%d\n", rc);
            return (void *)(PTS_FAIL);
        }
        rc = pthread_spin_lock(&spinlock3);
        if (rc != 0) {
            fprintf(stderr, "Error on pthread_mutex_lock(), rc=%d\n", rc);
            return (void *)(PTS_FAIL);
        }

        tmp = value;
        tmp = tmp + step;
        //fprintf(stderr,"Thread(0x%p) holds the mutex\n",(void*)self);
        //msleep(1);      /* delay the increasement operation */
        value = tmp;

        rc = pthread_spin_unlock(&spinlock1);
        if (rc != 0) {
            fprintf(stderr, "Error on pthread_mutex_unlock(), rc=%d\n", rc);
            return (void *)(PTS_UNRESOLVED);
        }
        rc = pthread_spin_unlock(&spinlock2);
        if (rc != 0) {
            fprintf(stderr, "Error on pthread_mutex_unlock(), rc=%d\n", rc);
            return (void *)(PTS_UNRESOLVED);
        }
        rc = pthread_spin_unlock(&spinlock3);
        if (rc != 0) {
            fprintf(stderr, "Error on pthread_mutex_unlock(), rc=%d\n", rc);
            return (void *)(PTS_UNRESOLVED);
        }
        //sleep(1);
    }
    pthread_exit(0);
    return (void *)(0);
}
