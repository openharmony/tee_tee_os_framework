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

#include <stdio.h>
#include <pthread.h>
#include <semaphore.h>
#include <fcntl.h>
#include "test_libc_func.h"

static sem_t sem;
static volatile int step = 0;

static void *thread_run(void *arg)
{
    printf("child thread begin run...\n");
    step = 1;
    printf("child thread wait on semaphore...\n");
    sem_wait(&sem);
    printf("child thread wake from semaphore...\n");
    step = 2;
    printf("child thread done.\n");
    return NULL;
}

int test_sem(void)
{
    int value;
    pthread_t thread;
    int ret, i;
    printf("main thread init unamed sem...\n");
    ret = sem_init(&sem, 0, 1);
    if (ret != 0) {
        printf("init sem failed.\n");
        return -1;
    }
    /* test sem_wait and sem_getvalue */
    sem_wait(&sem);
    sem_getvalue(&sem, &value);
    if (value != 0) {
        printf("sem_wait/sem_getvalue failed.\n");
        return -1;
    }
    /* test sem_wait and sem_post in threads */
    step = 0;
    printf("main thread create child thread...\n");
    ret = pthread_create(&thread, NULL, thread_run, NULL);
    if (ret != 0) {
        printf("create thread failed.\n");
        return -1;
    }
    printf("main thread yield...\n");
    for (i = 0; i < 100; i++)
        (void)sched_yield();
    if (step != 1) {
        printf("child thread should wait on sem, but not.\n");
        return -1;
    }
    printf("main thread post sem...\n");
    ret = sem_post(&sem);
    if (ret != 0) {
        printf("post sem failed.\n");
        return -1;
    }
    printf("main thread join child thread...\n");
    pthread_join(thread, NULL);
    printf("main thread done.\n");
    return 0;
}
