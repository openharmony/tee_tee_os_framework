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
#include <sys/types.h>
#include <semaphore.h>
#include <stdbool.h>
#include <unistd.h> 

#define N_THREAD 5
#define N_MUTEX 5

static pthread_spinlock_t sync_spinlock;
static pthread_t tmp_thread;
static char stack_pages[4096 * 4];

static void *func_one(void *arg)
{
    tmp_thread = pthread_self();
    // sync_spinlock is locked before creating this thread. so thread will wait here.
    // parent will set priority for this thread, (to make sure this thread do not exit).
    // then parent will unlock sync_spinlock.
    for (;;) {
        // try to lock the spin lock, if locked, break.
        // else hm_yield(), (here to test pthread_spin_trylock)
        if (pthread_spin_trylock(&sync_spinlock) == 0) {
            break;
        }
        (void)sched_yield();
    }

    printf("func_one thread print\n");
    // after we got the lock, just unlock it.
    pthread_spin_unlock(&sync_spinlock);
    pthread_exit(NULL);
}

int test_pthread_equal(void)
{
    int ret;
    pthread_t thread_one;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_spin_init(&sync_spinlock, false);
    pthread_spin_lock(&sync_spinlock);
    // using given thread stack which larger than 3KB(our stack 4KB)
    // pthread will use the stack which application provided.
    pthread_attr_setstack(&attr, stack_pages, sizeof(stack_pages));
    ret = pthread_create(&thread_one, &attr, func_one, NULL);
    if (ret != 0) {
        printf("pthread create failed: return %d\n", ret);
        return -1;
    }

    // let other thread to run.
    (void)sched_yield();
    // this print must output before thread print.
    printf("main thread print\n");
    pthread_setschedprio(thread_one, 200);
    pthread_spin_unlock(&sync_spinlock);

    pthread_join(thread_one, NULL);
    pthread_spin_destroy(&sync_spinlock);

    if (!pthread_equal(tmp_thread, thread_one)) {
        printf("test pthread_equal fail.\n");
        return -1;
    }
    return 0;
}


