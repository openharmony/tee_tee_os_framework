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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "test_libc_func.h"

static pthread_spinlock_t spinlock;
volatile static int thread_state;
static int rc;

#define NOT_CREATED_THREAD 1
#define ENTERED_THREAD 2
#define EXITING_THREAD 3


static void *fn_chld(void *arg)
{
    rc = 0;

    thread_state = ENTERED_THREAD;

    printf("thread: attempt trylock\n");
    rc = pthread_spin_trylock(&spinlock);

    pthread_exit(0);
    return NULL;
}

int pthread_spin_trylock_1_1(void)
{
    pthread_t child_thread;

    if (pthread_spin_init(&spinlock, PTHREAD_PROCESS_PRIVATE) != 0) {
        printf("main: Error at pthread_spin_init()\n");
        return PTS_UNRESOLVED;
    }

    printf("main: attempt to trylock\n");

    /* We should get the lock */
    if (pthread_spin_trylock(&spinlock) != 0) {
        printf("Test FAILED: main cannot get spin lock when no one owns the lock\n");
        return PTS_FAIL;
    }
    printf("main: acquired spin lock\n");

    thread_state = NOT_CREATED_THREAD;
    printf("main: create thread\n");
    if (pthread_create(&child_thread, NULL, fn_chld, NULL) != 0) {
        printf("main: Error creating child thread\n");
        return PTS_UNRESOLVED;
    }

    /* Wait for thread to end execution */
    pthread_join(child_thread, NULL);

    /* Check the return code of pthread_spin_trylock */
    if (rc != EBUSY) {
        printf("Test FAILED: pthread_spin_trylock should return EBUSY, instead got error code:%d\n"
               , rc);
        return PTS_FAIL;
    }

    printf("thread: correctly returned EBUSY on trylock\n");
    printf("Test PASSED\n");
    return PTS_PASS;

}
