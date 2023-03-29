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
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "test_libc_func.h"

static pthread_spinlock_t spinlock;

#define NOT_CREATED_THREAD 1
#define ENTERED_THREAD 2
#define EXITING_THREAD 3

int pthread_spin_trylock_0_1(void)
{
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


    if (pthread_spin_trylock(&spinlock) != EBUSY) {
        printf("Test FAILED: main trylock again is not EBUSY\n");
        return PTS_FAIL;
    }

    printf("thread: correctly returned EBUSY on trylock\n");
    printf("Test PASSED\n");
    return PTS_PASS;
}
