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
#include <string.h>

#include "test_libc_func.h"

static pthread_spinlock_t spinlock;
static int pshared;
static int ret_value = 0;
static void *fn_chld(void *arg)
{
    int rc;
    /* child: initialize a spin lock being locked by main thread */
    printf("child: attempt initialize spin lock\n");
    rc = pthread_spin_init(&spinlock, pshared);
    if (rc == EBUSY)
        printf("child: correctly got EBUSY\n");
    else {
        ret_value = 1;
        printf("child: got return code %d, %s\n", rc, strerror(rc));
        printf("Test PASSED: *Note: Did not return EBUSY when initializing a spinlock already in use, but standard says 'may' fail\n");
    }
    pthread_exit(PTS_PASS);
}

int pthread_spin_init_4_1(void)
{
    int rc = 0;
    pthread_t child_thread;

#ifdef PTHREAD_PROCESS_PRIVATE
    pshared = PTHREAD_PROCESS_PRIVATE;
#else
    pshared = -1;
#endif

    printf("main: initialize spin lock\n");

    rc = pthread_spin_init(&spinlock, pshared);
    if (rc != 0) {
        printf("Test FAILED:  Error at pthread_spin_init()\n");
        return PTS_FAIL;
    }

    printf("main: attempt spin lock\n");

    /* We should get the lock */
    if (pthread_spin_lock(&spinlock) != 0) {
        printf("Error: main cannot get spin lock when no one owns the lock\n");
        return PTS_UNRESOLVED;
    }

    printf("main: acquired spin lock\n");

    printf("main: create thread\n");
    if (pthread_create(&child_thread, NULL, fn_chld, NULL) != 0) {
        printf("main: Error creating child thread\n");
        return PTS_UNRESOLVED;
    }

    /* Wait for thread to end execution */
    pthread_join(child_thread, NULL);

    if (ret_value == 1)
        return PTS_FAIL;

    return PTS_PASS;
}
