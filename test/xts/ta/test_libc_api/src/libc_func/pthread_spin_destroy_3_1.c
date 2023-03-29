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
static int ret_value = 0;
static void *fn_chld(void *arg)
{
    int rc = 0;

    printf("child: destroy spin lock\n");
    rc = pthread_spin_destroy(&spinlock);
    if (rc == EBUSY) {
        printf("child: correctly got EBUSY\n");
        printf("Test PASSED\n");
    } else {
        printf("child: got return code %d, %s\n", rc, strerror(rc));
        printf("Test PASSED: *Note: Did not return EBUSY when destroying a spinlock already in use, but standard says 'may' fail\n");
        ret_value = 1;
    }
    pthread_exit(PTS_PASS);
}

int pthread_spin_destroy_3_1(void)
{
    pthread_t child_thread;

    if (pthread_spin_init(&spinlock, PTHREAD_PROCESS_PRIVATE) != 0) {
        printf("main: Error at pthread_spin_init()\n");
        return PTS_UNRESOLVED;
    }

    printf("main: attempt spin lock\n");

    /* We should get the lock */
    if (pthread_spin_lock(&spinlock) != 0) {
        printf("main cannot get spin lock when no one owns the lock\n");
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

    if (ret_value)
        return PTS_FAIL;

    return PTS_PASS;
}
