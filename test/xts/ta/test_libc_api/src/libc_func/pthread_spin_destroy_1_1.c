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
#include "test_libc_func.h"

static pthread_spinlock_t spinlock;

int pthread_spin_destroy_1_1(void)
{
    int rc = 0;

    printf("main: initialize spin lock\n");
    if (pthread_spin_init(&spinlock, PTHREAD_PROCESS_PRIVATE) != 0) {
        printf("main: Error at pthread_spin_init()\n");
        return PTS_UNRESOLVED;
    }

    printf("main: attempt spin lock\n");

    /* We should get the lock */
    if (pthread_spin_lock(&spinlock) != 0) {
        printf("Unresolved: main cannot get spin lock when no one owns the lock\n");
        return PTS_UNRESOLVED;
    }

    printf("main: acquired spin lock\n");

    printf("main: unlock spin lock\n");
    if (pthread_spin_unlock(&spinlock) != 0) {
        printf("main: Error at pthread_spin_unlock()\n");
        return PTS_UNRESOLVED;
    }

    printf("main: destroy spin lock\n");
    rc = pthread_spin_destroy(&spinlock);
    if (rc != 0) {
        printf("Test FAILED: Error at pthread_spin_destroy()"
               "Return code : %d\n", rc);
        return PTS_FAIL;
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}
