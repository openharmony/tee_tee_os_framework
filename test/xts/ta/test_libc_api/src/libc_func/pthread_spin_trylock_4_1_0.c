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


int pthread_spin_trylock_4_1_0(void)
{

    pthread_spinlock_t spinlock;
    int rc;

    /* attemp to lock an uninitalized spin lock */

    rc = pthread_spin_trylock(&spinlock);
    if (rc == EINVAL) {
        printf("Correctly got EINVAL at pthread_spin_trylock()\n");
        printf("Test PASSED\n");
    } else {
        printf("Expected EINVAL, but get return code: %d,%s\n", rc, strerror(rc));
        printf("Test PASSED: *Note: Returned incorrect value, but standard says 'may' fail\n");
        return PTS_FAIL;
    }
    return PTS_PASS;
}
