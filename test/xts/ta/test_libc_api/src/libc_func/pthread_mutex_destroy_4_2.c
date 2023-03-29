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
#include <errno.h>
#include <unistd.h>
#include "test_libc_func.h"

#define TEST "4-2"
#define FUNCTION "pthread_mutex_destroy"
#define ERROR_PREFIX "unexpected error: " FUNCTION " " TEST ": "

int pthread_mutex_destroy_4_2(void)
{
    pthread_mutex_t     mutex = PTHREAD_MUTEX_INITIALIZER;
    int                 rc = 0;

    /* Lock the mutex */
    rc = pthread_mutex_lock(&mutex);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_mutex_lock\n");
        return PTS_UNRESOLVED;
    }

    /* Try to destroy the locked mutex */
    rc = pthread_mutex_destroy(&mutex);
    if (rc != EBUSY) {
        printf(ERROR_PREFIX "Test PASS: Expected %d(EBUSY) got %d, "
               "though the standard states 'may' fail\n", EBUSY, rc);
        return PTS_PASS;
    }
    printf("Test PASS\n");

    return PTS_PASS;
}
