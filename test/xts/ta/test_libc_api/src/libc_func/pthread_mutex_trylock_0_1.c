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
#include <errno.h>
#include <unistd.h>

#include "test_libc_func.h"

static int flag = 0;
static pthread_mutex_t    mutex = PTHREAD_MUTEX_INITIALIZER;

static void *func(void *parm)
{

    if ((pthread_mutex_trylock(&mutex)) != EBUSY) {

        printf("child trylock not ebusy\n");
        pthread_exit((void *)PTS_UNRESOLVED);
    }
    flag = 1;

    pthread_exit(0);
}

int pthread_mutex_trylock_0_1(void)
{
    int               rc;
    pthread_t       t1;


    /* Trylock the mutex and expect it returns EBUSY */
    rc = pthread_mutex_trylock(&mutex);
    if (rc != 0) {
        printf("Test FAILED trylock failed\n");
        return PTS_FAIL;
    }

    rc = pthread_mutex_trylock(&mutex);
    if (rc != EBUSY) {
        printf("Test FAILED again trylock success\n");
        return PTS_FAIL;
    }

    /* Create a secondary thread and wait until it has locked the mutex */
    pthread_create(&t1, NULL, func, NULL);

    /* Clean up */
    pthread_join(t1, NULL);

    pthread_mutex_unlock(&mutex);

    pthread_mutex_destroy(&mutex);

    if (flag == 0)
        return PTS_FAIL;

    printf("Test PASSED\n");
    return PTS_PASS;
}

