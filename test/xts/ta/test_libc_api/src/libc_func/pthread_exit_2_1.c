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
#include <unistd.h>

#include "test_libc_func.h"

static int i[3], j;

/* Cleanup function that the thread executes when it is canceled.  So if
 * cleanup_flag is 1, it means that the thread was canceled. */
static void a_cleanup_func1(void *args)
{
    i[j] = 1;
    j++;
    return;
}

/* Cleanup function that the thread executes when it is canceled.  So if
 * cleanup_flag is 1, it means that the thread was canceled. */
static void a_cleanup_func2(void *args)
{
    i[j] = 2;
    j++;
    return;
}

/* Cleanup function that the thread executes when it is canceled.  So if
 * cleanup_flag is 1, it means that the thread was canceled. */
static void a_cleanup_func3(void *args)
{
    i[j] = 3;
    j++;
    return;
}
/* Thread's function. */
static void *a_thread_func(void *args)
{
    /* Set up 3 cleanup handlers */
    pthread_cleanup_push(a_cleanup_func1, NULL);
    pthread_cleanup_push(a_cleanup_func2, NULL);
    pthread_cleanup_push(a_cleanup_func3, NULL);

    /* Terminate the thread here. */
    pthread_exit(0);

    /* Need these here for it to compile nicely.  We never reach here though. */
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    return NULL;
}

int pthread_exit_2_1(void)
{
    pthread_t new_th;

    /* Initialize integer array. */
    for (j = 0; j < 3; j++)
        i[j] = 0;

    /* Initialize counter. */
    j = 0;

    /* Create a new thread. */
    if (pthread_create(&new_th, NULL, a_thread_func, NULL) != 0) {
        printf("Error creating thread\n");
        return PTS_UNRESOLVED;
    }

    /* Wait for thread to return */
    if (pthread_join(new_th, NULL) != 0) {
        printf("Error in pthread_join()\n");
        return PTS_UNRESOLVED;
    }

    /* Check to make sure that the cleanup handlers were executed in order. */
    if (i[0] == 3) {
        if (i[1] == 2) {
            if (i[2] == 1) {
                printf("Test PASSED\n");
                return PTS_PASS;

            }
            printf("Test FAILED: Did not execute cleanup handlers in order.\n");
            return PTS_FAIL;
        }
        printf("Test FAILED: Did not execute cleanup handlers in order.\n");
        return PTS_FAIL;
    } else if (i[0] == 0) {
        printf("Test FAILED: Did not execute cleanup handlers.\n");
        return PTS_FAIL;
    }

    printf("Test FAILED: Did not execute cleanup handlers in order.\n");
    return PTS_FAIL;

}


