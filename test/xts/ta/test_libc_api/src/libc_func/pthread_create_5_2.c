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

#include "test_libc_func.h"

#define NUM_THREADS 5

/* The thread start routine. */
static void *a_thread_func(void *num)
{
    int *i, j;

    i = (int *)num;

    for (j = 0; j < NUM_THREADS; j++)
        printf("Passed argument %d for thread\n", i[j]);

    pthread_exit(0);
    return NULL;
}

int pthread_create_5_2(void)
{
    pthread_t new_th;
    int i[NUM_THREADS], j;

    for (j = 0; j < NUM_THREADS; j++)
        i[j] = j + 1;

    if (pthread_create(&new_th, NULL, a_thread_func, (void *)&i) != 0) {
        printf("Error creating thread\n");
        return PTS_FAIL;
    }

    /* Wait for thread to end execution */
    pthread_join(new_th, NULL);

    printf("Test PASSED\n");
    return PTS_PASS;
}


