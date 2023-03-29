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

static void *a_thread_func(void *args)
{
    pthread_exit(0);
    return NULL;
}

int pthread_create_1_1(void)
{
    pthread_t main_th, new_th;

    if (pthread_create(&new_th, NULL, a_thread_func, NULL) != 0) {
        printf("Error creating thread\n");
        return PTS_UNRESOLVED;
    }

    /* Obtain the thread ID of this main function */
    main_th = pthread_self();

    /* Compare the thread ID of the new thread to the main thread.
     * They should be different.  If not, the test fails. */
    if (pthread_equal(new_th, main_th) != 0) {
        printf("Test FAILED: A new thread wasn't created\n");
        return PTS_FAIL;
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}


