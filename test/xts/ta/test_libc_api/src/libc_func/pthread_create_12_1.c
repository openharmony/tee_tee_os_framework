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

#include "test_libc_func.h"

/* Thread starting routine that really does nothing. */
static void *a_thread_func(void *args)
{
    pthread_exit(0);
    return NULL;
}

int pthread_create_12_1(void)
{
    pthread_t new_th;
    int ret;

    /* Create new thread and check the return value. */
    ret = pthread_create(&new_th, NULL, a_thread_func, NULL);
    if (ret != 0) {
        if ((ret != EINVAL) && (ret != EAGAIN) && (ret != EPERM))

            printf("Test FAILED: Wrong return code: %d\n", ret);
        return PTS_FAIL;
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}


