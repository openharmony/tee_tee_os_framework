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


static void *a_thread_func(void *args)
{

    pthread_exit(0);
    return NULL;
}

int pthread_attr_destroy_1_1(void)
{
    pthread_t new_th;
    pthread_attr_t new_attr;
    int ret;

    /* Initialize attribute */
    if (pthread_attr_init(&new_attr) != 0) {
        printf("Cannot initialize attribute object\n");
        return PTS_UNRESOLVED;
    }

    /* Destroy attribute */
    if (pthread_attr_destroy(&new_attr) != 0) {
        printf("Cannot destroy the attribute object\n");
        return PTS_UNRESOLVED;
    }

    /* Creating a thread, passing to it the destroyed attribute, should
     * result in an error value of EINVAL (invalid 'attr' value). */
    ret = pthread_create(&new_th, &new_attr, a_thread_func, NULL);

    if (ret == EINVAL) {
        printf("Test PASSED\n");
        return PTS_PASS;
    } else if ((ret != 0) && ((ret == EPERM) || (ret == EAGAIN))) {
        printf("Error created a new thread\n");
        return PTS_UNRESOLVED;
    } else if (ret == 0) {
        printf("Test PASSED: NOTE*: Though returned 0 when creating a thread with a destroyed attribute, this behavior is compliant with garbage-in-garbage-out. \n");
        return PTS_PASS;
    } else {
        printf("Test FAILED: (1) Incorrect return code from pthread_create(); %d not EINVAL  or  (2) Error in pthread_create()'s behavior in returning error codes \n",
               ret);
        return PTS_FAIL;
    }

}