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
#include <unistd.h>

#include "test_libc_func.h"

#define KEY_VALUE_1 100
#define KEY_VALUE_2 200

static pthread_key_t key;
void *rc1;
void *rc2;

static void *a_thread_func(void *args)
{
    /* Bind a value to key for this thread (this will be different from the value
     * that we bind for the main thread) */
    if (pthread_setspecific(key, (void *)(KEY_VALUE_2)) != 0) {
        printf("Test FAILED: Could not set the value of the key to %d\n",
               (KEY_VALUE_2));
        pthread_exit((void *)PTS_FAIL);
        return NULL;
    }

    /* Get the bound value of the key that we just set. */
    rc2 = pthread_getspecific(key);

    pthread_exit(0);
    return NULL;

}

int pthread_setspecific_1_2(void)
{
    pthread_t new_th;

    /* Create the key */
    if (pthread_key_create(&key, NULL) != 0) {
        printf("Error: pthread_key_create() failed\n");
        return PTS_UNRESOLVED;
    }

    /* Bind a value for this main thread */
    if (pthread_setspecific(key, (void *)(KEY_VALUE_1)) != 0) {
        printf("Test FAILED: Could not set the value of the key to %d\n",
               (KEY_VALUE_1));
        return PTS_FAIL;
    }

    /* Create another thread.  This thread will also bind a value to the key */
    if (pthread_create(&new_th, NULL, a_thread_func, NULL) != 0) {
        printf("Error: in pthread_create()\n");
        return PTS_UNRESOLVED;
    }

    /* Wait for thread to end execution */
    pthread_join(new_th, NULL);

    /* Get the value associated for the key in this main thread */
    rc1 = pthread_getspecific(key);

    /* Compare this value with the value associated for the key in the newly created
     * thread, they should be different. */
    if (rc1 != (void *)(KEY_VALUE_1)) {
        printf("Test FAILED: Incorrect value bound to key, expected %d, got %ld\n",
               KEY_VALUE_1, (long)rc1);
        return PTS_FAIL;
    }

    if (rc2 != (void *)(KEY_VALUE_2)) {
        printf("Test FAILED: Incorrect value bound to key, expected %d, got %ld\n",
               KEY_VALUE_2, (long)rc2);
        return PTS_FAIL;
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}
