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

#define NUM_OF_KEYS 100
#define KEY_VALUE 0

static pthread_key_t keys[NUM_OF_KEYS];

int test_pthread_key_create(void)
{
    int i;
    void *rc;

    for (i = 0; i < NUM_OF_KEYS; i++) {
        if (pthread_key_create(&keys[i], NULL) != 0) {
            printf("Error: pthread_key_create() failed\n");
            return PTS_UNRESOLVED;
        } else {
            if (pthread_setspecific(keys[i], (void *)(long)(i + KEY_VALUE)) != 0) {
                printf("Error: pthread_setspecific() failed\n");
                return PTS_UNRESOLVED;
            }

        }
    }

    for (i = 0; i < NUM_OF_KEYS; ++i) {
        rc = pthread_getspecific(keys[i]);
        if (rc != (void *)(long)(i + KEY_VALUE)) {
            printf("Test FAILED: Did not return correct value of thread-specific key, expected %ld, but got %ld\n",
                   (long)(i + KEY_VALUE), (long)rc);
            return PTS_FAIL;
        } else {
            if (pthread_key_delete(keys[i]) != 0) {
                printf("Error: pthread_key_delete() failed\n");
                return PTS_UNRESOLVED;
            }
        }
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}
