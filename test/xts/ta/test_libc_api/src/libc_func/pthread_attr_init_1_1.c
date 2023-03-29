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

int pthread_attr_init_1_1(void)
{
    pthread_attr_t new_attr;
    int detach_state;

    /* Initialize attribute */
    if (pthread_attr_init(&new_attr) != 0) {
        printf("Cannot initialize attribute object\n");
        return PTS_UNRESOLVED;
    }

    /* The test passes if the attribute object has a detachstate of
     * PTHREAD_CREATE_JOINABLE, which is the default value for this
     * attribute. */
    if (pthread_attr_getdetachstate(&new_attr, &detach_state) != 0) {
        printf("Error obtaining the detachstate of the attribute\n");
        return PTS_UNRESOLVED;
    }

    if (detach_state == PTHREAD_CREATE_JOINABLE) {
        printf("Test PASSED\n");
        return PTS_PASS;
    } else {
        printf("Test FAILED\n");
        return PTS_FAIL;
    }
}


