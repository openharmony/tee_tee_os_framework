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


int pthread_attr_destroy_3_1(void)
{
    pthread_attr_t new_attr;

    /* Initialize attribute */
    if (pthread_attr_init(&new_attr) != 0) {
        printf("Cannot initialize attribute object\n");
        return PTS_UNRESOLVED;
    }

    /* Destroy attribute */
    if (pthread_attr_destroy(&new_attr) != 0) {
        printf("Test FAILED\n");
        return PTS_FAIL;
    } else {
        printf("Test PASSED\n");
        return PTS_PASS;
    }
}


