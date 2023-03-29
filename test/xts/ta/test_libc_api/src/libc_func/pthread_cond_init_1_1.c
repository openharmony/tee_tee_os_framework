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

int pthread_cond_init_1_1(void)
{
    /*pthread_condattr_t condattr;*/
    pthread_cond_t cond;
    /*pthread_cond_t  cond1;*/
    int rc;

    /* Initialize cond with NULL attributes */
    if ((rc = pthread_cond_init(&cond, NULL)) != 0) {
        fprintf(stderr, "Fail to initialize cond, rc=%d\n", rc);
        printf("Test FAILED\n");
        return PTS_FAIL;
    }
    if ((rc = pthread_cond_destroy(&cond)) != 0) {
        fprintf(stderr, "Fail to destroy cond, rc=%d\n", rc);
        printf("Test FAILED\n");
        return PTS_FAIL;
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}
