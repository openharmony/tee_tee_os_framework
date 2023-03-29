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

int pthread_attr_init_4_1(void)
{
    pthread_attr_t new_attr;
    int ret;

    /* Initialize attribute */
    ret = pthread_attr_init(&new_attr);
    if (ret == 0) {
        printf("Test PASSED\n");
        return PTS_PASS;
    }
    /* There's insufficient memory, can't run test */
    else if (ret == ENOMEM) {
        printf("Error in pthread_attr_init()\n");
        return PTS_UNRESOLVED;
    }

    /* Any other return value other than 0 or ENOMEM, means the test
     * failed, because those are the only 2 return values for this
     * function. */
    else {
        printf("Test FAILED\n");
        return PTS_FAIL;
    }

}
