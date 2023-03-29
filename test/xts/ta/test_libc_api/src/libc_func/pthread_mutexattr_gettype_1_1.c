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
#include <errno.h>

#include "test_libc_func.h"

#define TEST "1-1"
#define FUNCTION "pthread_mutexattr_gettype"
#define ERROR_PREFIX "unexpected error: " FUNCTION " " TEST ": "

#define CORRECT_NUM (2)
#define WRONG_NUM (3)
#define ZERO_NUM (0)

static int verify_type(pthread_mutexattr_t *attr, int typetype)
{
    int rc;
    int type;

    rc = pthread_mutexattr_gettype(attr, &type);
    if (0 != rc) {
        printf(ERROR_PREFIX "pthread_mutexattr_gettype");
        return PTS_UNRESOLVED;
    }
    if (type != typetype) {
        printf(ERROR_PREFIX "got wrong type param");
        return PTS_FAIL;
    }
    return 0;
}

int pthread_mutexattr_gettype_1_1(void)
{
    int rc = 0;
    pthread_mutexattr_t attr;

    rc = pthread_mutexattr_init(&attr);
    if (0 != rc) {
        printf(ERROR_PREFIX "pthread_mutexattr_init");
        return PTS_UNRESOLVED;
    }

    rc = pthread_mutexattr_settype(&attr, WRONG_NUM);
    if (EINVAL != rc) {
        printf(ERROR_PREFIX "pthread_mutexattr_settype");
        return PTS_UNRESOLVED;
    }

    rc = pthread_mutexattr_settype(&attr, CORRECT_NUM);
    if (0 != rc) {
        printf(ERROR_PREFIX "pthread_mutexattr_settype wrong type");
        return PTS_UNRESOLVED;
    }

    verify_type(&attr, CORRECT_NUM);


    rc = pthread_mutexattr_settype(&attr, ZERO_NUM);
    if (0 != rc) {
        printf(ERROR_PREFIX "pthread_mutexattr_settype wrong type");
        return PTS_UNRESOLVED;
    }

    verify_type(&attr, ZERO_NUM);

    rc = pthread_mutexattr_destroy(&attr);
    if (0 != rc) {
        printf(ERROR_PREFIX "pthread_mutexattr_destroy");
        return PTS_UNRESOLVED;
    }
    printf("Test PASS\n");
    return PTS_PASS;
}

