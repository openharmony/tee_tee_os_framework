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
#define FUNCTION "pthread_mutexattr_getprotocol"
#define ERROR_PREFIX "unexpected error: " FUNCTION " " TEST ": "

static int verify_protocol(pthread_mutexattr_t *attr, int protocoltype)
{
    int rc;
    int protocol;

    rc = pthread_mutexattr_getprotocol(attr, &protocol);

    if (0 != rc) {
        printf(ERROR_PREFIX "pthread_mutexattr_getprotocol");
        return PTS_UNRESOLVED;
    }
    if (protocol != protocoltype) {
        printf(ERROR_PREFIX "got wrong protocol param");
        return PTS_FAIL;
    }
    return 0;
}

int pthread_mutexattr_getprotocol_1_1(void)
{
    int rc = 0;
    pthread_mutexattr_t attr;

    rc = pthread_mutexattr_init(&attr);
    if (0 != rc) {
        printf(ERROR_PREFIX "pthread_mutexattr_init");
        return PTS_UNRESOLVED;
    }

    verify_protocol(&attr, PTHREAD_PRIO_NONE);

    rc = pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_NONE);
    if (0 != rc) {
        printf(ERROR_PREFIX "pthread_mutexattr_setprotocol");
        return PTS_UNRESOLVED;
    }
    verify_protocol(&attr, PTHREAD_PRIO_NONE);

    rc = pthread_mutexattr_setprotocol(&attr, !PTHREAD_PRIO_NONE);
    if (ENOTSUP != rc) {
        printf(ERROR_PREFIX "pthread_mutexattr_setprotocol wrong protocol");
        return PTS_UNRESOLVED;
    }

    rc = pthread_mutexattr_destroy(&attr);
    if (0 != rc) {
        printf(ERROR_PREFIX "pthread_mutexattr_destroy");
        return PTS_UNRESOLVED;
    }
    printf("Test PASS\n");
    return PTS_PASS;
}
