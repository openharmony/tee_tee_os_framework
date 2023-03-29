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
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/param.h>
#include <errno.h>
#include <unistd.h>

#include "test_libc_func.h"

#define TEST "1-1"
#define FUNCTION "pthread_attr_setstack"
#define ERROR_PREFIX "unexpected error: " FUNCTION " " TEST ": "

#define STACKADDROFFSET 0x8000000

static void *stack_addr;
static size_t stack_size;

static void *thread_func(void *args)
{
    pthread_exit(0);
    return NULL;
}
int pthread_attr_setstack_1_1(void)
{
    pthread_t new_th;
    pthread_attr_t attr;
    size_t ssize;
    void *saddr;
    int rc;

    /* Initialize attr */
    rc = pthread_attr_init(&attr);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_attr_init");
        return PTS_UNRESOLVED;
    }

    /* Get the default stack_addr and stack_size value */
    rc = pthread_attr_getstack(&attr, &stack_addr, &stack_size);
    if (rc != EINVAL) {
        printf(ERROR_PREFIX "pthread_attr_getstack");
        return PTS_UNRESOLVED;
    }
    /* printf("stack_addr = %p, stack_size = %u\n", stack_addr, stack_size); */

    stack_size = PTHREAD_STACK_MIN;

    //    if (posix_memalign (&stack_addr, sysconf(_SC_PAGE_SIZE),
    //            stack_size) != 0)
    //        {
    //              printf (ERROR_PREFIX "out of memory while "
    //                        "allocating the stack memory");
    //              return PTS_UNRESOLVED;
    //        }
    /* printf("stack_addr = %p, stack_size = %u\n", stack_addr, stack_size);*/

    stack_addr = 0;
    rc = pthread_attr_setstack(&attr, stack_addr, stack_size);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_attr_setstack");
        return PTS_UNRESOLVED;
    }

    rc = pthread_attr_getstack(&attr, &saddr, &ssize);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_attr_getstack");
        return PTS_UNRESOLVED;
    }
    /* printf("saddr = %p, ssize = %u\n", saddr, ssize); */

    rc = pthread_create(&new_th, &attr, thread_func, NULL);
    if (rc != 0) {
        printf(ERROR_PREFIX "failed to create a thread");
        return PTS_FAIL;
    }

    rc = pthread_join(new_th, NULL);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_join");
        return PTS_UNRESOLVED;
    }

    rc = pthread_attr_destroy(&attr);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_attr_destroy");
        return PTS_UNRESOLVED;
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}


