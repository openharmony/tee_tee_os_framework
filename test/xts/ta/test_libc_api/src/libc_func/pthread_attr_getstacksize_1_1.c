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
#define FUNCTION "pthread_attr_getstacksize"
#define ERROR_PREFIX "unexpected error: " FUNCTION " " TEST ": "

int pthread_attr_getstacksize_1_1(void)
{
    pthread_attr_t attr;
    size_t stack_size;
    size_t ssize;
    //    void *saddr;
    int rc;

    /* Initialize attr */
    rc = pthread_attr_init(&attr);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_attr_init");
        return PTS_UNRESOLVED;
    }

    /* Get the default stack_addr and stack_size value */
    rc = pthread_attr_getstacksize(&attr, &stack_size);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_attr_getstacksize");
        return PTS_UNRESOLVED;
    }
    /* printf("stack_size = %lu\n", stack_size); */

    stack_size = PTHREAD_STACK_MIN;

    /*    if (posix_memalign (&saddr, sysconf(_SC_PAGE_SIZE),
                stack_size) != 0)
            {
                  printf (ERROR_PREFIX "out of memory while "
                            "allocating the stack memory");
                  return PTS_UNRESOLVED;
            }
    */
    /* printf("stack_size = %lu\n", stack_size); */

    rc = pthread_attr_setstacksize(&attr, stack_size);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_attr_setstacksize");
        return PTS_UNRESOLVED;
    }

    rc = pthread_attr_getstacksize(&attr, &ssize);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_attr_getstacksize");
        return PTS_UNRESOLVED;
    }
    /* printf("ssize = %lu\n", ssize); */

    rc = pthread_attr_destroy(&attr);
    if (rc != 0) {
        printf(ERROR_PREFIX "pthread_attr_destroy");
        return PTS_UNRESOLVED;
    }

    printf("Test PASSED\n");
    return PTS_PASS;
}


