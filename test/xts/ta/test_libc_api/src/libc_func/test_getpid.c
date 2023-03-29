/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
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
#include <unistd.h>
#include <sys/types.h>
#include "test_libc_func.h"

static pid_t pid;
int test_err = 0;

static void *tf(void *a)
{
    if (getpid() != pid) {
        printf("test error:pid mismatch\n");
        test_err++;
    }

    return a;
}

int do_test_getpid(void)
{
    pid = getpid();

#define N 2
    pthread_t t[N];
    int i;

    for (i = 0; i < N; ++i)
        if (pthread_create(&t[i], NULL, tf, (void *)(long int)(i + 1)) != 0) {
            printf("pthread create failed\n");
            test_err++;
        } else
            printf("created thread %d\n", i);

    for (i = 0; i < N; ++i) {
        void *r;
        int e;
        if ((e = pthread_join(t[i], &r)) != 0) {
            printf("join failed: %d\n", e);
            test_err++;
        } else if (r != (void *)(long int)(i + 1)) {
            printf("result wrong\n");
            test_err++;
        } else
            printf("joined thread %d\n", i);
    }

    return test_err;
}
