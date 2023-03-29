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

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include "test_libc_func.h"


static clockid_t clocks[2] = { CLOCK_REALTIME, CLOCK_MONOTONIC };
#define TEST_LOOPING (100)
#define MILLISECOND 1000
#define WAIT5S 5

int do_test_clock_gettime(void)
{
    int lc, i;
    struct timespec spec;
    int ret = 0, test_ret;

    for (lc = 0; lc < TEST_LOOPING; lc++) {
        for (i = 0; i < (int)(sizeof(clocks) / sizeof(clockid_t)); i++) {
            test_ret = clock_gettime(clocks[i], &spec);
            if (test_ret < 0) {
                ret = -1;
                goto fail;
            }
        }
    }

    // invalid address
    test_ret = clock_gettime(clocks[0], NULL);
    //test_ret |= clock_gettime(clocks[1], -1);
    if (test_ret == 0) ret = -2;

fail:
    return ret;
}

int do_test_strftime(void)
{
    struct tm newtime;
    char buffer[80];

    newtime.tm_sec = 10;
    newtime.tm_min = 20;
    newtime.tm_hour = 20;
    newtime.tm_mday = 1;
    newtime.tm_mon = 3;
    newtime.tm_year = 118;
    newtime.tm_wday = 2;
    newtime.tm_yday = 11;

    strftime(buffer, 80, "%x - %I:%M%p", &newtime);
    printf("time is : |%s|\n", buffer);

    return (0);
}
