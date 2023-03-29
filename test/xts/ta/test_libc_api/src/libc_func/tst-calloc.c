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
#include <limits.h>
#include <malloc.h>
#include <stdlib.h>
#include <stdio.h>
#include "test_libc_func.h"

/* Number of samples per size.  */
#define N 5


static void fixed_test(int size)
{
    char *ptrs[N];
    int i;

    for (i = 0; i < N; ++i) {
        int j;

        ptrs[i] = (char *) calloc(1, size);

        if (ptrs[i] == NULL)
            break;

        for (j = 0; j < size; ++j) {
            if (ptrs[i][j] != '\0')
                printf("LIBC TEST Failed. byte not cleared (size %d, element %d, byte %d)",
                       size, i, j);
            ptrs[i][j] = '\xff';
        }

    }

    while (i-- > 0)
        free(ptrs[i]);
}


static void random_test(void)
{
    char *ptrs[N];
    int i;

    for (i = 0; i < N; ++i) {
        int j;
        int n = 1 + random() % 10;
        int elem = 1 + random() % 100;
        int size = n * elem;

        ptrs[i] = (char *) calloc(n, elem);

        if (ptrs[i] == NULL)
            break;

        for (j = 0; j < size; ++j) {
            if (ptrs[i][j] != '\0')
                printf("LIBC TEST Failed. byte not cleared (size %d, element %d, byte %d)",
                       size, i, j);
            ptrs[i][j] = '\xff';
        }
    }

    while (i-- > 0)
        free(ptrs[i]);
}


static void null_test(void)
{
    /* If the size is 0 the result is implementation defined.  Just make
       sure the program doesn't crash.  */
    calloc(0, 0);
    calloc(0, UINT_MAX);
    calloc(UINT_MAX, 0);
    calloc(0, ~((size_t) 0));
    calloc(~((size_t) 0), 0);
}


int do_test_calloc(void)
{
    /* We are allocating blocks with `calloc' and check whether every
       block is completely cleared.  We first try this for some fixed
       times and then with random size.  */
    fixed_test(15);
    fixed_test(5);
    fixed_test(17);
    fixed_test(6);
    fixed_test(31);
    fixed_test(96);

    random_test();

    null_test();
    
    printf("test calloc pass\n");
    return 0;
}
