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
#include <malloc.h>
#include <stdio.h>
#include "test_libc_func.h"

static int errors = 0;

static void merror(const char *msg)
{
    ++errors;
    printf("Error: %s\n", msg);
}

int do_test_malloc(void)
{
    void *p, *q;

    p = malloc(-1);
    if (p != NULL)
        merror("malloc (-1) succeeded.\n");

    if (p == NULL && errno != ENOMEM)
        merror("errno is not set correctly.\n");

    p = malloc(10);
    if (p == NULL)
        merror("malloc (10) failed.");

    /* realloc (p, 0) == free (p).  */
    p = realloc(p, 0);
    if (p != NULL)
        merror("realloc (p, 0) failed.");

    p = malloc(0);
    if (p != NULL)
        merror("malloc (0) failed.");

    p = realloc(p, 0);
    if (p != NULL)
        merror("realloc (p, 0) failed.");

    p = malloc(513 * 1024);
    if (p == NULL)
        merror("malloc (513K) failed.");

    p = realloc(p, 513 * 1024 - 3);
    if (p == NULL)
        merror("realloc (p,  513 * 1024 - 3) failed.");

    p = realloc(p, 513 * 1024 + 3);
    if (p == NULL)
        merror("realloc (p,  513 * 1024 + 3) failed.");
    free(p);

    p = malloc(16);
    if (p == NULL)
        merror("malloc (16) failed.");

    p = realloc(p, 16 + 1024);
    if (p == NULL)
        merror("realloc (p,  16 + 1024) failed.");

    p = realloc(p, 15 + 1024);
    if (p == NULL)
        merror("realloc (p,  15 + 1024) failed.");
    free(p);

    q = malloc(-512 * 1024);
    if (q != NULL)
        merror("malloc (-512K) succeeded.");
    
    printf("test malloc pass\n");
    return errors;
}
