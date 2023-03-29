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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include "test_libc_func.h"

int do_test_free(void)
{
	void *p;

    p = malloc(1);
    free(p);

    p = malloc(4);
    free(p);

    p = malloc(1024 * 1024);
    free(p);
    return 0;
}

int do_test_free_1(void)
{
    char *str;
    str = (char *)malloc(10);
    strcpy(str, "Hello");
    printf("free test: String is %s\n", str);
    free(str);
    str = NULL;
    return 0;
}
