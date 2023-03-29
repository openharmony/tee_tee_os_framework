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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "test_libc_func.h"

int test_error(void)
{
    printf("=== test error begin ===\n");
    const char *str = "File descriptor in bad state";
    errno = EBADFD;
    char *msg = strerror(errno);
    if (strcmp(str, msg) != 0) {
        printf("Failed: errno and strerror failed\n");
        return -1;
    }
    printf("=== test error end   ===\n\n");
    return 0;
}