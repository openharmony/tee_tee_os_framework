/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <stdio.h>
#include "crypto/rand_pool.h"
#include "openssl/crypto.h"
#include "openssl/types.h"

void async_deinit(void)
{
}

int async_init(void)
{
    return 1;
}

int geteuid(void)
{
    return 0;
}

int getgid(void)
{
    return 0;
}

int getegid(void)
{
    return 0;
}

void OSSL_SELF_TEST_get_callback(OSSL_LIB_CTX *libctx, OSSL_CALLBACK **cb, void **cbarg)
{
    (void)libctx;
    (void)cb;
    (void)cbarg;
}

char *readdir(char *dirp)
{
    (void)dirp;
    return NULL;
}

char *opendir(const char *dirname)
{
    (void)dirname;
    return NULL;
}

int closedir(char* dir)
{
    (void)dir;
    return 0;
}

void ossl_rand_pool_cleanup(void)
{
}

int ossl_rand_pool_init(void)
{
    return 1;
}

int getuid(void)
{
    return 0;
}

int getpid(void)
{
    return 0;
}
