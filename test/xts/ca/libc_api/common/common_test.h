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

#ifndef __LIBC_COMMON_TEST_H__
#define __LIBC_COMMON_TEST_H__

#include <stdint.h>
#include <tee_client_type.h>

using namespace testing::ext;

#define LIBC_API_UUID                                     \
    {                                                      \
        0x534d4152, 0x542d, 0x4353,                        \
        {                                                  \
            0x4c, 0x54, 0xd3, 0x01, 0x6a, 0x17, 0x1f, 0x0c \
        }                                                  \
    }

enum LibcCmdId {
    CMD_TEST_PTHREAD_ATTR = 0,
    CMD_TEST_PTHREAD_BASE_FUNC,
    CMD_TEST_PTHREAD_MUTEX_LOCK,
    CMD_TEST_PTHREAD_SPIN_LOCK,
    CMD_TEST_PTHREAD_COND,
    CMD_TEST_SEM,
    CMD_TEST_APPLY_AND_FREE_MEM,
    CMD_TEST_MMAP_AND_MUNMAP,
    CMD_TEST_LIBC_MATH,
    CMD_TEST_LIBC_STDLIB,
    CMD_TEST_LIBC_CTYPE,
    CMD_TEST_LIBC_TIME,
    CMD_TEST_LIBC_STDIO,
    CMD_TEST_LIBC_ERROR,
    CMD_TEST_LIBC_UNISTD,
    CMD_TEST_LIBC_LOCALE,
    CMD_TEST_LIBC_MULTIBYTE,
    CMD_TEST_LIBC_PRNG,
    CMD_TEST_LIBC_STRING,
};

#endif
