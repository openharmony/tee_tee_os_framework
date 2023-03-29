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

#ifndef _TEST_LIBC_CASES_H_
#define _TEST_LIBC_CASES_H_

#include <tee_core_api.h>

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

TEE_Result TestPthreadAttr(void);
TEE_Result TestPthreadBaseFunc(void);
TEE_Result TestPthreadMutexLock(void);
TEE_Result TestPthreadSpinLock(void);
TEE_Result TestPthreadCond(void);
TEE_Result TestSem(void);

TEE_Result TestApplyAndFreeMem(void);
TEE_Result TestMmapAndMunmap(void);

TEE_Result TestLibcMath(void);
TEE_Result TestLibcStdlib(void);
TEE_Result TestLibcCtype(void);
TEE_Result TestLibcTime(void);
TEE_Result TestLibcStdio(void);
TEE_Result TestLibcError(void);
TEE_Result TestLibcUnistd(void);
TEE_Result TestLibcLocale(void);
TEE_Result TestLibcMultiByte(void);
TEE_Result TestLibcPrng(void);

TEE_Result TestLibcString(void);

#endif