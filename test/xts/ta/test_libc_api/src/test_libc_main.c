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

#include <tee_ext_api.h>
#include <tee_log.h>
#include <securec.h>
#include <test_libc_cases.h>

#define CA_VENDOR "/vendor/bin/tee_test_libc_api"
#define CA_SYSTEM "/system/bin/tee_test_libc_api"
#define CA_UID 0

typedef TEE_Result (* TestLibcApiFunc)(void);

typedef struct {
    uint32_t cmdId;
    TestLibcApiFunc func;
} TestFunctionWithCmd;

static TestFunctionWithCmd g_cmdList[] = {
    {CMD_TEST_PTHREAD_ATTR, TestPthreadAttr}, // 0
    {CMD_TEST_PTHREAD_BASE_FUNC, TestPthreadBaseFunc},
    {CMD_TEST_PTHREAD_MUTEX_LOCK, TestPthreadMutexLock},
    {CMD_TEST_PTHREAD_SPIN_LOCK, TestPthreadSpinLock},
    {CMD_TEST_PTHREAD_COND, TestPthreadCond},
    {CMD_TEST_SEM, TestSem},
    {CMD_TEST_APPLY_AND_FREE_MEM, TestApplyAndFreeMem},
    {CMD_TEST_MMAP_AND_MUNMAP, TestMmapAndMunmap},
    {CMD_TEST_LIBC_MATH, TestLibcMath},
    {CMD_TEST_LIBC_STDLIB, TestLibcStdlib},
    {CMD_TEST_LIBC_CTYPE, TestLibcCtype},
    {CMD_TEST_LIBC_TIME, TestLibcTime},
    {CMD_TEST_LIBC_STDIO, TestLibcStdio},
    {CMD_TEST_LIBC_ERROR, TestLibcError},
    {CMD_TEST_LIBC_UNISTD, TestLibcUnistd},
    {CMD_TEST_LIBC_LOCALE, TestLibcLocale},
    {CMD_TEST_LIBC_MULTIBYTE, TestLibcMultiByte},
    {CMD_TEST_LIBC_PRNG, TestLibcPrng},
    {CMD_TEST_LIBC_STRING, TestLibcString},
};

static TEE_Result TestLibcApi(uint32_t cmdId)
{
    uint32_t count = sizeof(g_cmdList) / sizeof(g_cmdList[0]);
    tlogi("[TestLibcApi]: g_cmdList count = %d, cmdId = %d\n", count, cmdId);
    for (uint32_t i = 0; i < count; i++) {
        if (g_cmdList[i].cmdId == cmdId) {
            return g_cmdList[i].func();
        }
    }

    tlogi("unknown command id, cmdId: %u\n", cmdId);
    return TEE_ERROR_INVALID_CMD;
}

TEE_Result TA_CreateEntryPoint(void)
{
    tlogi("---- TA_CreateEntryPoint ---------");
    TEE_Result ret = AddCaller_CA_exec(CA_VENDOR, CA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("Add caller failed, ret = 0x%x", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(CA_SYSTEM, CA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("Add caller failed, ret = 0x%x", ret);
        return ret;
    }
    return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t parmType, TEE_Param params[4], void **sessionContext)
{
    (void)parmType;
    (void)params;
    (void)sessionContext;
    tlogi("---- TA_OpenSessionEntryPoint --------");

    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t cmdId, uint32_t parmType, TEE_Param params[4])
{
    TEE_Result ret = TEE_SUCCESS;
    (void)sessionContext;
    (void)params;
    (void)parmType;

    ret = TestLibcApi(cmdId);
    if (ret != TEE_SUCCESS)
        tloge("invoke command for value failed! cmdId: %u, ret: 0x%x", cmdId, ret);

    return ret;
}

void TA_CloseSessionEntryPoint(void *sessionContext)
{
    (void)sessionContext;
    tlogi("---- TA_CloseSessionEntryPoint -----");
}

void TA_DestroyEntryPoint(void)
{
    tlogi("---- TA_DestroyEntryPoint ----");
}

