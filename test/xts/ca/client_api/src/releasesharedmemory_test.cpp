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

#include <gtest/gtest.h>

#include <vector>
#include <iostream>

#include <securec.h>
#include <test_defines.h>

#include <common_test.h>
#include <empty_test.h>
#include <public_test.h>
#include <session_mgr/client_session_mgr.h>
#include <tee_client_api.h>
#include <tee_client_type.h>

using namespace std;
using namespace testing::ext;

/**
 * @testcase.name      : ReleaseSharedMemory_WithAllocatedMem
 * @testcase.desc      : call TEEC_ReleaseSharedMemory WithAllocatedMem,
 * @testcase.expect    : sharedMem.buffer has released
 */
TEE_TEST(TeeBasicTestFramWithInitContext, ReleaseSharedMemory_WithAllocatedMem, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TEEC_SharedMemory sharedMem;
    sharedMem.size = TEST_STR_LEN;
    sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(GetContext(), &sharedMem);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    TEEC_ReleaseSharedMemory(&sharedMem);
    ASSERT_STREQ(reinterpret_cast<char *>(sharedMem.buffer), NULL);
    ASSERT_STREQ(reinterpret_cast<char *>(sharedMem.context), NULL);
}

/**
 * @testcase.name      : ReleaseSharedMemory_WithRegisterMem
 * @testcase.desc      : call TEEC_ReleaseSharedMemory WithRegisterMem,
 * @testcase.expect    : sharedMem.buffer has released
 */
TEE_TEST(TeeBasicTestFramWithInitContext, ReleaseSharedMemory_WithRegisterMem, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TEEC_SharedMemory sharedMem;
    char* testData0 = reinterpret_cast<char*>(malloc(TEST_STR_LEN));
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_STR_LEN, 0x0, TEST_STR_LEN);

    sharedMem.size = TEST_STR_LEN;
    sharedMem.flags = TEEC_MEM_INOUT;
    sharedMem.buffer = testData0;
    ret = TEEC_RegisterSharedMemory(GetContext(), &sharedMem);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    TEEC_ReleaseSharedMemory(&sharedMem);
    ASSERT_STREQ(reinterpret_cast<char *>(sharedMem.buffer), NULL);
    ASSERT_STREQ(reinterpret_cast<char *>(sharedMem.context), NULL);
    free(testData0);
}

/**
 * @testcase.name      : ReleaseSharedMemory_WithoutSharedMem
 * @testcase.desc      : call TEEC_ReleaseSharedMemory WithoutSharedMem,
 * @testcase.expect    : sharedMem.buffer has not released
 */
TEE_TEST(TeeBasicTestFramWithInitContext, ReleaseSharedMemory_WithoutSharedMem, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TEEC_SharedMemory sharedMem;
    sharedMem.size = TEST_STR_LEN;
    sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(GetContext(), &sharedMem);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    TEEC_ReleaseSharedMemory(NULL);
    ASSERT_STRNE(reinterpret_cast<char*>(sharedMem.buffer), NULL);
    ASSERT_STRNE(reinterpret_cast<char*>(sharedMem.context), NULL);
}

/**
 * @testcase.name      : ReleaseSharedMemory_WithNotAllocatedSharedMem
 * @testcase.desc      : call TEEC_ReleaseSharedMemory With SharedMem Not Allocated,
 * @testcase.expect    : sharedMem.buffer is null, no error occur
 */
TEE_TEST(TeeBasicTestFramWithInitContext, ReleaseSharedMemory_WithNotAllocatedSharedMem, Function | MediumTest | Level0)
{
    TEEC_SharedMemory sharedMem = { 0 };
    sharedMem.size = TEST_STR_LEN;
    sharedMem.flags = TEEC_MEM_INOUT;

    TEEC_ReleaseSharedMemory(&sharedMem);
    ASSERT_STREQ(reinterpret_cast<char *>(sharedMem.buffer), NULL);
    ASSERT_STREQ(reinterpret_cast<char *>(sharedMem.context), NULL);
}