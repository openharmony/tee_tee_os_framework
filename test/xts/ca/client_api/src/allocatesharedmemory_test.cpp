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
#include <test_comm_cmdid.h>

// The test case uses the same string to pass the input and output test of buffer during REE and tee communication
static char g_teeOutput[] = "TEEMEM_OUTPUT";
static char g_teeInout[] = "the param is TEEMEM_INOUT";
static uint32_t g_teeOutputLen;
static uint32_t g_teeInoutLen;

static char g_offset0[] = "11223344556677889900";
static char g_offset100[] = "offset is 100";
static char g_offset200[] = "offset is 200";
static char g_offset300[] = "offset is 300";


#define MAILBOXPOOL_MAX_SIZE (1024 * 1024 * 4)

using namespace std;
using namespace testing::ext;

/**
 * @testcase.name      : AllocateSharedMemory_WithAllocatedMem
 * @testcase.desc      : call TEEC_AllocateSharedMemory normal test
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(OnlyInit, AllocateSharedMemory_WithAllocatedMem, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    GetSharedMem()->size = TEST_STR_LEN;
    GetSharedMem()->flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(GetContext(), GetSharedMem());
    EXPECT_EQ(ret, TEEC_SUCCESS);
}

/**
 * @testcase.name      : AllocateSharedMemory_WithoutContext
 * @testcase.desc      : call TEEC_AllocateSharedMemory Without Context
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, AllocateSharedMemory_WithoutContext, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    GetSharedMem()->size = TEST_STR_LEN;
    GetSharedMem()->flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(NULL, GetSharedMem());
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
}

/**
 * @testcase.name      : AllocateSharedMemory_WithNotInitContext
 * @testcase.desc      : call TEEC_AllocateSharedMemory With Context is not init
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(EmptyTest, AllocateSharedMemory_WithNotInitContext, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TEEC_Context context = { 0 };
    const char *name = "testname";
    TEEC_SharedMemory sharedMem;
    sharedMem.size = TEST_STR_LEN;
    sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_InitializeContext(name, &context);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    TEEC_FinalizeContext(&context);
    ret = TEEC_AllocateSharedMemory(&context, &sharedMem);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
}

/**
 * @testcase.name      : AllocateSharedMemory_WithoutSharedMem
 * @testcase.desc      : call TEEC_AllocateSharedMemory Without SharedMem
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, AllocateSharedMemory_WithoutSharedMem, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    ret = TEEC_AllocateSharedMemory(GetContext(), NULL);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
}

/**
 * @testcase.name      : AllocateSharedMemory_WithSharedMemHasReleased
 * @testcase.desc      : call TEEC_AllocateSharedMemory With SharedMem has Released
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, AllocateSharedMemory_WithSharedMemHasReleased, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    GetSharedMem()->size = TEST_STR_LEN;
    GetSharedMem()->flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(GetContext(), GetSharedMem());
    EXPECT_EQ(ret, TEEC_SUCCESS);

    TEEC_ReleaseSharedMemory(GetSharedMem());
    ret = TEEC_AllocateSharedMemory(GetContext(), GetSharedMem());
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
}

/**
 * @testcase.name      : AllocateSharedMemory_WithSharedMemSizeIsZero
 * @testcase.desc      : call TEEC_AllocateSharedMemory With SharedMem size is 0
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(OnlyInit, AllocateSharedMemory_WithSharedMemSizeIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    GetSharedMem()->size = 0;
    GetSharedMem()->flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(GetContext(), GetSharedMem());
    ASSERT_EQ(ret, TEEC_SUCCESS);
}

/**
 * @testcase.name      : AllocateSharedMemory_WithSharedMemFlagIsZero
 * @testcase.desc      : call TEEC_AllocateSharedMemory With SharedMem flag is 0
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, AllocateSharedMemory_WithSharedMemFlagIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    GetSharedMem()->size = TEST_STR_LEN;
    GetSharedMem()->flags = 0;
    ret = TEEC_AllocateSharedMemory(GetContext(), GetSharedMem());
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
}

/**
 * @testcase.name      : AllocateSharedMemory_WithSharedMemFlagIsInvalid
 * @testcase.desc      : call TEEC_AllocateSharedMemory With SharedMem flag is invalid
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, AllocateSharedMemory_WithSharedMemFlagIsInvalid, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    GetSharedMem()->size = TEST_STR_LEN;
    GetSharedMem()->flags = TEEC_MEM_INVALID;
    ret = TEEC_AllocateSharedMemory(GetContext(), GetSharedMem());
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
}

/**
 * @testcase.name      : AllocateSharedMemory_WithFlagInput_UseParamTypesOutput
 * @testcase.desc      : call TEEC_AllocateSharedMemory With SharedMem flag is input,
 * while TEEC_InvokeCommand ParamTypes is output
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(EmptyTest, AllocateSharedMemory_WithFlagInput_UseParamTypesOutput, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    /* *allocate shared memory* */
    ClientShareMemMgr testMem;
    testMem.sharedMem.size = TEST_STR_LEN;
    testMem.sharedMem.flags = TEEC_MEM_INPUT;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, testMem.sharedMem.size, 0x0, testMem.sharedMem.size);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = testMem.sharedMem.size;
    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : AllocateSharedMemory_WithFlagInput_UseParamTypesInout
 * @testcase.desc      : call TEEC_AllocateSharedMemory With SharedMem flag is input,
 * while TEEC_InvokeCommand ParamTypes is inout
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(EmptyTest, AllocateSharedMemory_WithFlagInput_UseParamTypesInout, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    /* *allocate shared memory* */
    ClientShareMemMgr testMem;
    testMem.sharedMem.flags = TEEC_MEM_INPUT;
    testMem.sharedMem.size = TEST_STR_LEN;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, testMem.sharedMem.size, 0x0, testMem.sharedMem.size);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = testMem.sharedMem.size;
    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : AllocateSharedMemory_WithFlagInput_UseParamTypesWhole
 * @testcase.desc      : call TEEC_AllocateSharedMemory With SharedMem flag is input,
 * while TEEC_InvokeCommand ParamTypes is whole
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, AllocateSharedMemory_WithFlagInput_UseParamTypesWhole, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_Operation operation = { 0 };
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    /* *allocate shared memory* */
    ClientShareMemMgr testMem;
    testMem.sharedMem.flags = TEEC_MEM_INPUT;
    testMem.sharedMem.size = TEST_STR_LEN;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, testMem.sharedMem.size, 0x0, testMem.sharedMem.size);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = OFFSET100;
    operation.params[0].memref.size = testMem.sharedMem.size - OFFSET100;
    operation.params[1].memref.parent = &testMem.sharedMem;
    operation.params[1].memref.offset = 0;
    operation.params[1].memref.size = 0;
    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : AllocateSharedMemory_WithFlagOutput_UseParamTypesInput
 * @testcase.desc      : call TEEC_AllocateSharedMemory With SharedMem flag is output,
 * while TEEC_InvokeCommand ParamTypes is input
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(EmptyTest, AllocateSharedMemory_WithFlagOutput_UseParamTypesInput, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    /* *allocate shared memory* */
    ClientShareMemMgr testMem;
    testMem.sharedMem.size = TEST_STR_LEN;
    testMem.sharedMem.flags = TEEC_MEM_OUTPUT;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, testMem.sharedMem.size, 0x0, testMem.sharedMem.size);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = testMem.sharedMem.size;
    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : AllocateSharedMemory_WithFlagOutput_UseParamTypesInout
 * @testcase.desc      : call TEEC_AllocateSharedMemory With SharedMem flag is output,
 * while TEEC_InvokeCommand ParamTypes is inout
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(EmptyTest, AllocateSharedMemory_WithFlagOutput_UseParamTypesInout, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    /* *allocate shared memory* */
    ClientShareMemMgr testMem;
    testMem.sharedMem.flags = TEEC_MEM_OUTPUT;
    testMem.sharedMem.size = TEST_STR_LEN;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, testMem.sharedMem.size, 0x0, testMem.sharedMem.size);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = testMem.sharedMem.size;
    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : AllocateSharedMemory_WithFlagOutput_UseParamTypesWhole
 * @testcase.desc      : call TEEC_AllocateSharedMemory With SharedMem flag is output,
 * while TEEC_InvokeCommand ParamTypes is whole
 * @testcase.expect    : return TEEC_SUCCESS ,output buffer is correct
 */
TEE_TEST(EmptyTest, AllocateSharedMemory_WithFlagOutput_UseParamTypesWhole, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    g_teeOutputLen = strlen(g_teeOutput) + 1;

    /* *allocate shared memory* */
    ClientShareMemMgr testMem;
    testMem.sharedMem.flags = TEEC_MEM_OUTPUT;
    testMem.sharedMem.size = TEST_STR_LEN;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, testMem.sharedMem.size, 0x0, testMem.sharedMem.size);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = OFFSET100;
    operation.params[0].memref.size = testMem.sharedMem.size - OFFSET100;
    operation.params[1].memref.parent = &testMem.sharedMem;
    operation.params[1].memref.offset = 0;
    operation.params[1].memref.size = 0;
    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_STREQ(reinterpret_cast<char *>(testMem.sharedMem.buffer) + OFFSET100, g_teeOutput);
    EXPECT_EQ(operation.params[0].memref.size, g_teeOutputLen);
    EXPECT_STREQ(reinterpret_cast<char *>(testMem.sharedMem.buffer), g_teeOutput);
    EXPECT_EQ(operation.params[1].memref.size, 0);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
}

static int CopyToBuffer(char *buffer, uint32_t buffer_size)
{
    int rc = strcpy_s(buffer, buffer_size, g_offset0);
    EXPECT_EQ(rc, 0);
    rc = strcpy_s(buffer + OFFSET100, buffer_size - OFFSET100, g_offset100);
    EXPECT_EQ(rc, 0);
    rc = strcpy_s(buffer + OFFSET200, buffer_size - OFFSET200, g_offset200);
    EXPECT_EQ(rc, 0);
    rc = strcpy_s(buffer + OFFSET300, buffer_size - OFFSET300, g_offset300);
    EXPECT_EQ(rc, 0);
    return rc;
}

/**
 * @testcase.name      : AllocateSharedMemory_ReturnLenUseTypesOutput
 * @testcase.desc      : test for allocatedshared with some params ree size less tee write size, use output types
 * @testcase.expect    : return TEEC_ERROR_SHORT_BUFFER ,output buffer is correct
 */
TEE_TEST(EmptyTest, AllocateSharedMemory_ReturnLenUseTypesOutput, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    int rc;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    g_teeOutputLen = strlen(g_teeOutput) + 1;

    /* *allocate shared memory* */
    ClientShareMemMgr testMem;
    testMem.sharedMem.flags = TEEC_MEM_OUTPUT;
    testMem.sharedMem.size = TEST_SIZE512;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, testMem.sharedMem.size, 0x0, testMem.sharedMem.size);
    rc = CopyToBuffer(reinterpret_cast<char *>(testMem.sharedMem.buffer), testMem.sharedMem.size);
    EXPECT_EQ(rc, 0);

    TEEC_Operation operation = { 0 };
    /* for test TEEC_MEMREF_PARTIAL_OUTPUT, [0] size < tee size, [1] size < tee size [2] size > tee size [3] size > tee
     * size */
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_MEMREF_PARTIAL_OUTPUT,
        TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_MEMREF_PARTIAL_OUTPUT);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = SIZE10;
    operation.params[1].memref.parent = &testMem.sharedMem;
    operation.params[1].memref.offset = OFFSET100;
    operation.params[1].memref.size = SIZE10;
    operation.params[2].memref.parent = &testMem.sharedMem;
    operation.params[2].memref.offset = OFFSET200;
    operation.params[2].memref.size = SIZE20;
    operation.params[3].memref.parent = &testMem.sharedMem;
    operation.params[3].memref.offset = OFFSET300;
    operation.params[3].memref.size = SIZE20;
    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    EXPECT_EQ(ret, TEEC_ERROR_SHORT_BUFFER);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_EQ(operation.params[0].memref.size, g_teeOutputLen);
    EXPECT_EQ(operation.params[1].memref.size, g_teeOutputLen);
    EXPECT_EQ(operation.params[2].memref.size, g_teeOutputLen);
    EXPECT_EQ(operation.params[3].memref.size, g_teeOutputLen);
    EXPECT_STREQ(reinterpret_cast<char *>(testMem.sharedMem.buffer), g_offset0);
    EXPECT_STREQ(reinterpret_cast<char *>(testMem.sharedMem.buffer) + OFFSET100, g_offset100);
    EXPECT_STREQ(reinterpret_cast<char *>(testMem.sharedMem.buffer) + OFFSET200, g_teeOutput);
    EXPECT_STREQ(reinterpret_cast<char *>(testMem.sharedMem.buffer) + OFFSET300, g_teeOutput);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
}

/**
 * @testcase.name      : AllocateSharedMemory_ReturnLenUseTypesInout
 * @testcase.desc      : test for allocatedshared with some params ree size less tee write size, use inout types
 * @testcase.expect    : return TEEC_ERROR_SHORT_BUFFER ,output buffer is correct
 */
TEE_TEST(EmptyTest, AllocateSharedMemory_ReturnLenUseTypesInout, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    int rc;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    g_teeOutputLen = strlen(g_teeOutput) + 1;
    g_teeInoutLen = strlen(g_teeInout) + 1;
    /* *allocate shared memory* */
    ClientShareMemMgr testMem;
    testMem.sharedMem.size = TEST_SIZE512;
    testMem.sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, testMem.sharedMem.size, 0x0, testMem.sharedMem.size);
    rc = CopyToBuffer(reinterpret_cast<char *>(testMem.sharedMem.buffer), testMem.sharedMem.size);
    EXPECT_EQ(rc, 0);

    TEEC_Operation operation = { 0 };
    /* for test TEEC_MEMREF_PARTIAL_INOUT, [0] size > tee size, [1] size < tee size [2] size < tee size [3] size < tee
     * size */
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_MEMREF_PARTIAL_INOUT,
        TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_MEMREF_PARTIAL_OUTPUT);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = SIZE20 + SIZE10;
    operation.params[1].memref.parent = &testMem.sharedMem;
    operation.params[1].memref.offset = OFFSET100;
    operation.params[1].memref.size = SIZE20;
    operation.params[2].memref.parent = &testMem.sharedMem;
    operation.params[2].memref.offset = OFFSET200;
    operation.params[2].memref.size = SIZE10;
    operation.params[3].memref.parent = &testMem.sharedMem;
    operation.params[3].memref.offset = OFFSET300;
    operation.params[3].memref.size = SIZE10;
    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    EXPECT_EQ(ret, TEEC_ERROR_SHORT_BUFFER);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_EQ(operation.params[0].memref.size, g_teeInoutLen);
    EXPECT_EQ(operation.params[1].memref.size, g_teeInoutLen);
    EXPECT_EQ(operation.params[2].memref.size, g_teeOutputLen);
    EXPECT_EQ(operation.params[3].memref.size, g_teeOutputLen);
    EXPECT_STREQ(reinterpret_cast<char *>(testMem.sharedMem.buffer), g_teeInout);
    EXPECT_STREQ(reinterpret_cast<char *>(testMem.sharedMem.buffer) + OFFSET100, g_offset100);
    EXPECT_STREQ(reinterpret_cast<char *>(testMem.sharedMem.buffer) + OFFSET200, g_offset200);
    EXPECT_STREQ(reinterpret_cast<char *>(testMem.sharedMem.buffer) + OFFSET300, g_offset300);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
}

/**
 * @testcase.name      : AllocateSharedMemory_OffsetExceedTest1
 * @testcase.desc      : test for memref.offset + memref.size > sharedMem.size ,should return bad params
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(EmptyTest, AllocateSharedMemory_OffsetExceedTest1, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    g_teeOutputLen = strlen(g_teeOutput) + 1;
    /* *allocate shared memory* */
    ClientShareMemMgr testMem;
    testMem.sharedMem.size = TEST_SIZE512;
    testMem.sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, testMem.sharedMem.size, 0x0, testMem.sharedMem.size);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_MEMREF_PARTIAL_OUTPUT,
        TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_MEMREF_PARTIAL_OUTPUT);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = SIZE10;
    operation.params[1].memref.parent = &testMem.sharedMem;
    operation.params[1].memref.offset = OFFSET100;
    operation.params[1].memref.size = SIZE10;
    operation.params[2].memref.parent = &testMem.sharedMem;
    operation.params[2].memref.offset = OFFSET200;
    operation.params[2].memref.size = SIZE20;
    operation.params[3].memref.parent = &testMem.sharedMem;
    operation.params[3].memref.offset = TEST_SIZE512 - SIZE10 + 1;
    operation.params[3].memref.size = SIZE10;
    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : AllocateSharedMemory_OffsetExceedTest2
 * @testcase.desc      : test for memref.offset > sharedMem.size ,should return bad params
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(EmptyTest, AllocateSharedMemory_OffsetExceedTest2, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    g_teeOutputLen = strlen(g_teeOutput) + 1;
    /* *allocate shared memory* */
    ClientShareMemMgr testMem;
    testMem.sharedMem.flags = TEEC_MEM_INOUT;
    testMem.sharedMem.size = TEST_SIZE512;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, testMem.sharedMem.size, 0x0, testMem.sharedMem.size);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_MEMREF_PARTIAL_INOUT,
        TEEC_MEMREF_PARTIAL_INOUT, TEEC_MEMREF_PARTIAL_INOUT);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = SIZE10;
    operation.params[1].memref.parent = &testMem.sharedMem;
    operation.params[1].memref.offset = OFFSET100;
    operation.params[1].memref.size = SIZE10;
    operation.params[2].memref.parent = &testMem.sharedMem;
    operation.params[2].memref.offset = OFFSET200;
    operation.params[2].memref.size = SIZE20;
    operation.params[3].memref.parent = &testMem.sharedMem;
    operation.params[3].memref.offset = TEST_SIZE512 + 1;
    operation.params[3].memref.size = SIZE10;
    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : AllocateSharedMemory_WithSizeExceed
 * @testcase.desc      : call TEEC_AllocateSharedMemory With SharedMem size exceed 4M
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, AllocateSharedMemory_WithSizeExceed, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    GetSharedMem()->size = MAILBOXPOOL_MAX_SIZE + 1; // 4M + 1
    GetSharedMem()->flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(GetContext(), GetSharedMem());
    ASSERT_EQ(ret, TEEC_ERROR_OUT_OF_MEMORY);
}

#define SHAREMEM_LIMIT_MAX 64

/**
 * @testcase.name      : AllocateSharedMemory_ReachSharememNumLimit
 * @testcase.desc      : call TEEC_AllocateSharedMemory With same Context 65 times,
 * This case will generate wild pointers, but these pointers are all hung on the same context.
 * The teardown function at the end of the use case will recycle the context to ensure the
 * recycling of these wild pointers.
 * @testcase.expect    : alloc 65 times should return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, AllocateSharedMemory_ReachSharememNumLimit, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t i;
    GetSharedMem()->size = TEST_STR_LEN; // 256
    GetSharedMem()->flags = TEEC_MEM_INOUT;

    for (i = 1; i <= SHAREMEM_LIMIT_MAX; i++) {
        ret = TEEC_AllocateSharedMemory(GetContext(), GetSharedMem());
        ASSERT_EQ(ret, TEEC_SUCCESS);
    }

    // alloc 65 times
    ret = TEEC_AllocateSharedMemory(GetContext(), GetSharedMem());
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
}