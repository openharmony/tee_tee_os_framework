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

using namespace std;

/**
 * @testcase.name      : RegisterSharedMemory_WithRegisterMem
 * @testcase.desc      : call TEEC_RegisterSharedMemory With RegisterMem
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(OnlyInit, RegisterSharedMemory_WithRegisterMem, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    char *testData0 = (char *)malloc(TEST_STR_LEN);
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_STR_LEN, 0x0, TEST_STR_LEN);
    GetSharedMem()->buffer = testData0;
    GetSharedMem()->size = TEST_STR_LEN;
    GetSharedMem()->flags = TEEC_MEM_INOUT;
    ret = TEEC_RegisterSharedMemory(GetContext(), GetSharedMem());
    free(testData0);
    ASSERT_EQ(ret, TEEC_SUCCESS);
}

/**
 * @testcase.name      : RegisterSharedMemory_WithoutContext
 * @testcase.desc      : call TEEC_RegisterSharedMemory Without Context
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, RegisterSharedMemory_WithoutContext, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    char *testData0 = (char *)malloc(TEST_STR_LEN);
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_STR_LEN, 0x0, TEST_STR_LEN);
    GetSharedMem()->buffer = testData0;
    GetSharedMem()->size = TEST_STR_LEN;
    GetSharedMem()->flags = TEEC_MEM_INOUT;
    ret = TEEC_RegisterSharedMemory(NULL, GetSharedMem());
    free(testData0);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
}

/**
 * @testcase.name      : RegisterSharedMemory_WithNotInitContext
 * @testcase.desc      : call TEEC_RegisterSharedMemory With Context is not init
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(EmptyTest, RegisterSharedMemory_WithNotInitContext, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TEEC_Context context = { 0 };
    TEEC_SharedMemory sharedMem;
    char *testData0 = (char *)malloc(TEST_STR_LEN);
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_STR_LEN, 0x0, TEST_STR_LEN);
    sharedMem.buffer = testData0;
    sharedMem.size = TEST_STR_LEN;
    sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_RegisterSharedMemory(&context, &sharedMem);
    free(testData0);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
}

/**
 * @testcase.name      : RegisterSharedMemory_WithoutSharedMem
 * @testcase.desc      : call TEEC_RegisterSharedMemory Without SharedMem
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, RegisterSharedMemory_WithoutSharedMem, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    ret = TEEC_RegisterSharedMemory(GetContext(), NULL);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
}

/**
 * @testcase.name      : RegisterSharedMemory_WithSharedMemSizeIsZero
 * @testcase.desc      : call TEEC_RegisterSharedMemory With SharedMem size is 0
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(OnlyInit, RegisterSharedMemory_WithSharedMemSizeIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    char *testData0 = (char *)malloc(TEST_STR_LEN);
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_STR_LEN, 0x0, TEST_STR_LEN);
    GetSharedMem()->buffer = testData0;
    GetSharedMem()->size = 0;
    GetSharedMem()->flags = TEEC_MEM_INOUT;
    ret = TEEC_RegisterSharedMemory(GetContext(), GetSharedMem());
    free(testData0);
    ASSERT_EQ(ret, TEEC_SUCCESS);
}

/**
 * @testcase.name      : RegisterSharedMemory_WithSharedMemFlagIsZero
 * @testcase.desc      : call TEEC_RegisterSharedMemory With SharedMem flag is 0
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, RegisterSharedMemory_WithSharedMemFlagIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    char *testData0 = (char *)malloc(TEST_STR_LEN);
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_STR_LEN, 0x0, TEST_STR_LEN);
    GetSharedMem()->buffer = testData0;
    GetSharedMem()->size = TEST_STR_LEN;
    GetSharedMem()->flags = 0;
    ret = TEEC_RegisterSharedMemory(GetContext(), GetSharedMem());
    free(testData0);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
}

/**
 * @testcase.name      : RegisterSharedMemory_WithSharedMemFlagIsInvalid
 * @testcase.desc      : call TEEC_RegisterSharedMemory With SharedMem flag is invalid
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, RegisterSharedMemory_WithSharedMemFlagIsInvalid, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    char *testData0 = (char *)malloc(TEST_STR_LEN);
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_STR_LEN, 0x0, TEST_STR_LEN);
    GetSharedMem()->buffer = testData0;
    GetSharedMem()->size = TEST_STR_LEN;
    GetSharedMem()->flags = TEEC_MEM_INVALID;
    ret = TEEC_RegisterSharedMemory(GetContext(), GetSharedMem());
    free(testData0);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
}

/**
 * @testcase.name      : RegisterSharedMemory_WithSharedMemBufferIsNull
 * @testcase.desc      : call TEEC_RegisterSharedMemory With SharedMem buffer is null
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, RegisterSharedMemory_WithSharedMemBufferIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    char *testData0 = (char *)malloc(TEST_STR_LEN);
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_STR_LEN, 0x0, TEST_STR_LEN);
    GetSharedMem()->size = TEST_STR_LEN;
    GetSharedMem()->flags = TEEC_MEM_INOUT;
    ret = TEEC_RegisterSharedMemory(GetContext(), GetSharedMem());
    free(testData0);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
}

/**
 * @testcase.name      : RegisterSharedMemory_WithFlagInput_UseParamTypesOutput
 * @testcase.desc      : call TEEC_RegisterSharedMemory With SharedMem flag is input while ParamTypes is Output
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(EmptyTest, RegisterSharedMemory_WithFlagInput_UseParamTypesOutput, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    /* *allocate shared memory* */
    char *testData0 = (char *)malloc(TEST_STR_LEN);
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_STR_LEN, 0x0, TEST_STR_LEN);
    ClientShareMemMgr testMem;
    testMem.sharedMem.buffer = testData0;
    testMem.sharedMem.size = TEST_STR_LEN;
    testMem.sharedMem.flags = TEEC_MEM_INPUT;
    ret = TEEC_RegisterSharedMemory(&sess.context, &testMem.sharedMem);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = testMem.sharedMem.size;
    ret = TEEC_InvokeCommand(&sess.session, GET_COMM_CMDID(TEE_TEST_ALLTYPE), &operation, &origin);
    free(testData0);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : RegisterSharedMemory_WithFlagInput_UseParamTypesInout
 * @testcase.desc      : call TEEC_RegisterSharedMemory With SharedMem flag is input while ParamTypes is inout
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(EmptyTest, RegisterSharedMemory_WithFlagInput_UseParamTypesInout, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    /* *allocate shared memory* */
    char *testData0 = (char *)malloc(TEST_STR_LEN);
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_STR_LEN, 0x0, TEST_STR_LEN);
    ClientShareMemMgr testMem;
    testMem.sharedMem.size = TEST_STR_LEN;
    testMem.sharedMem.flags = TEEC_MEM_INPUT;
    testMem.sharedMem.buffer = testData0;
    ret = TEEC_RegisterSharedMemory(&sess.context, &testMem.sharedMem);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = testMem.sharedMem.size;
    ret = TEEC_InvokeCommand(&sess.session, GET_COMM_CMDID(TEE_TEST_ALLTYPE), &operation, &origin);
    free(testData0);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : RegisterSharedMemory_WithFlagInput_UseParamTypesWhole
 * @testcase.desc      : call TEEC_RegisterSharedMemory With SharedMem flag is input while ParamTypes is whole
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, RegisterSharedMemory_WithFlagInput_UseParamTypesWhole, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_Operation operation = { 0 };
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    /* *allocate shared memory* */
    char *testData0 = (char *)malloc(TEST_STR_LEN);
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_STR_LEN, 0x0, TEST_STR_LEN);
    ClientShareMemMgr testMem;
    testMem.sharedMem.buffer = testData0;
    testMem.sharedMem.flags = TEEC_MEM_INPUT;
    testMem.sharedMem.size = TEST_STR_LEN;
    ret = TEEC_RegisterSharedMemory(&sess.context, &testMem.sharedMem);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = OFFSET100;
    operation.params[0].memref.size = testMem.sharedMem.size - OFFSET100;
    operation.params[1].memref.parent = &testMem.sharedMem;
    operation.params[1].memref.offset = 0;
    operation.params[1].memref.size = 0;
    ret = TEEC_InvokeCommand(&sess.session, GET_COMM_CMDID(TEE_TEST_ALLTYPE), &operation, &origin);
    free(testData0);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : RegisterSharedMemory_WithFlagOutput_UseParamTypesInput
 * @testcase.desc      : call TEEC_RegisterSharedMemory With SharedMem flag is output while ParamTypes is input
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(EmptyTest, RegisterSharedMemory_WithFlagOutput_UseParamTypesInput, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    /* *allocate shared memory* */
    char *testData0 = (char *)malloc(TEST_STR_LEN);
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_STR_LEN, 0x0, TEST_STR_LEN);
    ClientShareMemMgr testMem;
    testMem.sharedMem.buffer = testData0;
    testMem.sharedMem.flags = TEEC_MEM_OUTPUT;
    testMem.sharedMem.size = TEST_STR_LEN;
    ret = TEEC_RegisterSharedMemory(&sess.context, &testMem.sharedMem);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = testMem.sharedMem.size;
    ret = TEEC_InvokeCommand(&sess.session, GET_COMM_CMDID(TEE_TEST_ALLTYPE), &operation, &origin);
    free(testData0);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : RegisterSharedMemory_WithFlagOutput_UseParamTypesInout
 * @testcase.desc      : call TEEC_RegisterSharedMemory With SharedMem flag is output while ParamTypes is inout
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(EmptyTest, RegisterSharedMemory_WithFlagOutput_UseParamTypesInout, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    /* *allocate shared memory* */
    char *testData0 = (char *)malloc(TEST_STR_LEN);
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_STR_LEN, 0x0, TEST_STR_LEN);
    ClientShareMemMgr testMem;
    testMem.sharedMem.flags = TEEC_MEM_OUTPUT;
    testMem.sharedMem.size = TEST_STR_LEN;
    testMem.sharedMem.buffer = testData0;
    ret = TEEC_RegisterSharedMemory(&sess.context, &testMem.sharedMem);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = testMem.sharedMem.size;
    ret = TEEC_InvokeCommand(&sess.session, GET_COMM_CMDID(TEE_TEST_ALLTYPE), &operation, &origin);
    free(testData0);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : RegisterSharedMemory_WithFlagOutput_UseParamTypesWhole
 * @testcase.desc      : call TEEC_RegisterSharedMemory With SharedMem flag is output while ParamTypes is whole
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, RegisterSharedMemory_WithFlagOutput_UseParamTypesWhole, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    g_teeOutputLen = strlen(g_teeOutput) + 1;

    /* *allocate shared memory* */
    char *testData0 = (char *)malloc(TEST_STR_LEN);
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_STR_LEN, 0x0, TEST_STR_LEN);
    ClientShareMemMgr testMem;
    testMem.sharedMem.flags = TEEC_MEM_OUTPUT;
    testMem.sharedMem.size = TEST_STR_LEN;
    testMem.sharedMem.buffer = testData0;
    ret = TEEC_RegisterSharedMemory(&sess.context, &testMem.sharedMem);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE, TEEC_NONE);
    operation.params[1].memref.parent = &testMem.sharedMem;
    operation.params[1].memref.offset = OFFSET100;
    operation.params[1].memref.size = SIZE20 + SIZE10;
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = 0;
    ret = TEEC_InvokeCommand(&sess.session, GET_COMM_CMDID(TEE_TEST_ALLTYPE), &operation, &origin);
    free(testData0);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ((char *)testMem.sharedMem.buffer + OFFSET100, g_teeOutput);
    ASSERT_EQ(operation.params[1].memref.size, g_teeOutputLen);
    ASSERT_STREQ((char *)testMem.sharedMem.buffer, g_teeOutput);
    ASSERT_EQ(operation.params[0].memref.size, 0);
}

static void SetOperationParams(TEEC_Operation *operation, ClientShareMemMgr *testMem)
{
    operation->params[0].memref.parent = &testMem->sharedMem;
    operation->params[0].memref.offset = 0;
    operation->params[0].memref.size = SIZE10;
    operation->params[1].memref.parent = &testMem->sharedMem;
    operation->params[1].memref.offset = OFFSET100;
    operation->params[1].memref.size = SIZE20 + SIZE10;
    operation->params[2].memref.parent = &testMem->sharedMem;
    operation->params[2].memref.offset = OFFSET200;
    operation->params[2].memref.size = SIZE20 + SIZE10;
    operation->params[3].memref.parent = &testMem->sharedMem;
    operation->params[3].memref.offset = OFFSET300;
    operation->params[3].memref.size = SIZE20;
    return;
}

/**
 * @testcase.name      : RegisterSharedMemory_WithFlagOutput_UseParamTypesWhole
 * @testcase.desc      : test for allocatedshared with some params ree size less tee write size, use output types
 * @testcase.expect    : return TEEC_ERROR_SHORT_BUFFER
 */
TEE_TEST(EmptyTest, RegisterSharedMemory_ReturnLenUseTypesOutput, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    g_teeOutputLen = strlen(g_teeOutput) + 1;
    g_teeInoutLen = strlen(g_teeInout) + 1;
    char *testData0 = (char *)malloc(TEST_SIZE512);
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_SIZE512, 0x0, TEST_SIZE512);

    /* *allocate shared memory* */
    ClientShareMemMgr testMem;
    testMem.sharedMem.size = TEST_SIZE512;
    testMem.sharedMem.flags = TEEC_MEM_INOUT;
    testMem.sharedMem.buffer = testData0;
    ret = TEEC_RegisterSharedMemory(&sess.context, &testMem.sharedMem);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, testMem.sharedMem.size, 0x0, testMem.sharedMem.size);
    /* for test , [0] size < tee size, [1] size > tee size, [2] size > tee size, [3] size < tee size */
    rc = strcpy_s((char*)testMem.sharedMem.buffer, testMem.sharedMem.size, g_offset0);
    EXPECT_EQ(rc, 0);
    rc = strcpy_s((char*)testMem.sharedMem.buffer + OFFSET100, testMem.sharedMem.size - OFFSET100, g_offset100);
    EXPECT_EQ(rc, 0);
    rc = strcpy_s((char*)testMem.sharedMem.buffer + OFFSET200, testMem.sharedMem.size - OFFSET200, g_offset200);
    EXPECT_EQ(rc, 0);
    rc = strcpy_s((char*)testMem.sharedMem.buffer + OFFSET300, testMem.sharedMem.size - OFFSET300, g_offset300);
    EXPECT_EQ(rc, 0);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_MEMREF_PARTIAL_OUTPUT,
        TEEC_MEMREF_PARTIAL_INOUT, TEEC_MEMREF_PARTIAL_INOUT);
    SetOperationParams(&operation, &testMem);

    ret = TEEC_InvokeCommand(&sess.session, GET_COMM_CMDID(TEE_TEST_ALLTYPE), &operation, &origin);
    free(testData0);
    ASSERT_EQ(ret, TEEC_ERROR_SHORT_BUFFER);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(operation.params[0].memref.size, g_teeOutputLen);
    ASSERT_EQ(operation.params[1].memref.size, g_teeOutputLen);
    ASSERT_EQ(operation.params[2].memref.size, g_teeInoutLen);
    ASSERT_EQ(operation.params[3].memref.size, g_teeInoutLen);
    ASSERT_STREQ((char *)testMem.sharedMem.buffer, g_offset0);
    ASSERT_STREQ((char *)testMem.sharedMem.buffer + OFFSET100, g_teeOutput);
    ASSERT_STREQ((char *)testMem.sharedMem.buffer + OFFSET200, g_teeInout);
    ASSERT_STREQ((char *)testMem.sharedMem.buffer + OFFSET300, g_offset300);
}

/**
 * @testcase.name      : RegisterSharedMemory_OffsetExceedTest1
 * @testcase.desc      : test for memref.offset + memref.size > sharedMem.size
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(EmptyTest, RegisterSharedMemory_OffsetExceedTest1, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    g_teeOutputLen = strlen(g_teeOutput) + 1;
    char *testData0 = (char *)malloc(TEST_SIZE512);
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_SIZE512, 0x0, TEST_SIZE512);

    /* *allocate shared memory* */
    ClientShareMemMgr testMem;
    testMem.sharedMem.size = TEST_SIZE512;
    testMem.sharedMem.flags = TEEC_MEM_INOUT;
    testMem.sharedMem.buffer = testData0;
    ret = TEEC_RegisterSharedMemory(&sess.context, &testMem.sharedMem);
    EXPECT_EQ(ret, TEEC_SUCCESS);
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
    operation.params[1].memref.size = SIZE20;
    operation.params[2].memref.parent = &testMem.sharedMem;
    operation.params[2].memref.offset = OFFSET200;
    operation.params[2].memref.size = SIZE20;
    operation.params[3].memref.parent = &testMem.sharedMem;
    operation.params[3].memref.offset = TEST_SIZE512 - SIZE10 + 1;
    operation.params[3].memref.size = SIZE10;
    ret = TEEC_InvokeCommand(&sess.session, GET_COMM_CMDID(TEE_TEST_ALLTYPE), &operation, &origin);
    free(testData0);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : RegisterSharedMemory_OffsetExceedTest2
 * @testcase.desc      : test for memref.offset > sharedMem.size
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(EmptyTest, RegisterSharedMemory_OffsetExceedTest2, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    g_teeOutputLen = strlen(g_teeOutput) + 1;
    char *testData0 = (char *)malloc(TEST_SIZE512);
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_SIZE512, 0x0, TEST_SIZE512);

    /* *allocate shared memory* */
    ClientShareMemMgr testMem;
    testMem.sharedMem.flags = TEEC_MEM_INOUT;
    testMem.sharedMem.size = TEST_SIZE512;
    testMem.sharedMem.buffer = testData0;
    ret = TEEC_RegisterSharedMemory(&sess.context, &testMem.sharedMem);
    EXPECT_EQ(ret, TEEC_SUCCESS);
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
    operation.params[1].memref.size = SIZE20;
    operation.params[2].memref.parent = &testMem.sharedMem;
    operation.params[2].memref.offset = OFFSET200;
    operation.params[2].memref.size = SIZE20;
    operation.params[3].memref.parent = &testMem.sharedMem;
    operation.params[3].memref.offset = TEST_SIZE512 + 1;
    operation.params[3].memref.size = SIZE10;
    ret = TEEC_InvokeCommand(&sess.session, GET_COMM_CMDID(TEE_TEST_ALLTYPE), &operation, &origin);
    free(testData0);
    operation.params[3].memref.size = SIZE10;
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}