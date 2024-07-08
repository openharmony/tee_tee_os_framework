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

#include <common_test.h>
#include <empty_test.h>
#include <iostream>
#include <pthread.h>

#include <public_test.h>
#include <securec.h>
#include <session_mgr/client_session_mgr.h>
#include <string>
#include <tee_client_api.h>
#include <tee_client_type.h>
#include <test_comm_cmdid.h>
#include <test_defines.h>
#include <test_log.h>

using namespace std;
using namespace testing::ext;

// The test case uses the same string to pass the input and output test of buffer during REE and tee communication
static char g_teeOutput[] = "TEEMEM_OUTPUT";
static char g_teeInout[] = "the param is TEEMEM_INOUT";
static uint32_t g_teeOutputLen;
static uint32_t g_teeInoutLen;
static string g_testString = "11223344556677889900qwertyuiop";
char g_testData0[TEST_STR_LEN] = "Hello";
char g_testData1[TEST_STR_LEN] = "abcdefgh";
char g_testData2[TEST_STR_LEN] = "qwertyuiop";
char g_testData3[TEST_STR_LEN] = "this is test string";

static char g_offset0[] = "11223344556677889900";
static char g_offset100[] = "offset is 100";
static char g_offset200[] = "offset is 200";
static char g_offset300[] = "offset is 300";

#define SIZE_4K (4 * 1024)
#define SIZE_1024K (1024 * 1024)
#define SIZE_2048K (2048 * 1024)

/**
 * @testcase.name      : InvokeCommand_WithSessionNotOpen
 * @testcase.desc      : call TEEC_InvokeCommand With session is not open
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithSessionNotOpen, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    TEEC_CloseSession(&sess.session);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].value.a = 0xaaa;
    operation.params[0].value.b = 0xbbb;

    ret = TEEC_InvokeCommand(&sess.session, 0, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : InvokeCommand_WithSessionIsClose
 * @testcase.desc      : call TEEC_InvokeCommand With session is closed
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithSessionIsClose, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    TEEC_CloseSession(&sess.session);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].value.a = 0xaaa;
    operation.params[0].value.b = 0xbbb;

    ret = TEEC_InvokeCommand(&sess.session, 0, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : InvokeCommand_WithoutOperation
 * @testcase.desc      : call TEEC_InvokeCommand Without operation
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithoutOperation, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, 0, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : InvokeCommand_WithoutOrigin
 * @testcase.desc      : call TEEC_InvokeCommand Without Origin
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithoutOrigin, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    ret = TEEC_InvokeCommand(&sess.session, 0, &operation, NULL);
    ASSERT_EQ(ret, TEEC_SUCCESS);
}

/**
 * @testcase.name      : InvokeCommand_WithoutSession
 * @testcase.desc      : call TEEC_InvokeCommand Without session
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithoutSession, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    ret = TEEC_InvokeCommand(NULL, 0, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : InvokeCommand_WithOperationIsValue
 * @testcase.desc      : call TEEC_InvokeCommand With paramtype is value
 * @testcase.expect    : return TEEC_SUCCESS, TA can modify input value and return to CA
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithOperationIsValue, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT, TEEC_VALUE_INOUT, TEEC_VALUE_INOUT);
    operation.params[0].value.a = 0x111;
    operation.params[0].value.b = 0x222;
    operation.params[1].value.a = 0x333;
    operation.params[1].value.b = 0x444;
    operation.params[2].value.a = 0x555;
    operation.params[2].value.b = 0x666;
    operation.params[3].value.a = 0x777;
    operation.params[3].value.b = 0x888;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_VALUE, &operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(operation.params[0].value.a, 0x111);
    ASSERT_EQ(operation.params[0].value.b, 0x222);
    ASSERT_EQ(operation.params[1].value.a, 0x333 + 1);
    ASSERT_EQ(operation.params[1].value.b, 0x444 + 1);
    ASSERT_EQ(operation.params[2].value.a, 0x555 - 1);
    ASSERT_EQ(operation.params[2].value.b, 0x666 - 1);
    ASSERT_EQ(operation.params[3].value.a, 0x777 - 1);
    ASSERT_EQ(operation.params[3].value.b, 0x888 - 1);
}

/**
 * @testcase.name      : InvokeCommand_WithOperationIsTempMem
 * @testcase.desc      : call TEEC_InvokeCommand With paramtype is TempMem
 * @testcase.expect    : return TEEC_SUCCESS, TA can modify input tempmem and return to CA
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithOperationIsTempMem, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_Operation operation = { 0 };
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    g_teeOutputLen = strlen(g_teeOutput) + 1;
    g_teeInoutLen = strlen(g_teeInout) + 1;

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_INOUT,
        TEEC_MEMREF_TEMP_INOUT);
    operation.params[0].tmpref.buffer = g_testData0;
    operation.params[0].tmpref.size = TEST_STR_LEN;
    operation.params[1].tmpref.buffer = g_testData1;
    operation.params[1].tmpref.size = TEST_STR_LEN;
    operation.params[2].tmpref.buffer = g_testData2;
    operation.params[2].tmpref.size = TEST_STR_LEN;
    operation.params[3].tmpref.buffer = g_testData3;
    operation.params[3].tmpref.size = TEST_STR_LEN;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_BUFFER, &operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(reinterpret_cast<char *>(operation.params[0].tmpref.buffer), g_testData0);
    ASSERT_EQ(operation.params[0].tmpref.size, TEST_STR_LEN);
    ASSERT_STREQ(reinterpret_cast<char *>(operation.params[1].tmpref.buffer), g_teeOutput);
    ASSERT_EQ(operation.params[1].tmpref.size, g_teeOutputLen);
    ASSERT_STREQ(reinterpret_cast<char *>(operation.params[2].tmpref.buffer), g_teeInout);
    ASSERT_EQ(operation.params[2].tmpref.size, g_teeInoutLen);
    ASSERT_STREQ(reinterpret_cast<char *>(operation.params[3].tmpref.buffer), g_teeInout);
    ASSERT_EQ(operation.params[3].tmpref.size, g_teeInoutLen);
}

static void MemSharedFreeShmem(TEEC_SharedMemory *shmems, uint32_t count)
{
    if (count == 0) {
        TEST_PRINT_ERROR("input for free count is wrong!\n");
        return;
    }

    for (uint32_t idx = 0; idx < count; idx++) {
        TEEC_ReleaseSharedMemory(shmems + idx);
    }
}

static TEEC_Result MemSharedAllocShmem(TEEC_Context *context, TEEC_SharedMemory *shmems, uint32_t count, uint32_t size,
    uint32_t flag)
{
    TEEC_Result result;
    if (count == 0) {
        TEST_PRINT_ERROR("input for free count is wrong!\n");
        return TEEC_ERROR_GENERIC;
    }

    for (uint32_t id = 0; id < count; id++) {
        shmems[id].flags = flag;
        shmems[id].size = size;
        result = TEEC_AllocateSharedMemory(context, shmems + id);
        if (result != TEEC_SUCCESS) {
            TEST_PRINT_ERROR("%dth TEEC_AllocateSharedMemory size 0x%x fail,ret=0x%x\n", id + 1, size, result);
            MemSharedFreeShmem(shmems, id);
            return TEEC_FAIL;
        }
        (void)memset_s(shmems[id].buffer, shmems[id].size, 0x0, shmems[id].size);
    }

    return TEEC_SUCCESS;
}

/**
 * @testcase.name      : InvokeCommand_WithOperationIsPartialMem
 * @testcase.desc      : call TEEC_InvokeCommand With paramtype is PartialMem
 * @testcase.expect    : return TEEC_SUCCESS, TA can modify input PartialMem and return to CA
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithOperationIsPartialMem, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    int rc;
    TEEC_Operation operation = { 0 };

    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    TEEC_SharedMemory sharedMem[PARAM_COUNT] = { { 0 } };
    // test malloc mem
    ret = MemSharedAllocShmem(&sess.context, sharedMem, PARAM_COUNT, TEST_STR_LEN, TEEC_MEM_INOUT);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    g_teeOutputLen = strlen(g_teeOutput) + 1;
    g_teeInoutLen = strlen(g_teeInout) + 1;
    rc = memcpy_s(sharedMem[0].buffer, TEST_STR_LEN, g_testData0, TEST_STR_LEN);
    ASSERT_EQ(rc, 0);
    rc = memcpy_s(sharedMem[1].buffer, TEST_STR_LEN, g_testData1, TEST_STR_LEN);
    ASSERT_EQ(rc, 0);
    rc = memcpy_s(sharedMem[2].buffer, TEST_STR_LEN, g_testData2, TEST_STR_LEN);
    ASSERT_EQ(rc, 0);
    rc = memcpy_s(sharedMem[3].buffer, TEST_STR_LEN, g_testData3, TEST_STR_LEN);
    ASSERT_EQ(rc, 0);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT,
        TEEC_MEMREF_PARTIAL_INOUT, TEEC_MEMREF_PARTIAL_INOUT);
    operation.params[0].memref.parent = &sharedMem[0];
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = sharedMem[0].size;
    operation.params[1].memref.parent = &sharedMem[1];
    operation.params[1].memref.offset = 0;
    operation.params[1].memref.size = sharedMem[1].size;
    operation.params[2].memref.parent = &sharedMem[2];
    operation.params[2].memref.offset = 0;
    operation.params[2].memref.size = sharedMem[2].size;
    operation.params[3].memref.parent = &sharedMem[3];
    operation.params[3].memref.offset = 0;
    operation.params[3].memref.size = sharedMem[3].size;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_BUFFER, &operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(reinterpret_cast<char *>(sharedMem[0].buffer), g_testData0);
    ASSERT_EQ(operation.params[0].memref.size, TEST_STR_LEN);
    ASSERT_STREQ(reinterpret_cast<char *>(sharedMem[1].buffer), g_teeOutput);
    ASSERT_EQ(operation.params[1].memref.size, g_teeOutputLen);
    ASSERT_STREQ(reinterpret_cast<char *>(sharedMem[2].buffer), g_teeInout);
    ASSERT_EQ(operation.params[2].memref.size, g_teeInoutLen);
    ASSERT_STREQ(reinterpret_cast<char *>(sharedMem[3].buffer), g_teeInout);
    ASSERT_EQ(operation.params[3].memref.size, g_teeInoutLen);
}

/**
 * @testcase.name      : InvokeCommand_WithOperationIsTempMemIsNULL
 * @testcase.desc      : call TEEC_InvokeCommand With tempMem is null
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithOperationIsTempMemIsNULL, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_Operation operation = { 0 };
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_MEMREF_TEMP_INOUT, TEEC_NONE, TEEC_NONE);
    operation.params[1].tmpref.buffer = NULL;
    operation.params[1].tmpref.size = TEST_STR_LEN;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_BUFFER, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : InvokeCommand_WithOperationNotStart
 * @testcase.desc      : call TEEC_InvokeCommand With Operation is Not Start
 * @testcase.expect    : return TEEC_ERROR_NOT_IMPLEMENTED
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithOperationNotStart, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_Operation operation = { 0 };
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_MEMREF_TEMP_INOUT, TEEC_NONE, TEEC_NONE);
    operation.params[1].tmpref.buffer = g_testData0;
    operation.params[1].tmpref.size = TEST_STR_LEN;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_BUFFER, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_NOT_IMPLEMENTED);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : InvokeCommand_WithOperationTypeTempUsePartial
 * @testcase.desc      : call TEEC_InvokeCommand With ParamType is temp while operation is memref
 * @testcase.expect    : return TEEC_ERROR_COMMUNICATION
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithOperationTypeTempUsePartial, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_Operation operation = { 0 };
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ClientShareMemMgr testMem;
    testMem.sharedMem.size = TEST_STR_LEN;
    testMem.sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = testMem.sharedMem.size;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_BUFFER, &operation, &origin);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_ERROR_COMMUNICATION);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : InvokeCommand_WithOperationTypePartialUseTemp
 * @testcase.desc      : call TEEC_InvokeCommand With ParamType is partial while operation is tmpref
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithOperationTypePartialUseTemp, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_Operation operation = { 0 };
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].tmpref.buffer = g_testData0;
    operation.params[0].tmpref.size = TEST_STR_LEN;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_BUFFER, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : InvokeCommand_WithOperationTypePartialIsNULL
 * @testcase.desc      : call TEEC_InvokeCommand With ParamType is partial while memref.buffer is assign
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithOperationTypePartialIsNULL, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_Operation operation = { 0 };
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = TEST_STR_LEN;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_BUFFER, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : InvokeCommand_WithOperationTypePartialSizeIsExceed
 * @testcase.desc      : call TEEC_InvokeCommand With ParamType is partial while memref offset+size > sharedMem.size
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithOperationTypePartialSizeIsExceed, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_Operation operation = { 0 };
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ClientShareMemMgr testMem;
    testMem.sharedMem.size = TEST_STR_LEN;
    testMem.sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = 1;
    operation.params[0].memref.size = testMem.sharedMem.size;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_BUFFER, &operation, &origin);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : InvokeCommand_WithOperationTypePartialSizeIsZero
 * @testcase.desc      : call TEEC_InvokeCommand With ParamType is partial while memref.size = 0
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithOperationTypePartialSizeIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_Operation operation = { 0 };
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ClientShareMemMgr testMem;
    testMem.sharedMem.size = TEST_STR_LEN;
    testMem.sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = 0;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_BUFFER, &operation, &origin);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_COMMS);
}

/**
 * @testcase.name      : InvokeCommand_WithMemrefPartialBufferIsWrong
 * @testcase.desc      : call TEEC_InvokeCommand With ParamType is partial while sharedMem.buffer is not use
 * TEEC_AllocateSharedMemory allocated
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithMemrefPartialBufferIsWrong, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientShareMemMgr testMem;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    char *testData0 = reinterpret_cast<char *>(malloc(TEST_STR_LEN));
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_STR_LEN, 0x0, TEST_STR_LEN);

    /* *allocate shared memory* */
    testMem.sharedMem.flags = TEEC_MEM_INOUT;
    testMem.sharedMem.size = TEST_STR_LEN;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    testMem.sharedMem.buffer = testData0;

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE, TEEC_NONE);
    operation.params[1].memref.parent = &testMem.sharedMem;
    operation.params[1].memref.offset = 0;
    operation.params[1].memref.size = TEST_STR_LEN;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    free(testData0);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : InvokeCommand_WithContextIsAlreadyFinalize
 * @testcase.desc      : call TEEC_InvokeCommand With Context is already Finalized
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithContextIsAlreadyFinalize, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_Operation operation = { 0 };
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_MEMREF_TEMP_INOUT, TEEC_NONE, TEEC_NONE);
    operation.params[1].tmpref.buffer = g_testData0;
    operation.params[1].tmpref.size = TEST_STR_LEN;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_BUFFER, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : InvokeCommand_WithOperationAllType
 * @testcase.desc      : call TEEC_InvokeCommand With paramType is all kind of type
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithOperationAllType, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    uint32_t origin;
    TEEC_Operation operation = { 0 };
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    g_teeInoutLen = strlen(g_teeInout) + 1;
    ClientShareMemMgr testMem;
    ClientShareMemMgr nonZeroCopysharedMem;
    /* *allocate shared memory* */
    testMem.sharedMem.size = TEST_STR_LEN;
    testMem.sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, TEST_STR_LEN, 0x0, TEST_STR_LEN);
    rc = strcpy_s(reinterpret_cast<char *>(testMem.sharedMem.buffer), testMem.sharedMem.size, g_testData2);
    ASSERT_EQ(rc, 0);

    /* *register shared memory* */
    nonZeroCopysharedMem.sharedMem.buffer = g_testData1;
    nonZeroCopysharedMem.sharedMem.size = TEST_STR_LEN;
    nonZeroCopysharedMem.sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_RegisterSharedMemory(&sess.context, &nonZeroCopysharedMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    operation.started = 1;
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_MEMREF_WHOLE, TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT);
    operation.params[0].memref.parent = &nonZeroCopysharedMem.sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = nonZeroCopysharedMem.sharedMem.size;
    operation.params[1].memref.parent = &testMem.sharedMem;
    operation.params[1].memref.offset = 0;
    operation.params[1].memref.size = 0;
    operation.params[2].tmpref.buffer = g_testData0;
    operation.params[2].tmpref.size = TEST_STR_LEN;
    operation.params[3].value.a = 0x123;
    operation.params[3].value.b = 0x987;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(reinterpret_cast<char *>(nonZeroCopysharedMem.sharedMem.buffer), g_teeInout);
    ASSERT_EQ(operation.params[0].memref.size, g_teeInoutLen);
    ASSERT_STREQ(reinterpret_cast<char *>(testMem.sharedMem.buffer), g_teeInout);
    ASSERT_EQ(operation.params[1].memref.size, 0);
    ASSERT_STREQ(reinterpret_cast<char *>(operation.params[2].tmpref.buffer), g_teeInout);
    ASSERT_EQ(operation.params[2].tmpref.size, g_teeInoutLen);
    ASSERT_EQ(operation.params[3].value.a, 0x123 - 1);
    ASSERT_EQ(operation.params[3].value.b, 0x987 - 1);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
}

/**
 * @testcase.name      : InvokeCommand_WithMemrefTempInput1024k
 * @testcase.desc      : call TEEC_InvokeCommand With paramType is TEMP_INPUT and size is 1024k
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithMemrefTempInput1024k, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    uint32_t origin;
    TEEC_Operation operation = { 0 };
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    char *testData0 = reinterpret_cast<char *>(malloc(SIZE_1024K));
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, SIZE_1024K, 0x0, SIZE_1024K);
    rc = memcpy_s(testData0, SIZE_1024K, g_testString.c_str(), g_testString.length());
    ASSERT_EQ(rc, 0);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
    operation.params[1].tmpref.buffer = testData0;
    operation.params[1].tmpref.size = SIZE_1024K;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_STREQ(reinterpret_cast<char *>(operation.params[1].tmpref.buffer), testData0);
    EXPECT_EQ(operation.params[1].tmpref.size, SIZE_1024K);
    free(testData0);
}

/**
 * @testcase.name      : InvokeCommand_WithMemrefTempOutput1024k
 * @testcase.desc      : call TEEC_InvokeCommand With paramType is TEMP_OUTPUT and size is 1024k
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithMemrefTempOutput1024k, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    g_teeOutputLen = strlen(g_teeOutput) + 1;
    char *testData0 = reinterpret_cast<char *>(malloc(SIZE_1024K));
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, SIZE_1024K, 0x0, SIZE_1024K);
    rc = memcpy_s(testData0, SIZE_1024K, g_testString.c_str(), g_testString.length());
    ASSERT_EQ(rc, 0);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
    operation.params[1].tmpref.buffer = testData0;
    operation.params[1].tmpref.size = SIZE_1024K;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_STREQ(reinterpret_cast<char *>(operation.params[1].tmpref.buffer), g_teeOutput);
    EXPECT_EQ(operation.params[1].tmpref.size, g_teeOutputLen);
    free(testData0);
}

/**
 * @testcase.name      : InvokeCommand_WithMemrefTempInout1024k
 * @testcase.desc      : call TEEC_InvokeCommand With paramType is TEMP_INOUT and size is 1024k
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithMemrefTempInout1024k, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    int rc;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    g_teeInoutLen = strlen(g_teeInout) + 1;
    char *testData0 = reinterpret_cast<char *>(malloc(SIZE_1024K));
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, SIZE_1024K, 0x0, SIZE_1024K);
    rc = memcpy_s(testData0, SIZE_1024K, g_testString.c_str(), g_testString.length());
    ASSERT_EQ(rc, 0);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_MEMREF_TEMP_INOUT, TEEC_NONE, TEEC_NONE);
    operation.params[1].tmpref.buffer = testData0;
    operation.params[1].tmpref.size = SIZE_1024K;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_STREQ(reinterpret_cast<char *>(operation.params[1].tmpref.buffer), g_teeInout);
    EXPECT_EQ(operation.params[1].tmpref.size, g_teeInoutLen);
    free(testData0);
}

/**
 * @testcase.name      : InvokeCommand_WithMemrefTempInoutExceed1024k
 * @testcase.desc      : call TEEC_InvokeCommand With paramType is TEMP_INOUT and size is 1024k + 1
 * @testcase.expect    : return TEEC_ERROR_ACCESS_DENIED
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithMemrefTempInoutExceed1024k, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    char *testData0 = reinterpret_cast<char *>(malloc(SIZE_1024K + 1));
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, SIZE_1024K + 1, 0x0, SIZE_1024K + 1);
    rc = memcpy_s(testData0, SIZE_1024K + 1, g_testString.c_str(), g_testString.length());
    ASSERT_EQ(rc, 0);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_MEMREF_TEMP_INOUT, TEEC_NONE, TEEC_NONE);
    operation.params[1].tmpref.buffer = testData0;
    operation.params[1].tmpref.size = SIZE_1024K + 1;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    free(testData0);
    ASSERT_EQ(ret, TEEC_ERROR_ACCESS_DENIED);
    ASSERT_EQ(origin, TEEC_ORIGIN_COMMS);
}

/**
 * @testcase.name      : InvokeCommand_WithMemrefWhole2048k
 * @testcase.desc      : call TEEC_InvokeCommand With paramType is WHOLE and size is 2048k
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithMemrefWhole2048k, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    /* *allocate shared memory* */
    ClientShareMemMgr testMem;
    testMem.sharedMem.size = SIZE_2048K;
    testMem.sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, SIZE_2048K, 0x0, SIZE_2048K);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE);
    operation.params[1].memref.parent = &testMem.sharedMem;
    operation.params[1].memref.offset = 0;
    operation.params[1].memref.size = testMem.sharedMem.size;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : InvokeCommand_WithMemrefWholeExceed2048k
 * @testcase.desc      : call TEEC_InvokeCommand With paramType is WHOLE and sharedMem.size is 2048k + 1
 * @testcase.expect    : return TEEC_ERROR_OUT_OF_MEMORY
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithMemrefWholeExceed2048k, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    /* *allocate shared memory* */
    ClientShareMemMgr testMem;
    testMem.sharedMem.size = SIZE_2048K + 1;
    testMem.sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, SIZE_2048K + 1, 0x0, SIZE_2048K + 1);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE);
    operation.params[1].memref.parent = &testMem.sharedMem;
    operation.params[1].memref.offset = 0;
    operation.params[1].memref.size = testMem.sharedMem.size;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_ERROR_OUT_OF_MEMORY);
    ASSERT_EQ(origin, TEEC_ORIGIN_COMMS);
}

/**
 * @testcase.name      : InvokeCommand_WithMemrefPartialInput2048k
 * @testcase.desc      : call TEEC_InvokeCommand With paramType is PARTIAL_INPUT and size is 2048k
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithMemrefPartialInput2048k, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    uint32_t origin;
    TEEC_Operation operation = { 0 };
    ClientShareMemMgr testMem;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    /* *allocate shared memory* */
    testMem.sharedMem.size = SIZE_2048K;
    testMem.sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, SIZE_2048K, 0x0, SIZE_2048K);
    rc = memcpy_s(testMem.sharedMem.buffer, SIZE_2048K, g_testString.c_str(), g_testString.length());
    ASSERT_EQ(rc, 0);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE, TEEC_NONE);
    operation.params[1].memref.parent = &testMem.sharedMem;
    operation.params[1].memref.offset = 0;
    operation.params[1].memref.size = testMem.sharedMem.size;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_STREQ(reinterpret_cast<char *>(testMem.sharedMem.buffer), g_testString.c_str());
    EXPECT_EQ(operation.params[1].memref.size, SIZE_2048K);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
}

/**
 * @testcase.name      : InvokeCommand_WithMemrefPartialOutput2048k
 * @testcase.desc      : call TEEC_InvokeCommand With paramType is PARTIAL_OUTPUT and size is 2048k
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithMemrefPartialOutput2048k, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    uint32_t origin;
    ClientShareMemMgr testMem;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    /* *allocate shared memory* */
    testMem.sharedMem.size = SIZE_2048K;
    testMem.sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, SIZE_2048K, 0x0, SIZE_2048K);
    rc = memcpy_s(testMem.sharedMem.buffer, SIZE_2048K, g_testString.c_str(), g_testString.length());
    ASSERT_EQ(rc, 0);

    g_teeOutputLen = strlen(g_teeOutput) + 1;
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE, TEEC_NONE);
    operation.params[1].memref.parent = &testMem.sharedMem;
    operation.params[1].memref.offset = 0;
    operation.params[1].memref.size = testMem.sharedMem.size;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_STREQ(reinterpret_cast<char *>(testMem.sharedMem.buffer), g_teeOutput);
    EXPECT_EQ(operation.params[1].memref.size, g_teeOutputLen);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
}

/**
 * @testcase.name      : InvokeCommand_WithMemrefPartialInout2048k
 * @testcase.desc      : call TEEC_InvokeCommand With paramType is PARTIAL_INOUT and size is 2048k
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithMemrefPartialInout2048k, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    uint32_t origin;
    ClientShareMemMgr testMem;
    TEEC_Operation operation = { 0 };
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    /* *allocate shared memory* */
    g_teeInoutLen = strlen(g_teeInout) + 1;
    testMem.sharedMem.size = SIZE_2048K;
    testMem.sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, SIZE_2048K, 0x0, SIZE_2048K);
    rc = memcpy_s(testMem.sharedMem.buffer, SIZE_2048K, g_testString.c_str(), g_testString.length());
    ASSERT_EQ(rc, 0);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE);
    operation.params[1].memref.parent = &testMem.sharedMem;
    operation.params[1].memref.offset = 0;
    operation.params[1].memref.size = testMem.sharedMem.size;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_STREQ(reinterpret_cast<char *>(testMem.sharedMem.buffer), g_teeInout);
    EXPECT_EQ(operation.params[1].memref.size, g_teeInoutLen);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
}

/**
 * @testcase.name      : InvokeCommand_WithMemrefPartialInoutExceed2048k
 * @testcase.desc      : call TEEC_InvokeCommand With paramType is PARTIAL_INOUT and size is 2048k + 1
 * @testcase.expect    : return TEEC_ERROR_OUT_OF_MEMORY
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_WithMemrefPartialInoutExceed2048k, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    uint32_t origin;
    TEEC_Operation operation = { 0 };
    ClientShareMemMgr testMem;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    /* *allocate shared memory* */
    g_teeInoutLen = strlen(g_teeInout) + 1;
    testMem.sharedMem.size = SIZE_2048K + 1;
    testMem.sharedMem.flags = TEEC_MEM_INOUT;
    ret = TEEC_AllocateSharedMemory(&sess.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    (void)memset_s(testMem.sharedMem.buffer, SIZE_2048K + 1, 0x0, SIZE_2048K + 1);
    rc = memcpy_s(testMem.sharedMem.buffer, SIZE_2048K + 1, g_testString.c_str(), g_testString.length());
    ASSERT_EQ(rc, 0);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE);
    operation.params[1].memref.parent = &testMem.sharedMem;
    operation.params[1].memref.offset = 0;
    operation.params[1].memref.size = testMem.sharedMem.size;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    EXPECT_EQ(ret, TEEC_ERROR_OUT_OF_MEMORY);
    EXPECT_EQ(origin, TEEC_ORIGIN_COMMS);
    EXPECT_STREQ(reinterpret_cast<char *>(testMem.sharedMem.buffer), g_testString.c_str());
    EXPECT_EQ(operation.params[1].memref.size, testMem.sharedMem.size);
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
}

/**
 * @testcase.name      : InvokeCommand_ReturnLenWithMemrefTempOutput
 * @testcase.desc      : for test TEEC_MEMREF_TEMP_OUTPUT, [0] size < tee size, [1] size < tee size,
 * [2] size > tee size, [3] size > tee size
 * @testcase.expect    : return TEEC_ERROR_SHORT_BUFFER
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_ReturnLenWithMemrefTempOutput, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    g_teeOutputLen = strlen(g_teeOutput) + 1;

    char *testData0 = reinterpret_cast<char *>(malloc(TEST_SIZE512));
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_SIZE512, 0x0, TEST_SIZE512);
    rc = strcpy_s(testData0, TEST_SIZE512, g_offset0);
    ASSERT_EQ(rc, 0);
    rc = strcpy_s(testData0 + OFFSET100, TEST_SIZE512 - OFFSET100, g_offset100);
    ASSERT_EQ(rc, 0);
    rc = strcpy_s(testData0 + OFFSET200, TEST_SIZE512 - OFFSET200, g_offset200);
    ASSERT_EQ(rc, 0);
    rc = strcpy_s(testData0 + OFFSET300, TEST_SIZE512 - OFFSET300, g_offset300);
    ASSERT_EQ(rc, 0);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_MEMREF_TEMP_OUTPUT);
    operation.params[0].tmpref.buffer = testData0;
    operation.params[0].tmpref.size = SIZE10;
    operation.params[1].tmpref.buffer = testData0 + OFFSET100;
    operation.params[1].tmpref.size = SIZE10;
    operation.params[2].tmpref.buffer = testData0 + OFFSET200;
    operation.params[2].tmpref.size = SIZE20;
    operation.params[3].tmpref.buffer = testData0 + OFFSET300;
    operation.params[3].tmpref.size = SIZE20;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    EXPECT_EQ(ret, TEEC_ERROR_SHORT_BUFFER);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_EQ(operation.params[0].tmpref.size, g_teeOutputLen);
    EXPECT_EQ(operation.params[1].tmpref.size, g_teeOutputLen);
    EXPECT_EQ(operation.params[2].tmpref.size, g_teeOutputLen);
    EXPECT_EQ(operation.params[3].tmpref.size, g_teeOutputLen);
    EXPECT_STREQ(testData0, g_offset0);
    EXPECT_STREQ(testData0 + OFFSET100, g_offset100);
    EXPECT_STREQ(testData0 + OFFSET200, g_teeOutput);
    EXPECT_STREQ(testData0 + OFFSET300, g_teeOutput);
    free(testData0);
}

/**
 * @testcase.name      : InvokeCommand_ReturnLenWithMemrefTempOutput
 * @testcase.desc      : for test TEEC_MEMREF_TEMP_INOUT, [0] size > tee size, [1] size < tee size,
 * [2] size < tee size [3] size < tee size
 * @testcase.expect    : return TEEC_ERROR_SHORT_BUFFER
 */
TEE_TEST(TeeBasicTestFram, InvokeCommand_ReturnLenWithMemrefTempInout, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    g_teeInoutLen = strlen(g_teeInout) + 1;
    g_teeOutputLen = strlen(g_teeOutput) + 1;

    char *testData0 = reinterpret_cast<char *>(malloc(TEST_SIZE512));
    ASSERT_STRNE(testData0, NULL);
    (void)memset_s(testData0, TEST_SIZE512, 0x0, TEST_SIZE512);
    rc = strcpy_s(testData0, TEST_SIZE512, g_offset0);
    ASSERT_EQ(rc, 0);
    rc = strcpy_s(testData0 + OFFSET100, TEST_SIZE512 - OFFSET100, g_offset100);
    ASSERT_EQ(rc, 0);
    rc = strcpy_s(testData0 + OFFSET200, TEST_SIZE512 - OFFSET200, g_offset200);
    ASSERT_EQ(rc, 0);
    rc = strcpy_s(testData0 + OFFSET300, TEST_SIZE512 - OFFSET300, g_offset300);
    ASSERT_EQ(rc, 0);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_OUTPUT,
        TEEC_MEMREF_TEMP_OUTPUT);
    operation.params[0].tmpref.buffer = testData0;
    operation.params[0].tmpref.size = SIZE20 + SIZE10;
    operation.params[1].tmpref.buffer = testData0 + OFFSET100;
    operation.params[1].tmpref.size = SIZE20;
    operation.params[2].tmpref.buffer = testData0 + OFFSET200;
    operation.params[2].tmpref.size = SIZE10;
    operation.params[3].tmpref.buffer = testData0 + OFFSET300;
    operation.params[3].tmpref.size = SIZE10;

    ret = TEEC_InvokeCommand(&sess.session, TEE_TEST_ALLTYPE, &operation, &origin);
    EXPECT_EQ(ret, TEEC_ERROR_SHORT_BUFFER);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_EQ(operation.params[0].tmpref.size, g_teeInoutLen);
    EXPECT_EQ(operation.params[1].tmpref.size, g_teeInoutLen);
    EXPECT_EQ(operation.params[2].tmpref.size, g_teeOutputLen);
    EXPECT_EQ(operation.params[3].tmpref.size, g_teeOutputLen);
    EXPECT_STREQ(testData0, g_teeInout);
    EXPECT_STREQ(testData0 + OFFSET100, g_offset100);
    EXPECT_STREQ(testData0 + OFFSET200, g_offset200);
    EXPECT_STREQ(testData0 + OFFSET300, g_offset300);
    free(testData0);
}

static TEEC_Result CreateOpensession(TEEC_Operation *operation, TEEC_Session *session, TEEC_Context *context,
    uint32_t id)
{
    uint32_t origin;
    TEEC_UUID uuid = CLIENTAPI_UUID_1;
    operation->started = 1;
    operation->paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    char str[64] = { 0 };
    sprintf(str,"/data/local/tmp/%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x.sec", uuid.timeLow, uuid.timeMid,
        uuid.timeHiAndVersion, uuid.clockSeqAndNode[0], uuid.clockSeqAndNode[1], uuid.clockSeqAndNode[2],
        uuid.clockSeqAndNode[3], uuid.clockSeqAndNode[4], uuid.clockSeqAndNode[5], uuid.clockSeqAndNode[6],
        uuid.clockSeqAndNode[7]);
    context->ta_path = (uint8_t *)str;
    TEEC_Result result = TEEC_OpenSession(context, session, &uuid, TEEC_LOGIN_IDENTIFY, NULL, operation, &origin);
    if (result != TEEC_SUCCESS)
        TEST_PRINT_ERROR("thread %d: TEEC_OpenSession failed, result=0x%x, origin=%d\n", id, result, origin);

    return result;
}

static void SetOperationParams(TEEC_Operation *operation, TEEC_SharedMemory *sharedMem)
{
    operation->started = 1;
    operation->paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE);
    operation->params[0].value.a = 0x10;
    operation->params[0].value.b = 0x20;
    operation->params[1].memref.parent = sharedMem;
    operation->params[1].memref.offset = 0;
    operation->params[1].memref.size = TEST_STR_LEN;
    return;
}

/* each child thread test OpenSession, Invokecommand, Allocatesharemem */
static void *ThreadTestOpenInvokeAllocmem(void *inParams)
{
    TEEC_Context *context = ((DatePacket *)inParams)->context;
    TEEC_Operation operation = { 0 };
    TEEC_Session session = { 0 };
    TEEC_SharedMemory sharedMem = { 0 };
    uint32_t origin;
    uint32_t id = ((DatePacket *)inParams)->id;
    g_teeInoutLen = strlen(g_teeInout) + 1;

    TEEC_Result result = CreateOpensession(&operation, &session, context, id);
    if (result != TEEC_SUCCESS) {
        ((DatePacket *)inParams)->ret = result;
        return NULL;
    }
    sharedMem.size = TEST_STR_LEN;
    sharedMem.flags = TEEC_MEM_INOUT;
    result = TEEC_AllocateSharedMemory(context, &sharedMem);
    if (result != TEEC_SUCCESS) {
        TEST_PRINT_ERROR("thread %d: TEEC_AllocateSharedMemory failed, result=0x%x\n", id, result);
        ((DatePacket *)inParams)->ret = result;
        goto clean;
    }
    (void)memset_s(sharedMem.buffer, TEST_STR_LEN, 0x0, TEST_STR_LEN);

    SetOperationParams(&operation, &sharedMem);
    ((DatePacket *)inParams)->ret = TEEC_InvokeCommand(&session, TEE_TEST_ALLTYPE, &operation, &origin);
    if (((DatePacket *)inParams)->ret != TEEC_SUCCESS) {
        TEST_PRINT_ERROR("thread %d:Invoke failed,result=0x%x,origin=%d\n", id, ((DatePacket *)inParams)->ret, origin);
        goto clean1;
    }

    if ((operation.params[0].value.a != (0x10 - 1)) || (operation.params[0].value.b != (0x20 - 1))) {
        TEST_PRINT_ERROR("thread %d:Invoke value failed,value.a=0x%x,value.b=0x%x\n", id, operation.params[0].value.a,
            operation.params[0].value.b);
        ((DatePacket *)inParams)->ret = TEEC_ERROR_GENERIC;
    }
    if ((operation.params[1].memref.size != g_teeInoutLen) ||
        (strncmp(g_teeInout, reinterpret_cast<char *>(sharedMem.buffer), g_teeInoutLen) != 0)) {
        TEST_PRINT_ERROR("thread %d:Invoke buffer failed,memref.size=%d,sharedMem.buffer=%s\n", id,
            operation.params[1].memref.size, reinterpret_cast<char *>(sharedMem.buffer));
        ((DatePacket *)inParams)->ret = TEEC_ERROR_GENERIC;
    }

    TEEC_CloseSession(&session);
    TEEC_ReleaseSharedMemory(&sharedMem);
    return NULL;
clean1:
    TEEC_ReleaseSharedMemory(&sharedMem);
clean:
    TEEC_CloseSession(&session);
    return NULL;
}

/**
 * @testcase.name      : InvokeCommand_5Thread_SameContext_DiffSessionAndAllocSharemem
 * @testcase.desc      : CA create 5 threads use same context, each child thread test OpenSession, Invokecommand,
 * Allocatesharemem use seperate session and sharemem
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFramWithInitContext, InvokeCommand_5Thread_SameContext_DiffSessionAndAllocSharemem, Function | MediumTest | Level0)
{
    DatePacket iInvokeParams[5];
    uint32_t i;
    pthread_t id[5];

    for (i = 0; i < 5; i++) {
        iInvokeParams[i].context = GetContext();
        iInvokeParams[i].id = i + 1;
        pthread_create(&id[i], NULL, ThreadTestOpenInvokeAllocmem, reinterpret_cast<void *>(&iInvokeParams[i]));
    }
    for (i = 0; i < 5; i++) {
        pthread_join(id[i], NULL);
        EXPECT_EQ(iInvokeParams[i].ret, TEEC_SUCCESS);
    }
}
