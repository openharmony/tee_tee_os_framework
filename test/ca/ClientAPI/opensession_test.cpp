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

#include <iostream>
#include <vector>

#include <test_defines.h>

#include <common_test.h>
#include <empty_test.h>
#include <public_test.h>
#include <session_mgr/client_session_mgr.h>
#include <tee_client_api.h>
#include <tee_client_type.h>

using namespace std;

/**
 * @testcase.name      : Opensession_WithoutContext
 * @testcase.desc      : call TEEC_OpenSession Without Context,
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, Opensession_WithoutContext, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    ret = TEEC_OpenSession(NULL, GetSession(), &testId, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : Opensession_WithoutSession
 * @testcase.desc      : call TEEC_OpenSession Without session,
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, Opensession_WithoutSession, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    ret = TEEC_OpenSession(GetContext(), NULL, &testId, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : Opensession_WithoutDestination
 * @testcase.desc      : call TEEC_OpenSession Without Destination,
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, Opensession_WithoutDestination, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    ret = TEEC_OpenSession(GetContext(), GetSession(), NULL, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : Opensession_WithoutConnectionMethod
 * @testcase.desc      : call TEEC_OpenSession Without ConnectionMethod,
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, Opensession_WithoutConnectionMethod, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    ret = TEEC_OpenSession(GetContext(), GetSession(), &testId, -1, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : Opensession_WithNotSupportConnectionMethod
 * @testcase.desc      : call TEEC_OpenSession With Not Support ConnectionMethod,
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, Opensession_WithNotSupportConnectionMethod, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    char testData[TEST_STR_LEN] = "Hello";

    ret = TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_PUBLIC, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);

    ret = TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_USER, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);

    ret = TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_GROUP, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);

    ret =
        TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_GROUP, (void *)testData, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);

    ret = TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_APPLICATION, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);

    ret = TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_USER_APPLICATION, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);

    ret =
        TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_GROUP_APPLICATION, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);

    ret = TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_GROUP_APPLICATION, (void *)testData,
        &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : Opensession_WithoutOperation
 * @testcase.desc      : call TEEC_OpenSession Without Operation,
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(OnlyInit, Opensession_WithoutOperation, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;

    ret = TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_IDENTIFY, NULL, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : Opensession_WithoutOrigin
 * @testcase.desc      : call TEEC_OpenSession Without Origin,
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(OnlyInit, Opensession_WithoutOrigin, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    ret = TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_IDENTIFY, NULL, &operation, NULL);
    ASSERT_EQ(ret, TEEC_SUCCESS);
}

/**
 * @testcase.name      : Opensession_ContextIsNotInit
 * @testcase.desc      : call TEEC_OpenSession With Context is Not Init,
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(EmptyTest, Opensession_ContextIsNotInit, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_Context context = { 0 };
    TEEC_Session session = { 0 };
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    ret = TEEC_OpenSession(&context, &session, &testId, TEEC_LOGIN_IDENTIFY, NULL, NULL, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);

    TEEC_FinalizeContext(&context);
}

/**
 * @testcase.name      : Opensession_ParamTypesIsInvalid
 * @testcase.desc      : call TEEC_OpenSession With ParamTypes is invalid
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, Opensession_ParamTypesIsInvalid, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
    operation.params[0].value.a = 0;
    operation.params[0].value.b = 0;
    operation.params[1].value.a = 0xFFFFFFFF;
    operation.params[1].value.b = 1;

    ret = TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : Opensession_WithOperationIsNone
 * @testcase.desc      : call TEEC_OpenSession With Operation is none
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(OnlyInit, Opensession_WithOperationIsNone, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    ret = TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : Opensession_WithOperationIsValue
 * @testcase.desc      : call TEEC_OpenSession With Operation paramtype is value
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(OnlyInit, Opensession_WithOperationIsValue, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
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

    ret = TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(operation.params[0].value.a, 0x111);
    ASSERT_EQ(operation.params[0].value.b, 0x222);
    ASSERT_EQ(operation.params[1].value.a, 0x333);
    ASSERT_EQ(operation.params[1].value.b, 0x444);
    ASSERT_EQ(operation.params[2].value.a, 0x555);
    ASSERT_EQ(operation.params[2].value.b, 0x666);
    ASSERT_EQ(operation.params[3].value.a, 0x777);
    ASSERT_EQ(operation.params[3].value.b, 0x888);
}

/**
 * @testcase.name      : Opensession_WithOperationIsTempMem
 * @testcase.desc      : call TEEC_OpenSession With Operation paramtype is tempmem
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(OnlyInit, Opensession_WithOperationIsTempMem, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    TEEC_Operation operation = { 0 };
    char testData0[TEST_STR_LEN] = "Hello";
    char testData1[TEST_STR_LEN] = "abcdefgh";
    char testData2[TEST_STR_LEN] = "qwertyuiop";
    char testData3[TEST_STR_LEN] = "this is test string";

    uint32_t len0 = strlen(testData0) + 1;
    uint32_t len1 = strlen(testData1) + 1;
    uint32_t len2 = strlen(testData2) + 1;
    uint32_t len3 = strlen(testData3) + 1;
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_INOUT,
        TEEC_MEMREF_TEMP_INOUT);
    operation.params[0].tmpref.buffer = testData0;
    operation.params[0].tmpref.size = len0;
    operation.params[1].tmpref.buffer = testData1;
    operation.params[1].tmpref.size = len1;
    operation.params[2].tmpref.buffer = testData2;
    operation.params[2].tmpref.size = len2;
    operation.params[3].tmpref.buffer = testData3;
    operation.params[3].tmpref.size = len3;

    ret = TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ((char *)operation.params[0].tmpref.buffer, testData0);
    ASSERT_EQ(operation.params[0].tmpref.size, len0);
    ASSERT_STREQ((char *)operation.params[1].tmpref.buffer, testData1);
    ASSERT_EQ(operation.params[1].tmpref.size, len1);
    ASSERT_STREQ((char *)operation.params[2].tmpref.buffer, testData2);
    ASSERT_EQ(operation.params[2].tmpref.size, len2);
    ASSERT_STREQ((char *)operation.params[3].tmpref.buffer, testData3);
    ASSERT_EQ(operation.params[3].tmpref.size, len3);
}

/**
 * @testcase.name      : Opensession_WithOperationIsPartialMem
 * @testcase.desc      : call TEEC_OpenSession With Operation paramtype is PartialMem
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(OnlyInit, Opensession_WithOperationIsPartialMem, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    TEEC_Operation operation = { 0 };
    char testData0[TEST_STR_LEN] = "Hello";

    TEEC_SharedMemory sharedMem = { 0 };
    // test malloc mem
    sharedMem.size = TEST_STR_LEN;
    sharedMem.flags = TEEC_MEM_INOUT;

    ret = TEEC_AllocateSharedMemory(GetContext(), &sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    rc = memcpy_s(sharedMem.buffer, TEST_STR_LEN, testData0, TEST_STR_LEN);
    ASSERT_EQ(rc, 0);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT,
        TEEC_MEMREF_PARTIAL_INOUT, TEEC_MEMREF_PARTIAL_INOUT);
    operation.params[0].memref.parent = &sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = sharedMem.size;
    operation.params[1].memref.parent = &sharedMem;
    operation.params[1].memref.offset = 0;
    operation.params[1].memref.size = sharedMem.size;
    operation.params[2].memref.parent = &sharedMem;
    operation.params[2].memref.offset = 0;
    operation.params[2].memref.size = sharedMem.size;
    operation.params[3].memref.parent = &sharedMem;
    operation.params[3].memref.offset = 0;
    operation.params[3].memref.size = sharedMem.size;

    ret = TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ((char *)sharedMem.buffer, testData0);
    ASSERT_EQ(operation.params[0].memref.size, sharedMem.size);
    ASSERT_EQ(operation.params[1].memref.size, sharedMem.size);
    ASSERT_EQ(operation.params[2].memref.size, sharedMem.size);
    ASSERT_EQ(operation.params[3].memref.size, sharedMem.size);
}

/**
 * @testcase.name      : Opensession_WithNotExistUUID
 * @testcase.desc      : call TEEC_OpenSession With uuid is not exist
 * @testcase.expect    : return TEEC_ERROR_GENERIC
 */
TEE_TEST(OnlyInit, Opensession_WithNotExistUUID, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_UUID testId = UUID_TA_NOT_EXIST;
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    ret = TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_GENERIC);
    ASSERT_EQ(origin, TEEC_ORIGIN_COMMS);
}

/**
 * @testcase.name      : Opensession_ReturnErrorFromTA
 * @testcase.desc      : call TEEC_OpenSession With TA return error
 * @testcase.expect    : return TEEC_ERROR_GENERIC
 */
TEE_TEST(OnlyInit, Opensession_ReturnErrorFromTA, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].value.b = 0xFFFFFFFE; // this number intend for trigger ta return error when opensession

    ret = TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_GENERIC);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : Opensession_WithParamTypesIsInvalid
 * @testcase.desc      : call TEEC_OpenSession With paramtype is invalid
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(OnlyInit, Opensession_WithParamTypesIsInvalid, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(0x1F, TEEC_NONE, TEEC_NONE, TEEC_NONE); // 0X1F is invalid

    ret = TEEC_OpenSession(GetContext(), GetSession(), &testId, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(origin, TEEC_ORIGIN_API);
}

/**
 * @testcase.name      : RequestCancellationTest
 * @testcase.desc      : call TEEC_RequestCancellation after TEEC_InvokeCommand
 * @testcase.expect    : no error occur,in log can see not support this api
 */
TEE_TEST(EmptyTest, RequestCancellationTest, Function | MediumTest | Level0)
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
    TEEC_RequestCancellation(&operation);

    ASSERT_EQ(ret, TEEC_SUCCESS);
}