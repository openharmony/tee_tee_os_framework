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

#include <common_test.h>
#include <gtest/gtest.h>
#include <public_test.h>
#include <session_mgr/client_session_mgr.h>
#include <securec.h>
#include <tee_client_api.h>
#include <tee_client_type.h>
#include <test_defines.h>
#include <test_log.h>
#include <test_tcf_cmdid.h>

using namespace std;
using namespace testing::ext;

#define TEST_STR_LEN 256
char g_testData3[TEST_STR_LEN] = "this is test string";

/**
 * @testcase.name      : TEE_PrintAPI
 * @testcase.desc      : test TA call tee_print, tee_print_driver, uart_cprintf, uart_printf_func api 
 * @testcase.expect    : return TEEC_SUCCESS
 */

TEE_TEST(TeeBasicTestFram, TEE_PrintAPI, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = TCF_API_UUID_1;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_MEMREF_TEMP_INOUT, TEEC_NONE, TEEC_NONE);
    operation.params[0].value.a = 0x10;
    operation.params[1].tmpref.buffer = g_testData3;
    operation.params[1].tmpref.size = TEST_STR_LEN;
    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_PRINT, &operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : TEE_GetAllKindsInfo
 * @testcase.desc      : test TA call get_heap_usage, tee_ext_get_caller_info, tee_ext_get_caller_userid,
 *                       tee_get_session_type api to get all kinds info
 * @testcase.expect    : return TEEC_SUCCESS, get info is correct
 */
TEE_TEST(TeeBasicTestFram, TEE_GetAllKindsInfo, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = TCF_API_UUID_1;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
    operation.params[0].value.a = 0;
    operation.params[0].value.b = 0;
    operation.params[1].value.a = SESSION_FROM_UNKNOWN;
    operation.params[1].value.b = SESSION_FROM_UNKNOWN;
    ret = TEEC_InvokeCommand(&sess.session, CMD_TEST_GETINFO, &operation, &origin);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_NE(operation.params[0].value.a, 0);
    ASSERT_LT(operation.params[0].value.b, 0xffffffff);
    ASSERT_GT(operation.params[0].value.b, 0);
    ASSERT_EQ(operation.params[1].value.a, 0);
    ASSERT_EQ(operation.params[1].value.b, 0);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    sess.Destroy();
}

/**
 * @testcase.name      : TEE_InvokeTACommand_With_ShareMem
 * @testcase.desc      : test TA call TEE_InvokeTACommand to pass memref to other TA while buffer is sharemem;
 *                       test tee_alloc_sharemem_aux, tee_alloc_coherent_sharemem_aux, tee_free_sharemem,
 *                       copy_from_sharemem, copy_to_sharemem api
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2TA2TATest, TEE_InvokeTACommand_With_ShareMem, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession;
    uint32_t origin = 0;
    TestData value = { 0 };
    value.uuid = TCF_API_UUID_1; // this uuid is for ta2
    value.inBufferLen = BIG_SIZE;
    value.outBufferLen = BIG_SIZE;

    ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession, &value, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TEE);
    ASSERT_NE(ta2taSession, 0);

    ret = Invoke_InvokeTACommand(GetSession(), CMD_TEE_ShareMemAPI, ta2taSession, &value, &origin);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_GENERIC);
#endif
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);

    ret = Invoke_CloseTASession(GetSession(), CMD_TEE_CloseTASession, ta2taSession, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}