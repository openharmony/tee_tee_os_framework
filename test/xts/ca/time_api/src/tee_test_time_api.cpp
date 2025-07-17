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

#include <public_test.h>
#include <test_log.h>
#include <securec.h>
#include <common_test.h>
#include <tee_client_api.h>
#include <tee_client_type.h>
#include <session_mgr/client_session_mgr.h>

using namespace testing::ext;
/**
 * @testcase.name      : GetSystemTime
 * @testcase.desc      : test TEE_GetSystemTime api
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, TEE_GetSystemTime, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = TIME_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = {0};
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE);
    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_GET_SYSTEM_TIME, &operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
#ifndef TEST_STUB
    uint32_t time1 = operation.params[1].value.a;

    sleep(3); // wait for 3s
    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_GET_SYSTEM_TIME, &operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    uint32_t time2 = operation.params[1].value.a;
    ASSERT_LT(time1, time2);
#endif
    sess.Destroy();
}

/**
 * @testcase.name      : TeeWait
 * @testcase.desc      : test TEE_Wait api
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, TeeWait, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = TIME_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_TEE_WAIT, NULL, &origin);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    sess.Destroy();
}

/**
 * @testcase.name      : GetPersistentTime
 * @testcase.desc      : test get persistent time
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, GetPersistentTime, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = TIME_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_GET_PERSISTENT_TIME, NULL, &origin);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    sess.Destroy();
}

/**
 * @testcase.name      : SetPersistentTime
 * @testcase.desc      : test set persistent time
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, SetPersistentTime, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = TIME_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_SET_PERSISTENT_TIME, NULL, &origin);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    sess.Destroy();
}

/**
 * @testcase.name      : TestPersistentTimeWithException
 * @testcase.desc      : test set and get persistent time with exception
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, TestPersistentTimeWithException, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = TIME_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_PERSISTENT_TIME_WITH_EXCEPTION, NULL, &origin);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    sess.Destroy();
}

/**
 * @testcase.name      : OnlyGetPersistentTime
 * @testcase.desc      : test only get persistent time
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, OnlyGetPersistentTime, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = TIME_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_ONLY_GET_PERSISTENT_TIME, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
}

/**
 * @testcase.name      : GetReeTime
 * @testcase.desc      : test TEE_GetREETime api
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, GetReeTime, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = TIME_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = {0};
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE);
    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_GET_REE_TIME, &operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
#ifndef TEST_STUB
    uint32_t time1 = operation.params[1].value.a;

    sleep(3); // wait for 3s
    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_GET_REE_TIME, &operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    uint32_t time2 = operation.params[1].value.a;

    ASSERT_LT(time1, time2);
#endif
    sess.Destroy();
}

/**
 * @testcase.name      : GetSecureRtcTime
 * @testcase.desc      : test tee_get_secure_rtc_time api
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, GetSecureRtcTime, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = TIME_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    uint32_t time = 0;

    TEEC_Operation operation = {0};
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE);
    operation.params[1].value.a = 0;
    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_GET_SECURE_RTC_TIME, &operation, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    time = operation.params[1].value.a;
#ifndef TEST_STUB
    ASSERT_LT(0, time);
#endif

    sess.Destroy();
}

/**
 * @testcase.name      : CreateDestoryExpireRemainTimer
 * @testcase.desc      : test tee_ext_create_timer, tee_ext_destory_timer, tee_ext_get_timer_expire, 
 *                       tee_ext_get_timer_remain api
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeBasicTestFram, CreateDestoryExpireRemainTimer, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    uint32_t origin;
    TEEC_UUID testId = TIME_API_UUID;
    TEEC_Result ret = sess.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);

    TEEC_Operation operation = { 0 };
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
    operation.params[1].value.a = 0;
    operation.params[1].value.b = 3;
    ret = TEEC_InvokeCommand(&sess.session, CMD_ID_TEST_OPERATE_TIMER, &operation, &origin);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(operation.params[1].value.a, 3);
    ASSERT_EQ(operation.params[1].value.b, 2); // get remain time
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif

    sess.Destroy();
}