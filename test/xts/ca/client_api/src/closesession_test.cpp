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
 * @testcase.name      : Closesession_WithCreatedSession
 * @testcase.desc      : call TEEC_CloseSession With created session
 * @testcase.expect    : session_id is 0
 */
TEE_TEST(EmptyTest, Closesession_WithCreatedSession, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    TEEC_CloseSession(&sess.session);
    ASSERT_EQ(sess.session.session_id, 0);
    ASSERT_STREQ(reinterpret_cast<char *>(sess.session.context), NULL);
}

/**
 * @testcase.name      : Closesession_WithoutSession
 * @testcase.desc      : call TEEC_CloseSession WithoutSession
 * @testcase.expect    : no error occur
 */
TEE_TEST(EmptyTest, Closesession_WithoutSession, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    ClientSessionMgr sess;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    TEEC_CloseSession(NULL);
    ASSERT_NE(sess.session.session_id, 0);
    ASSERT_NE(sess.session.ops_cnt, 0);
    ASSERT_STRNE(reinterpret_cast<char *>(sess.session.context), NULL);
}

/**
 * @testcase.name      : Closesession_WithNotOpenedSession
 * @testcase.desc      : call TEEC_CloseSession with Not Opened Session
 * @testcase.expect    : no error occur
 */
TEE_TEST(EmptyTest, Closesession_WithNotOpenedSession, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TEEC_UUID testId = CLIENTAPI_UUID_1;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    sess.Destroy();
    ret = TEEC_InitializeContext(NULL, &sess.context);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    TEEC_CloseSession(&sess.session);
    ASSERT_EQ(sess.session.session_id, 0);
    ASSERT_EQ(sess.session.ops_cnt, 0);
    ASSERT_STREQ(reinterpret_cast<char *>(sess.session.context), NULL);
}
