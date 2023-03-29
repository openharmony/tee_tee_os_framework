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

/**
 * @testcase.name      : Finalizecontext_WithCreatedContext
 * @testcase.desc      : call TEEC_FinalizeContext With created context
 * @testcase.expect    : fd has released
 */
TEE_TEST(EmptyTest, Finalizecontext_WithCreatedContext, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    ClientSessionMgr sess;
    ret = TEEC_InitializeContext(NULL, &sess.context);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    TEEC_FinalizeContext(&sess.context);
    ASSERT_EQ(sess.context.fd, -1);
}

/**
 * @testcase.name      : Finalizecontext_WithNotCreatedContext
 * @testcase.desc      : call TEEC_FinalizeContext With not created context
 * @testcase.expect    : fd is -1
 */
TEE_TEST(EmptyTest, Finalizecontext_WithNotCreatedContext, Function | MediumTest | Level0)
{
    ClientSessionMgr sess;
    sess.context = { 0 };
    TEEC_FinalizeContext(&sess.context);
    ASSERT_EQ(sess.context.fd, -1);
}

/**
 * @testcase.name      : Finalizecontext_WithoutContext
 * @testcase.desc      : call TEEC_FinalizeContext Without context
 * @testcase.expect    : fd is -1
 */
TEE_TEST(EmptyTest, Finalizecontext_WithoutContext, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    ClientSessionMgr sess;
    ret = TEEC_InitializeContext(NULL, &sess.context);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    TEEC_FinalizeContext(NULL);
    ASSERT_NE(sess.context.fd, -1);
}