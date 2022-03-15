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

#include <test_defines.h>

#include <tee_client_api.h>
#include <tee_client_type.h>
#include <empty_test.h>
#include <public_test.h>

using namespace std;

/**
 * @testcase.name      : InitContext_NameIsNotNULL
 * @testcase.desc      : call TEEC_InitializeContext normal test
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, InitContext_NameIsNotNULL, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TEEC_Context context = { 0 };
    const char *name = "testname";
    ret = TEEC_InitializeContext(name, &context);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    TEEC_FinalizeContext(&context);
}

/**
 * @testcase.name      : InitContext_ContextIsNULL
 * @testcase.desc      : call TEEC_InitializeContext with context is null
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(EmptyTest, InitContext_ContextIsNULL, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    ret = TEEC_InitializeContext(NULL, NULL);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
}

/**
 * @testcase.name      : InitContext_AfterFinalizeContext
 * @testcase.desc      : call TEEC_InitializeContext after Finalize Context
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(OnlyInit, InitContext_AfterFinalizeContext, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TEEC_FinalizeContext(GetContext());

    ret = TEEC_InitializeContext(NULL, GetContext());
    ASSERT_EQ(ret, TEEC_SUCCESS);
}

/**
 * @testcase.name      : InitContext_Use17Context
 * @testcase.desc      : one CA call TEEC_InitializeContext use 17 different Context,
 *                       this testcase shoud fail at init 17th context,only support 16 contexts in one CA
 * @testcase.expect    : return TEEC_FAIL
 */
TEE_TEST(EmptyTest, InitContext_Use17Context, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TEEC_Context context[17] = { { 0 } };
    uint32_t i;
    for (i = 0; i < 16; i++) {
        ret = TEEC_InitializeContext(NULL, &context[i]);
        EXPECT_EQ(ret, TEEC_SUCCESS);
    }
    // init 17th context should fail
    ret = TEEC_InitializeContext(NULL, &context[16]);
    EXPECT_EQ(ret, TEEC_FAIL);

    for (i = 0; i < 17; i++)
        TEEC_FinalizeContext(&context[i]);
}