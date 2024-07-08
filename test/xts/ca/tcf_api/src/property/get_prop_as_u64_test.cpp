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
#include <securec.h>
#include <tee_client_api.h>
#include <tee_client_type.h>
#include <test_defines.h>
#include <test_log.h>
#include <test_tcf_cmdid.h>

using namespace testing::ext;
/**
 * @testcase.name      : TEE_GetPropertyAsU64_WithoutEnum_TESTU64
 * @testcase.desc      : test TA call TEE_GetPropertyAsU64 to get value of  SMC_TA_TESTU64
 * @testcase.expect    : return TEEC_SUCCESS
*/
TEE_TEST(TeeTCF1Test, TEE_GetPropertyAsU64_WithoutEnum_TESTU64, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU64;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, SMC_TA_TESTU64, sizeof(SMC_TA_TESTU64));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(SMC_TA_TESTU64);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(atoll(value.outBuffer), VALUE_PREDEFINED_U64);
    ASSERT_EQ(value.outBufferLen, strlen(value.outBuffer) + 1);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU64_WithoutEnum_NameIsNull
 * @testcase.desc      : test TA call TEE_GetPropertyAsU64 for name is null
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
*/
TEE_TEST(TeeTCF1Test, TEE_GetPropertyAsU64_WithoutEnum_NameIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU64;
    value.caseId = INPUT_ISNULL;
    value.propSet = TEE_PROPSET_CURRENT_TA;

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU64_WithoutEnum_NameIsZero
 * @testcase.desc      : test TA call TEE_GetPropertyAsU64 for name value is zero
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
*/
TEE_TEST(TeeTCF1Test, TEE_GetPropertyAsU64_WithoutEnum_NameIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU64;
    value.propSet = TEE_PROPSET_CURRENT_TA;

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU64_WithoutEnum_ValueIsNull
 * @testcase.desc      : test TA call TEE_GetPropertyAsU64 for value is null
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
*/
TEE_TEST(TeeTCF1Test, TEE_GetPropertyAsU64_WithoutEnum_ValueIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU64;
    value.caseId = OUTPUT_ISNULL;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_DATASIZE, sizeof(GPD_TA_DATASIZE));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_DATASIZE);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU64_WithoutEnum_NameNotFound
 * @testcase.desc      : test TA call TEE_GetPropertyAsU64 while Name Not Found
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
*/
TEE_TEST(TeeTCF1Test, TEE_GetPropertyAsU64_WithoutEnum_NameNotFound, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU64;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, PROPERTY_NAME_UNKNOWN, sizeof(PROPERTY_NAME_UNKNOWN));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(PROPERTY_NAME_UNKNOWN);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU64_WithoutEnum_NameNotU64
 * @testcase.desc      : test TA call TEE_GetPropertyAsU64 while Name type is not U64
 * @testcase.expect    : return TEEC_ERROR_BAD_FORMAT
*/
TEE_TEST(TeeTCF1Test, TEE_GetPropertyAsU64_WithoutEnum_NameNotU64, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU64;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_DESCRIPTION, sizeof(GPD_TA_DESCRIPTION));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_DESCRIPTION);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_FORMAT);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}
