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
#include <test_defines.h>
#include <common_test.h>
#include <securec.h>
#include <tee_client_api.h>
#include <tee_client_type.h>
#include <test_log.h>
#include <test_tcf_cmdid.h>

using namespace testing::ext;

/**
 * @testcase.name      : TEE_GetPropertyAsBool_WithoutEnum_GPD_TA_SINGLEINSTANCE
 * @testcase.desc      : test TA call TEE_GetPropertyAsBool to get value of GPD_TA_SINGLEINSTANCE
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsBool_WithoutEnum_GPD_TA_SINGLEINSTANCE, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBool;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_SINGLEINSTANCE, sizeof(GPD_TA_SINGLEINSTANCE));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_SINGLEINSTANCE);
    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, VALUE_PREDEFINED_BOOLEAN);
    ASSERT_EQ(value.outBufferLen, sizeof(VALUE_PREDEFINED_BOOLEAN));
}

/**
 * @testcase.name      : TEE_GetPropertyAsBool_WithoutEnum_GPD_TA_MULTISESSION
 * @testcase.desc      : test TA call TEE_GetPropertyAsBool to get value of  GPD_TA_MULTISESSION
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsBool_WithoutEnum_GPD_TA_MULTISESSION, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBool;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_MULTISESSION, sizeof(GPD_TA_MULTISESSION));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_MULTISESSION);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, VALUE_PREDEFINED_BOOLEAN);
    ASSERT_EQ(value.outBufferLen, sizeof(VALUE_PREDEFINED_BOOLEAN));
}

/**
 * @testcase.name      : TEE_GetPropertyAsBool_WithoutEnum_GPD_TA_INSTANCEKEEPALIVE
 * @testcase.desc      : test TA call TEE_GetPropertyAsBool to get value of GPD_TA_INSTANCEKEEPALIVE
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsBool_WithoutEnum_GPD_TA_INSTANCEKEEPALIVE, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBool;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_INSTANCEKEEPALIVE, sizeof(GPD_TA_INSTANCEKEEPALIVE));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_INSTANCEKEEPALIVE);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, VALUE_PREDEFINED_FALSE);
    ASSERT_EQ(value.outBufferLen, sizeof(VALUE_PREDEFINED_FALSE));
}

/**
 * @testcase.name      : TEE_GetPropertyAsBool_WithoutEnum_GPD_TEE_CRYPTOGRAPHY_ECC
 * @testcase.desc      : test TA call TEE_GetPropertyAsBool to get value of GPD_TEE_CRYPTOGRAPHY_ECC
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsBool_WithoutEnum_GPD_TEE_CRYPTOGRAPHY_ECC, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBool;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_CRYPTOGRAPHY_ECC, sizeof(GPD_TEE_CRYPTOGRAPHY_ECC));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_CRYPTOGRAPHY_ECC);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, VALUE_PREDEFINED_FALSE);
    ASSERT_EQ(value.outBufferLen, sizeof(VALUE_PREDEFINED_FALSE));
}

/**
 * @testcase.name      : TEE_GetPropertyAsBool_WithoutEnum_GPD_TEE_CRYPTOGRAPHY_NIST
 * @testcase.desc      : test TA call TEE_GetPropertyAsBool to get value of GPD_TEE_CRYPTOGRAPHY_NIST
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsBool_WithoutEnum_GPD_TEE_CRYPTOGRAPHY_NIST, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBool;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_CRYPTOGRAPHY_NIST, sizeof(GPD_TEE_CRYPTOGRAPHY_NIST));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_CRYPTOGRAPHY_NIST);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, VALUE_PREDEFINED_FALSE);
    ASSERT_EQ(value.outBufferLen, sizeof(VALUE_PREDEFINED_FALSE));
}

/**
 * @testcase.name      : TEE_GetPropertyAsBool_WithoutEnum_GPD_TEE_CRYPTOGRAPHY_BSI_R
 * @testcase.desc      : test TA call TEE_GetPropertyAsBool to get value of GPD_TEE_CRYPTOGRAPHY_BSI_R
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsBool_WithoutEnum_GPD_TEE_CRYPTOGRAPHY_BSI_R, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBool;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_CRYPTOGRAPHY_BSI_R, sizeof(GPD_TEE_CRYPTOGRAPHY_BSI_R));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_CRYPTOGRAPHY_BSI_R);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, VALUE_PREDEFINED_FALSE);
    ASSERT_EQ(value.outBufferLen, sizeof(VALUE_PREDEFINED_FALSE));
}

/**
 * @testcase.name      : TEE_GetPropertyAsBool_WithoutEnum_GPD_TEE_CRYPTOGRAPHY_BSI_T
 * @testcase.desc      : test TA call TEE_GetPropertyAsBool to get value of GPD_TEE_CRYPTOGRAPHY_BSI_T
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsBool_WithoutEnum_GPD_TEE_CRYPTOGRAPHY_BSI_T, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBool;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_CRYPTOGRAPHY_BSI_T, sizeof(GPD_TEE_CRYPTOGRAPHY_BSI_T));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_CRYPTOGRAPHY_BSI_T);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, VALUE_PREDEFINED_FALSE);
    ASSERT_EQ(value.outBufferLen, sizeof(VALUE_PREDEFINED_FALSE));
}

/**
 * @testcase.name      : TEE_GetPropertyAsBool_WithoutEnum_GPD_TEE_CRYPTOGRAPHY_IETF
 * @testcase.desc      : test TA call TEE_GetPropertyAsBool to get value of GPD_TEE_CRYPTOGRAPHY_IETF
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsBool_WithoutEnum_GPD_TEE_CRYPTOGRAPHY_IETF, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBool;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_CRYPTOGRAPHY_IETF, sizeof(GPD_TEE_CRYPTOGRAPHY_IETF));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_CRYPTOGRAPHY_IETF);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, VALUE_PREDEFINED_FALSE);
    ASSERT_EQ(value.outBufferLen, sizeof(VALUE_PREDEFINED_FALSE));
}

/**
 * @testcase.name      : TEE_GetPropertyAsBool_WithoutEnum_GPD_TEE_CRYPTOGRAPHY_OCTA
 * @testcase.desc      : test TA call TEE_GetPropertyAsBool to get value of GPD_TEE_CRYPTOGRAPHY_OCTA
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsBool_WithoutEnum_GPD_TEE_CRYPTOGRAPHY_OCTA, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBool;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_CRYPTOGRAPHY_OCTA, sizeof(GPD_TEE_CRYPTOGRAPHY_OCTA));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_CRYPTOGRAPHY_OCTA);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, VALUE_PREDEFINED_FALSE);
    ASSERT_EQ(value.outBufferLen, sizeof(VALUE_PREDEFINED_FALSE));
}

/**
 * @testcase.name      : TEE_GetPropertyAsBool_WithoutEnum_NameIsNull
 * @testcase.desc      : test TA call TEE_GetPropertyAsBool for name is null
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsBool_WithoutEnum_NameIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBool;
    value.caseId = INPUT_ISNULL;
    value.propSet = TEE_PROPSET_CURRENT_TA;

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsBool_WithoutEnum_NameIsZero
 * @testcase.desc      : test TA call TEE_GetPropertyAsBool for name value is zero
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsBool_WithoutEnum_NameIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBool;
    value.propSet = TEE_PROPSET_CURRENT_TA;

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsBool_WithoutEnum_ValueIsNull
 * @testcase.desc      : test TA call TEE_GetPropertyAsBool for value is null
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsBool_WithoutEnum_ValueIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBool;
    value.caseId = OUTPUT_ISNULL;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_MULTISESSION, sizeof(GPD_TA_MULTISESSION));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_MULTISESSION);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_PARAMETERS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsBool_WithoutEnum_NameNotFound
 * @testcase.desc      : test TA call TEE_GetPropertyAsBool while Name Not Found
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsBool_WithoutEnum_NameNotFound, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBool;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, PROPERTY_NAME_UNKNOWN, sizeof(PROPERTY_NAME_UNKNOWN));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(PROPERTY_NAME_UNKNOWN);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsBool_WithoutEnum_NameNotBool
 * @testcase.desc      : test TA call TEE_GetPropertyAsBool while Name type is not bool
 * @testcase.expect    : return TEEC_ERROR_BAD_FORMAT
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsBool_WithoutEnum_NameNotBool, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBool;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_STACKSIZE, sizeof(GPD_TA_STACKSIZE));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_STACKSIZE);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_FORMAT);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}