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
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_GPD_TA_APPID
 * @testcase.desc      : test TA call TEE_GetPropertyAsString to get value of GPD_TA_APPID
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_GPD_TA_APPID, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_APPID, sizeof(GPD_TA_APPID));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_APPID);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, VALUE_PREDEFINED_UUID);
    ASSERT_EQ(value.outBufferLen, BIG_SIZE);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_GPD_TA_SERVICENAME
 * @testcase.desc      : test TA call TEE_GetPropertyAsString to get value of GPD_TA_SERVICENAME
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND, can not get value
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_GPD_TA_SERVICENAME, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_SERVICENAME, sizeof(GPD_TA_SERVICENAME));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_SERVICENAME);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_GPD_CLIENT_IDENTITY
 * @testcase.desc      : test TA call TEE_GetPropertyAsString to get value of GPD_CLIENT_IDENTITY
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_GPD_CLIENT_IDENTITY, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.propSet = TEE_PROPSET_CURRENT_CLIENT;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_CLIENT_IDENTITY, sizeof(GPD_CLIENT_IDENTITY));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_CLIENT_IDENTITY);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, VALUE_PREDEFINED_CLIENT_IDENTITY);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_GPD_CLIENT_IDENTITY_PropsetIsWrong
 * @testcase.desc      : test TA call TEE_GetPropertyAsString to get value of GPD_CLIENT_IDENTITY, Propset is wrong
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND, can not get value
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_GPD_CLIENT_IDENTITY_PropsetIsWrong,
    Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_CLIENT_IDENTITY, sizeof(GPD_CLIENT_IDENTITY));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_CLIENT_IDENTITY);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_GPD_TA_VERSION
 * @testcase.desc      : test TA call TEE_GetPropertyAsString to get value of GPD_TA_VERSION
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_GPD_TA_VERSION, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_VERSION, sizeof(GPD_TA_VERSION));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_VERSION);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, VALUE_PREDEFINED_TA_VERSION);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_GPD_TA_DESCRIPTION
 * @testcase.desc      : test TA call TEE_GetPropertyAsString to get value of GPD_TA_DESCRIPTION
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_GPD_TA_DESCRIPTION, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_DESCRIPTION, sizeof(GPD_TA_DESCRIPTION));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_DESCRIPTION);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, VALUE_PREDEFINED_TA_DESCRIPTION);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_GPD_TEE_APIVERSION
 * @testcase.desc      : test TA call TEE_GetPropertyAsString to get value of GPD_TEE_APIVERSION
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_GPD_TEE_APIVERSION, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_APIVERSION, sizeof(GPD_TEE_APIVERSION));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_APIVERSION);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, TEE_API_VERSION);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_GPD_TEE_DESCRIPTION
 * @testcase.desc      : test TA call TEE_GetPropertyAsString to get value of GPD_TEE_DESCRIPTION
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_GPD_TEE_DESCRIPTION, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_DESCRIPTION, sizeof(GPD_TEE_DESCRIPTION));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_DESCRIPTION);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, TEE_BUILD_VER);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_GPD_TEE_TRUSTEDOS_IMP_VERSION
 * @testcase.desc      : test TA call TEE_GetPropertyAsString to get value of GPD_TEE_TRUSTEDOS_IMP_VERSION
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_GPD_TEE_TRUSTEDOS_IMP_VERSION, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_TRUSTEDOS_IMP_VERSION, sizeof(GPD_TEE_TRUSTEDOS_IMP_VERSION));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_TRUSTEDOS_IMP_VERSION);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, TEE_IMP_VERSION);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_GPD_TEE_TRUSTEDOS_IMP_BINARYVERSION
 * @testcase.desc      : test TA call TEE_GetPropertyAsString to get value of GPD_TEE_TRUSTEDOS_IMP_BINARYVERSION
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_GPD_TEE_TRUSTEDOS_IMP_BINARYVERSION,
    Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_TRUSTEDOS_IMP_BINARYVERSION,
        sizeof(GPD_TEE_TRUSTEDOS_IMP_BINARYVERSION));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_TRUSTEDOS_IMP_BINARYVERSION);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, TEE_IMP_VERSION);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_GPD_TEE_FIRMWARE_IMP_VERSION
 * @testcase.desc      : test TA call TEE_GetPropertyAsString to get value of GPD_TEE_FIRMWARE_IMP_VERSION
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_GPD_TEE_FIRMWARE_IMP_VERSION, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_FIRMWARE_IMP_VERSION, sizeof(GPD_TEE_FIRMWARE_IMP_VERSION));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_FIRMWARE_IMP_VERSION);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, TEE_FIRMWARE_IMP_VERSION);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_GPD_TEE_FIRMWARE_IMP_BINARYVERSION
 * @testcase.desc      : test TA call TEE_GetPropertyAsString to get value of GPD_TEE_FIRMWARE_IMP_BINARYVERSION
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_GPD_TEE_FIRMWARE_IMP_BINARYVERSION,
    Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_FIRMWARE_IMP_BINARYVERSION,
        sizeof(GPD_TEE_FIRMWARE_IMP_BINARYVERSION));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_FIRMWARE_IMP_BINARYVERSION);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, TEE_FIRMWARE_IMP_VERSION);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_GPD_TEE_TRUSTEDOS_MANUFACTURER
 * @testcase.desc      : test TA call TEE_GetPropertyAsString to get value of GPD_TEE_TRUSTEDOS_MANUFACTURER
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_GPD_TEE_TRUSTEDOS_MANUFACTURER, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_TRUSTEDOS_MANUFACTURER, sizeof(GPD_TEE_TRUSTEDOS_MANUFACTURER));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_TRUSTEDOS_MANUFACTURER);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, TEE_MANUFACTURER);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_GPD_TEE_FIRMWARE_MANUFACTURER
 * @testcase.desc      : test TA call TEE_GetPropertyAsString to get value of GPD_TEE_FIRMWARE_MANUFACTURER
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_GPD_TEE_FIRMWARE_MANUFACTURER, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_FIRMWARE_MANUFACTURER, sizeof(GPD_TEE_FIRMWARE_MANUFACTURER));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_FIRMWARE_MANUFACTURER);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, TEE_FIRMWARE_MANUFACTURER);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_PropsetIsZero
 * @testcase.desc      : test TA call TEE_GetPropertyAsString while Propset Is Zero
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_PropsetIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.propSet = TEE_PROPSET_ZERO;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_APPID, sizeof(GPD_TA_APPID));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_APPID);
    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_NameIsNULL
 * @testcase.desc      : test TA call TEE_GetPropertyAsString while name is null
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_NameIsNULL, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.caseId = INPUT_ISNULL;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_NameIsZero
 * @testcase.desc      : test TA call TEE_GetPropertyAsString while name value is zero
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_NameIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_ValueBufferIsNULL
 * @testcase.desc      : test TA call TEE_GetPropertyAsString while value buffer is null
 * @testcase.expect    : return TEEC_ERROR_SHORT_BUFFER
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_ValueBufferIsNULL, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.caseId = OUTPUT_ISNULL;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_APPID, sizeof(GPD_TA_APPID));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_APPID);
    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_SHORT_BUFFER);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_ValueBufferSizeIsNULL
 * @testcase.desc      : test TA call TEE_GetPropertyAsString while value buffer size is null
 * @testcase.expect    : return TEEC_ERROR_SHORT_BUFFER
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_ValueBufferSizeIsNULL, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.caseId = OUTPUTBUFFERSIZE_ISNULL;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_APPID, sizeof(GPD_TA_APPID));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_APPID);
    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_SHORT_BUFFER);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_ValueBufferSizeIsZero
 * @testcase.desc      : test TA call TEE_GetPropertyAsString while value buffer size is zero
 * @testcase.expect    : return TEEC_ERROR_SHORT_BUFFER
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_ValueBufferSizeIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.caseId = OUTPUTBUFFERSIZE_ISZERO;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_APPID, sizeof(GPD_TA_APPID));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_APPID);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_SHORT_BUFFER);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_NameNotFound
 * @testcase.desc      : test TA call TEE_GetPropertyAsString while Name Not Found
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_NameNotFound, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, PROPERTY_NAME_UNKNOWN, sizeof(PROPERTY_NAME_UNKNOWN));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(PROPERTY_NAME_UNKNOWN);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsString_WithoutEnum_BufferTooShort
 * @testcase.desc      : test TA call TEE_GetPropertyAsString while out buffer is too short
 * @testcase.expect    : return TEEC_ERROR_SHORT_BUFFER
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsString_WithoutEnum_BufferTooShort, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsString;
    value.caseId = OUTPUTBUFFERSIZE_TOOSHORT;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_APPID, sizeof(GPD_TA_APPID));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_APPID);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_SHORT_BUFFER);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}