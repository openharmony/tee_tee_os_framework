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
 * @testcase.name      : TEE_GetPropertyAsU32_WithoutEnum_GPD_TA_DATASIZE
 * @testcase.desc      : test TA call TEE_GetPropertyAsU32 to get value of  GPD_TA_DATASIZE
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsU32_WithoutEnum_GPD_TA_DATASIZE, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_DATASIZE, sizeof(GPD_TA_DATASIZE));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_DATASIZE);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(atoi(value.outBuffer), VALUE_PREDEFINED_DATASIZE);
    ASSERT_EQ(value.outBufferLen, strlen(value.outBuffer) + 1);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU32_WithoutEnum_GPD_TA_STACKSIZE
 * @testcase.desc      : test TA call TEE_GetPropertyAsU32 to get value of GPD_TA_STACKSIZE
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsU32_WithoutEnum_GPD_TA_STACKSIZE, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_STACKSIZE, sizeof(GPD_TA_STACKSIZE));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_STACKSIZE);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(atoi(value.outBuffer), VALUE_PREDEFINED_STACKSIZE);
    ASSERT_EQ(value.outBufferLen, strlen(value.outBuffer) + 1);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU32_WithoutEnum_GPD_CLIENT_ENDIAN
 * @testcase.desc      : test TA call TEE_GetPropertyAsU32 to get value of GPD_CLIENT_ENDIAN
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsU32_WithoutEnum_GPD_CLIENT_ENDIAN, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
    value.propSet = TEE_PROPSET_CURRENT_CLIENT;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_CLIENT_ENDIAN, sizeof(GPD_CLIENT_ENDIAN));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_CLIENT_ENDIAN);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(atoi(value.outBuffer), VALUE_PREDEFINED_CLIENT_ENDIAN);
    ASSERT_EQ(value.outBufferLen, strlen(value.outBuffer) + 1);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU32_WithoutEnum_GPD_TEE_INTERNALCORE_VERSION
 * @testcase.desc      : test TA call TEE_GetPropertyAsU32 to get value of GPD_TEE_INTERNALCORE_VERSION
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsU32_WithoutEnum_GPD_TEE_INTERNALCORE_VERSION, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_INTERNALCORE_VERSION, sizeof(GPD_TEE_INTERNALCORE_VERSION));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_INTERNALCORE_VERSION);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(atoi(value.outBuffer), TEE_INTERNAL_CORE_VERSION);
    ASSERT_EQ(value.outBufferLen, strlen(value.outBuffer) + 1);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU32_WithoutEnum_GPD_TEE_SYSTEM_TIME_PROTECTIONLEVEL
 * @testcase.desc      : test TA call TEE_GetPropertyAsU32 to get value of GPD_TEE_SYSTEM_TIME_PROTECTIONLEVEL
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsU32_WithoutEnum_GPD_TEE_SYSTEM_TIME_PROTECTIONLEVEL, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_SYSTEM_TIME_PROTECTIONLEVEL,
        sizeof(GPD_TEE_SYSTEM_TIME_PROTECTIONLEVEL));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_SYSTEM_TIME_PROTECTIONLEVEL);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(atoi(value.outBuffer), TEE_TIME_PROTECT_LEVEL);
    ASSERT_EQ(value.outBufferLen, strlen(value.outBuffer) + 1);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU32_WithoutEnum_GPD_TEE_TA_PERSISTENT_TIME_PROTECTIONLEVEL
 * @testcase.desc      : test TA call TEE_GetPropertyAsU32 to get value of GPD_TEE_TA_PERSISTENT_TIME_PROTECTIONLEVEL
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsU32_WithoutEnum_GPD_TEE_TA_PERSISTENT_TIME_PROTECTIONLEVEL,
    Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_TA_PERSISTENT_TIME_PROTECTIONLEVEL,
        sizeof(GPD_TEE_TA_PERSISTENT_TIME_PROTECTIONLEVEL));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_TA_PERSISTENT_TIME_PROTECTIONLEVEL);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(atoi(value.outBuffer), TA_TIME_PROTECT_LEVEL);
    ASSERT_EQ(value.outBufferLen, strlen(value.outBuffer) + 1);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU32_WithoutEnum_GPD_TEE_ARITH_MAXBIGINTSIZE
 * @testcase.desc      : test TA call TEE_GetPropertyAsU32 to get value of GPD_TEE_ARITH_MAXBIGINTSIZE
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsU32_WithoutEnum_GPD_TEE_ARITH_MAXBIGINTSIZE, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_ARITH_MAXBIGINTSIZE, sizeof(GPD_TEE_ARITH_MAXBIGINTSIZE));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_ARITH_MAXBIGINTSIZE);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(atoi(value.outBuffer), MAX_BIG_INT_SIZE);
    ASSERT_EQ(value.outBufferLen, strlen(value.outBuffer) + 1);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU32_WithoutEnum_GPD_TEE_ANTIROLLBACK_PROTECTIONLEVEL
 * @testcase.desc      : test TA call TEE_GetPropertyAsU32 to get value of GPD_TEE_ANTIROLLBACK_PROTECTIONLEVEL
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsU32_WithoutEnum_GPD_TEE_ANTIROLLBACK_PROTECTIONLEVEL,
    Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_ANTIROLLBACK_PROTECTIONLEVEL,
        sizeof(GPD_TEE_ANTIROLLBACK_PROTECTIONLEVEL));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_ANTIROLLBACK_PROTECTIONLEVEL);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(atoi(value.outBuffer), 0);
    ASSERT_EQ(value.outBufferLen, strlen(value.outBuffer) + 1);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU32_WithoutEnum_GPD_TEE_ROLLBACKDETECT_PROTECTIONLEVEL
 * @testcase.desc      : test TA call TEE_GetPropertyAsU32 to get value of GPD_TEE_ROLLBACKDETECT_PROTECTIONLEVEL
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsU32_WithoutEnum_GPD_TEE_ROLLBACKDETECT_PROTECTIONLEVEL,
    Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_ROLLBACKDETECT_PROTECTIONLEVEL,
        sizeof(GPD_TEE_ROLLBACKDETECT_PROTECTIONLEVEL));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_ROLLBACKDETECT_PROTECTIONLEVEL);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(atoi(value.outBuffer), 0);
    ASSERT_EQ(value.outBufferLen, strlen(value.outBuffer) + 1);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU32_WithoutEnum_GPD_TEE_EVENT_MAXSOURCES
 * @testcase.desc      : test TA call TEE_GetPropertyAsU32 to get value of GPD_TEE_EVENT_MAXSOURCES
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsU32_WithoutEnum_GPD_TEE_EVENT_MAXSOURCES, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_EVENT_MAXSOURCES, sizeof(GPD_TEE_EVENT_MAXSOURCES));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_EVENT_MAXSOURCES);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(atoi(value.outBuffer), 0);
    ASSERT_EQ(value.outBufferLen, strlen(value.outBuffer) + 1);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU32_WithoutEnum_GPD_TEE_API_LEVEL
 * @testcase.desc      : test TA call TEE_GetPropertyAsU32 to get value of GPD_TEE_API_LEVEL
 * @testcase.expect    : return TEEC_SUCCESS, get value is correct
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsU32_WithoutEnum_GPD_TEE_API_LEVEL, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
    value.propSet = TEE_PROPSET_IMPLEMENTATION;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TEE_API_LEVEL, sizeof(GPD_TEE_API_LEVEL));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TEE_API_LEVEL);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(atoi(value.outBuffer), TEE_MAX_API_LEVEL_CONFIG);
    ASSERT_EQ(value.outBufferLen, strlen(value.outBuffer) + 1);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU32_WithoutEnum_NameIsNull
 * @testcase.desc      : test TA call TEE_GetPropertyAsU32 for name is null
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsU32_WithoutEnum_NameIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
    value.caseId = INPUT_ISNULL;
    value.propSet = TEE_PROPSET_CURRENT_TA;

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU32_WithoutEnum_NameIsZero
 * @testcase.desc      : test TA call TEE_GetPropertyAsU32 for name value is zero
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsU32_WithoutEnum_NameIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
    value.propSet = TEE_PROPSET_CURRENT_TA;

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU32_WithoutEnum_ValueIsNull
 * @testcase.desc      : test TA call TEE_GetPropertyAsU32 for value is null
 * @testcase.expect    : return TEEC_ERROR_BAD_PARAMETERS
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsU32_WithoutEnum_ValueIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
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
 * @testcase.name      : TEE_GetPropertyAsU32_WithoutEnum_NameNotFound
 * @testcase.desc      : test TA call TEE_GetPropertyAsU32 while Name Not Found
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsU32_WithoutEnum_NameNotFound, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, PROPERTY_NAME_UNKNOWN, sizeof(PROPERTY_NAME_UNKNOWN));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(PROPERTY_NAME_UNKNOWN);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsU32_WithoutEnum_NameNotU32
 * @testcase.desc      : test TA call TEE_GetPropertyAsU32 while Name type is not U32
 * @testcase.expect    : return TEEC_ERROR_BAD_FORMAT
 */
TEE_TEST(TCF1Test, TEE_GetPropertyAsU32_WithoutEnum_NameNotU32, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_DESCRIPTION, sizeof(GPD_TA_DESCRIPTION));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_DESCRIPTION);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_FORMAT);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}
