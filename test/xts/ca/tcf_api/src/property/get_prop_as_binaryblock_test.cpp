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
 * @testcase.name      : TEE_GetPropertyAsBinaryBlock_WithoutEnum_TestBinaryBlock
 * @testcase.desc      : test TA call TEE_GetPropertyAsBinaryBlock to get value of  SMC_TA_TESTBINARYBLOCK
 * @testcase.expect    : return TEEC_SUCCESS
*/
TEE_TEST(TCF1Test, TEE_GetPropertyAsBinaryBlock_WithoutEnum_TestBinaryBlock, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBinaryBlock;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, SMC_TA_TESTBINARYBLOCK, sizeof(SMC_TA_TESTBINARYBLOCK));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(SMC_TA_TESTBINARYBLOCK);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(value.outBuffer, VALUE_PREDEFINED_BINARY_BLOCK);
    ASSERT_EQ(value.outBufferLen, sizeof(VALUE_PREDEFINED_BINARY_BLOCK));
}

/**
 * @testcase.name      : TEE_GetPropertyAsBinaryBlock_WithoutEnum_NameIsNull
 * @testcase.desc      : test TA call TEE_GetPropertyAsBinaryBlock for name is null
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
*/
TEE_TEST(TCF1Test, TEE_GetPropertyAsBinaryBlock_WithoutEnum_NameIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBinaryBlock;
    value.caseId = INPUT_ISNULL;
    value.propSet = TEE_PROPSET_CURRENT_TA;

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsBinaryBlock_WithoutEnum_NameIsZero
 * @testcase.desc      : test TA call TEE_GetPropertyAsBinaryBlock for name value is zero
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
*/
TEE_TEST(TCF1Test, TEE_GetPropertyAsBinaryBlock_WithoutEnum_NameIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBinaryBlock;
    value.propSet = TEE_PROPSET_CURRENT_TA;

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsBinaryBlock_WithoutEnum_ValueBufferIsNULL
 * @testcase.desc      : test TA call TEE_GetPropertyAsBinaryBlock for value buffer is null
 * @testcase.expect    : return TEEC_ERROR_SHORT_BUFFER
*/
TEE_TEST(TCF1Test, TEE_GetPropertyAsBinaryBlock_WithoutEnum_ValueBufferIsNULL, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBinaryBlock;
    value.caseId = OUTPUT_ISNULL;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, SMC_TA_TESTBINARYBLOCK, sizeof(SMC_TA_TESTBINARYBLOCK));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(SMC_TA_TESTBINARYBLOCK);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_SHORT_BUFFER);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsBinaryBlock_WithoutEnum_ValueBufferSizeIsNULL
 * @testcase.desc      : test TA call TEE_GetPropertyAsBinaryBlock for value buffer size is null
 * @testcase.expect    : return TEEC_ERROR_SHORT_BUFFER
*/
TEE_TEST(TCF1Test, TEE_GetPropertyAsBinaryBlock_WithoutEnum_ValueBufferSizeIsNULL, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBinaryBlock;
    value.caseId = OUTPUTBUFFERSIZE_ISNULL;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, SMC_TA_TESTBINARYBLOCK, sizeof(SMC_TA_TESTBINARYBLOCK));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(SMC_TA_TESTBINARYBLOCK);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_SHORT_BUFFER);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsBinaryBlock_WithoutEnum_ValueBufferSizeIsZero
 * @testcase.desc      : test TA call TEE_GetPropertyAsBinaryBlock for value buffer size is zero
 * @testcase.expect    : return TEEC_ERROR_SHORT_BUFFER
*/
TEE_TEST(TCF1Test, TEE_GetPropertyAsBinaryBlock_WithoutEnum_ValueBufferSizeIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBinaryBlock;
    value.caseId = OUTPUTBUFFERSIZE_ISZERO;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, SMC_TA_TESTBINARYBLOCK, sizeof(SMC_TA_TESTBINARYBLOCK));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(SMC_TA_TESTBINARYBLOCK);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_SHORT_BUFFER);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsBinaryBlock_WithoutEnum_BufferTooShort
 * @testcase.desc      : test TA call TEE_GetPropertyAsBinaryBlock while out buffer is too short
 * @testcase.expect    : return TEEC_ERROR_SHORT_BUFFER
*/
TEE_TEST(TCF1Test, TEE_GetPropertyAsBinaryBlock_WithoutEnum_BufferTooShort, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBinaryBlock;
    value.caseId = OUTPUTBUFFERSIZE_TOOSHORT;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, SMC_TA_TESTBINARYBLOCK, sizeof(SMC_TA_TESTBINARYBLOCK));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(SMC_TA_TESTBINARYBLOCK);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_SHORT_BUFFER);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(value.outBufferLen, sizeof(VALUE_PREDEFINED_BINARY_BLOCK));
}


/**
 * @testcase.name      : TEE_GetPropertyAsBinaryBlock_WithoutEnum_NameNotFound
 * @testcase.desc      : test TA call TEE_GetPropertyAsBinaryBlock while Name Not Found
 * @testcase.expect    : return TEEC_ERROR_ITEM_NOT_FOUND
*/
TEE_TEST(TCF1Test, TEE_GetPropertyAsBinaryBlock_WithoutEnum_NameNotFound, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBinaryBlock;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, PROPERTY_NAME_UNKNOWN, sizeof(PROPERTY_NAME_UNKNOWN));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(PROPERTY_NAME_UNKNOWN);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_GetPropertyAsBinaryBlock_WithoutEnum_NameNotBinaryBlock
 * @testcase.desc      : test TA call TEE_GetPropertyAsBinaryBlock while Name type is not BinaryBlock
 * @testcase.expect    : return TEEC_ERROR_BAD_FORMAT
*/
TEE_TEST(TCF1Test, TEE_GetPropertyAsBinaryBlock_WithoutEnum_NameNotBinaryBlock, Function | MediumTest | Level0)
{
    TEEC_Result ret;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsBinaryBlock;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_SINGLEINSTANCE, sizeof(GPD_TA_SINGLEINSTANCE));
    ASSERT_EQ(rc, 0);
    value.inBufferLen = sizeof(GPD_TA_SINGLEINSTANCE);

    ret = Invoke_GetPropertyAsX(GetContext(), GetSession(), &value);
    ASSERT_EQ(ret, TEEC_ERROR_BAD_FORMAT);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}
