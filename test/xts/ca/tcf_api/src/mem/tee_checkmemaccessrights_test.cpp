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
 * @testcase.name      : TEE_CheckMemoryAccessRights_With_Access_Read_Flag
 * @testcase.desc      : test TA call TEE_CheckMemoryAccessRights to check buffer whether has Access_Read right
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TCF2Test, TEE_CheckMemoryAccessRights_With_Access_Read_Flag, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };

    value.oldSize = TESTSIZE;
    value.accessFlags = TEE_MEMORY_ACCESS_READ;
    ret = Invoke_CheckMemoryAccessRights(GetSession(), CMD_TEE_CheckMemoryAccessRights, &value);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_CheckMemoryAccessRights_With_Access_Write_Flag
 * @testcase.desc      : test TA call TEE_CheckMemoryAccessRights to check buffer whether has Access_Write right
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TCF2Test, TEE_CheckMemoryAccessRights_With_Access_Write_Flag, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };

    value.oldSize = TESTSIZE;
    value.accessFlags = TEE_MEMORY_ACCESS_WRITE;
    ret = Invoke_CheckMemoryAccessRights(GetSession(), CMD_TEE_CheckMemoryAccessRights, &value);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_CheckMemoryAccessRights_With_BufferIsFree
 * @testcase.desc      : test TA call TEE_CheckMemoryAccessRights to check buffer while assigned buffer is freeed
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TCF2Test, TEE_CheckMemoryAccessRights_With_BufferIsFree, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };

    value.oldSize = TESTSIZE;
    value.accessFlags = TEE_MEMORY_ACCESS_READ;
    value.caseId = BUFFER_IS_FREE;
    ret = Invoke_CheckMemoryAccessRights(GetSession(), CMD_TEE_CheckMemoryAccessRights, &value);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_CheckMemoryAccessRights_With_BufferIsNotMalloc
 * @testcase.desc      : test TA call TEE_CheckMemoryAccessRights while buffer is not alloced,it is on stack
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TCF2Test, TEE_CheckMemoryAccessRights_With_BufferIsNotMalloc, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };

    value.oldSize = TESTSIZE;
    value.accessFlags = TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_WRITE;
    value.caseId = BUFFER_ISNOT_MALLOC;
    ret = Invoke_CheckMemoryAccessRights(GetSession(), CMD_TEE_CheckMemoryAccessRights, &value);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_CheckMemoryAccessRights_With_SizeIsZero
 * @testcase.desc      : test TA call TEE_CheckMemoryAccessRights to check buffer while size is zero
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TCF2Test, TEE_CheckMemoryAccessRights_With_SizeIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };

    value.oldSize = TESTSIZE;
    value.accessFlags = TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_WRITE;
    value.caseId = OUTPUTBUFFERSIZE_ISZERO;
    ret = Invoke_CheckMemoryAccessRights(GetSession(), CMD_TEE_CheckMemoryAccessRights, &value);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_CheckMemoryAccessRights_With_GlobalVar
 * @testcase.desc      : test TA call TEE_CheckMemoryAccessRights while buffer is global variable
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TCF2Test, TEE_CheckMemoryAccessRights_With_GlobalVar, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };

    value.oldSize = TESTSIZE;
    value.accessFlags = TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_WRITE;
    value.caseId = BUFFER_IS_GLOBALVAR;
    ret = Invoke_CheckMemoryAccessRights(GetSession(), CMD_TEE_CheckMemoryAccessRights, &value);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_CheckMemoryAccessRights_With_ReadRight_GlobalConstVar
 * @testcase.desc      : test TA call TEE_CheckMemoryAccessRights while buffer is global variable
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TCF2Test, TEE_CheckMemoryAccessRights_With_ReadRight_GlobalConstVar, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };

    value.oldSize = TESTSIZE;
    value.accessFlags = TEE_MEMORY_ACCESS_READ;
    value.caseId = BUFFER_IS_GLOBALCONSTVAR;
    ret = Invoke_CheckMemoryAccessRights(GetSession(), CMD_TEE_CheckMemoryAccessRights, &value);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_SUCCESS);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_CheckMemoryAccessRights_With_Access_AnyOwner_Flag
 * @testcase.desc      : test TA call TEE_CheckMemoryAccessRights to check buffer whether has Access_AnyOwner right
 * @testcase.expect    : return TEEC_ERROR_ACCESS_DENIED
 */
TEE_TEST(TCF2Test, TEE_CheckMemoryAccessRights_With_Access_AnyOwner_Flag, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };

    value.oldSize = TESTSIZE;
    value.accessFlags = TEE_MEMORY_ACCESS_ANY_OWNER;
    ret = Invoke_CheckMemoryAccessRights(GetSession(), CMD_TEE_CheckMemoryAccessRights, &value);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_ERROR_ACCESS_DENIED);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_CheckMemoryAccessRights_With_FlagIsZero
 * @testcase.desc      : test TA call TEE_CheckMemoryAccessRights to check buffer while flag is zero
 * @testcase.expect    : return TEEC_ERROR_ACCESS_DENIED
 */
TEE_TEST(TCF2Test, TEE_CheckMemoryAccessRights_With_FlagIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };

    value.oldSize = TESTSIZE;
    value.accessFlags = 0;
    ret = Invoke_CheckMemoryAccessRights(GetSession(), CMD_TEE_CheckMemoryAccessRights, &value);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_ERROR_ACCESS_DENIED);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_CheckMemoryAccessRights_With_BufferIsNull
 * @testcase.desc      : test TA call TEE_CheckMemoryAccessRights to check buffer while assigned buffer is null
 * @testcase.expect    : return TEEC_ERROR_ACCESS_DENIED
 */
TEE_TEST(TCF2Test, TEE_CheckMemoryAccessRights_With_BufferIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };

    value.oldSize = TESTSIZE;
    value.accessFlags = TEE_MEMORY_ACCESS_READ;
    value.caseId = INPUT_ISNULL;
    ret = Invoke_CheckMemoryAccessRights(GetSession(), CMD_TEE_CheckMemoryAccessRights, &value);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_ERROR_ACCESS_DENIED);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_CheckMemoryAccessRights_With_BufferIsParam
 * @testcase.desc      : test TA call TEE_CheckMemoryAccessRights to check buffer while assigned buffer is param type
 * @testcase.expect    : return TEEC_ERROR_ACCESS_DENIED
 */
TEE_TEST(TCF2Test, TEE_CheckMemoryAccessRights_With_BufferIsParam, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };

    value.oldSize = TESTSIZE;
    value.accessFlags = TEE_MEMORY_ACCESS_READ;
    value.caseId = BUFFER_IS_PARAM;
    ret = Invoke_CheckMemoryAccessRights(GetSession(), CMD_TEE_CheckMemoryAccessRights, &value);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_ERROR_ACCESS_DENIED);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_CheckMemoryAccessRights_With_WriteRight_GlobalConstVar
 * @testcase.desc      : test TA call TEE_CheckMemoryAccessRights while buffer is global variable
 * @testcase.expect    : return TEEC_ERROR_ACCESS_DENIED
 */
TEE_TEST(TCF2Test, TEE_CheckMemoryAccessRights_With_WriteRight_GlobalConstVar, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };

    value.oldSize = TESTSIZE;
    value.accessFlags = TEE_MEMORY_ACCESS_WRITE;
    value.caseId = BUFFER_IS_GLOBALCONSTVAR;
    ret = Invoke_CheckMemoryAccessRights(GetSession(), CMD_TEE_CheckMemoryAccessRights, &value);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_ERROR_ACCESS_DENIED);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_CheckMemoryAccessRights_With_SizeIsTooBig
 * @testcase.desc      : test TA call TEE_CheckMemoryAccessRights to check buffer while size is too big
 * @testcase.expect    : return TEEC_ERROR_ACCESS_DENIED
 */
TEE_TEST(TCF2Test, TEE_CheckMemoryAccessRights_With_SizeIsTooBig, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };

    value.oldSize = TESTSIZE;
    value.accessFlags = TEE_MEMORY_ACCESS_READ | TEE_MEMORY_ACCESS_WRITE;
    value.caseId = BUFFERSIZE_ISTOOBIG;
    ret = Invoke_CheckMemoryAccessRights(GetSession(), CMD_TEE_CheckMemoryAccessRights, &value);
#ifndef TEST_STUB
    ASSERT_EQ(ret, TEEC_ERROR_ACCESS_DENIED);
#else
    ASSERT_EQ(ret, TEEC_ERROR_NOT_SUPPORTED);
#endif
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}