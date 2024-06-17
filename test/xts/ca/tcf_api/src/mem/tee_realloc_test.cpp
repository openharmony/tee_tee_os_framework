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
 * @testcase.name      : TEE_Realloc_With_NewSizeIsZero
 * @testcase.desc      : test TA call TEE_Realloc to alloc buffer with newsize is 0
 * @testcase.expect    : return TEEC_ERROR_OUT_OF_MEMORY
 */
TEE_TEST(TCF2Test, TEE_Realloc_With_NewSizeIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };
    char outBuf[TESTSIZE] = { 0 };

    value.oldSize = TESTSIZE;
    value.newSize = 0;
    ret = Invoke_Realloc(GetSession(), CMD_TEE_Realloc, &value, outBuf);
    ASSERT_EQ(ret, TEEC_ERROR_OUT_OF_MEMORY);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_Realloc_With_SizeExceedHeapLimit
 * @testcase.desc      : test TA call TEE_Realloc to alloc buffer with newsize exceed heaplimit
 * @testcase.expect    : return TEEC_ERROR_OUT_OF_MEMORY
 */
TEE_TEST(TCF2Test, TEE_Realloc_With_SizeExceedHeapLimit, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };
    char outBuf[TESTSIZE] = { 0 };

    uint32_t dateSize = get_ta_data_size(GetContext(), GetSession());
    ASSERT_GT(dateSize, 0);

    uint32_t stackSize = get_ta_stack_size(GetContext(), GetSession());
    ASSERT_GT(stackSize, 0);

    value.oldSize = TESTSIZE;
    value.newSize = dateSize + stackSize;
    ret = Invoke_Realloc(GetSession(), CMD_TEE_Realloc, &value, outBuf);
    ASSERT_EQ(ret, TEEC_ERROR_OUT_OF_MEMORY);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_Realloc_With_BufferIsNull
 * @testcase.desc      : test TA call TEE_Realloc to alloc buffer with buffer is null
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TCF2Test, TEE_Realloc_With_BufferIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };
    char outBuf[TESTSIZE + 1] = { 0 };

    value.oldSize = TESTSIZE;
    value.newSize = TESTSIZE;
    value.caseId = INPUT_ISNULL;
    ret = Invoke_Realloc(GetSession(), CMD_TEE_Realloc, &value, outBuf);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_NE(value.oldAddr, value.newAddr);
    ASSERT_STREQ(outBuf, EXPECTBUFFER_A);
}

/**
 * @testcase.name      : TEE_Realloc_With_SameSize
 * @testcase.desc      : test TA call TEE_Realloc to alloc buffer with newsize is same as oldsize
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TCF2Test, TEE_Realloc_With_SameSize, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };
    char outBuf[TESTSIZE + 1] = { 0 };

    value.oldSize = TESTSIZE;
    value.newSize = TESTSIZE;
    ret = Invoke_Realloc(GetSession(), CMD_TEE_Realloc, &value, outBuf);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(value.oldAddr, value.newAddr);
    ASSERT_STREQ(outBuf, EXPECTBUFFER_A);
}

/**
 * @testcase.name      : TEE_Realloc_With_LessSize
 * @testcase.desc      : test TA call TEE_Realloc to alloc buffer with newsize is less than oldsize
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TCF2Test, TEE_Realloc_With_LessSize, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };
    char outBuf[TESTSIZE] = { 0 };

    value.oldSize = TESTSIZE;
    value.newSize = TESTSIZE - 1;
    ret = Invoke_Realloc(GetSession(), CMD_TEE_Realloc, &value, outBuf);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(value.oldAddr, value.newAddr);
    ASSERT_STREQ(outBuf, EXPECTBUFFER_A_LESS);
}

/**
 * @testcase.name      : TEE_Realloc_With_GreaterSize
 * @testcase.desc      : test TA call TEE_Realloc to alloc buffer with newsize is greater than oldsize
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TCF2Test, TEE_Realloc_With_GreaterSize, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };
    char outBuf[BIG_SIZE] = { 0 };
    uint32_t i;

    value.oldSize = TESTSIZE;
    value.newSize = BIG_SIZE;
    ret = Invoke_Realloc(GetSession(), CMD_TEE_Realloc, &value, outBuf);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(outBuf, EXPECTBUFFER_A);

    for (i = TESTSIZE; i < BIG_SIZE; i++) {
        ASSERT_EQ(outBuf[i], 0);
    }
}
