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
#include <stdlib.h>
#include <tee_client_api.h>
#include <tee_client_type.h>
#include <test_defines.h>
#include <test_log.h>
#include <test_tcf_cmdid.h>

using namespace testing::ext;
/**
 * @testcase.name      : TEE_Malloc_With_TEE_MALLOC_FILL_ZERO
 * @testcase.desc      : test TA call TEE_Malloc to alloc buffer 16 bytes with hint is TEE_MALLOC_FILL_ZERO
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2Test, TEE_Malloc_With_TEE_MALLOC_FILL_ZERO, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    char *buffer = reinterpret_cast<char *>(malloc(MAX_SHARE_SIZE));
    ASSERT_STRNE(buffer, NULL);
    (void)memset_s(buffer, TESTSIZE, 0x41, TESTSIZE); // 0x41 = 'A'

    TestMemData value = { 0 };
    value.inMemSize = TESTSIZE;
    value.inHint = TEE_MALLOC_FILL_ZERO;
    value.testBuffer = buffer;
    ret = Invoke_Malloc(GetSession(), CMD_TEE_Malloc, &value, &origin);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_STREQ(buffer, EXPECTBUFFER_ZERO);
    free(buffer);
}

/**
 * @testcase.name      : TEE_Malloc_With_TEE_MALLOC_NO_FILL
 * @testcase.desc      : test TA call TEE_Malloc to alloc buffer 16 bytes with hint is TEE_MALLOC_NO_FILL, not support
 * @testcase.expect    : return TEEC_ERROR_GENERIC
 */
TEE_TEST(TeeTCF2Test, TEE_Malloc_With_TEE_MALLOC_NO_FILL, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    char *buffer = reinterpret_cast<char *>(malloc(MAX_SHARE_SIZE));
    ASSERT_STRNE(buffer, NULL);
    (void)memset_s(buffer, TESTSIZE, 0x41, TESTSIZE); // 0x41 = 'A'

    TestMemData value = { 0 };
    value.inMemSize = TESTSIZE;
    value.inHint = TEE_MALLOC_NO_FILL;
    value.testBuffer = buffer;
    ret = Invoke_Malloc(GetSession(), CMD_TEE_Malloc, &value, &origin);
    EXPECT_EQ(ret, TEEC_ERROR_GENERIC);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_STREQ(buffer, EXPECTBUFFER_A);
    free(buffer);
}

/**
 * @testcase.name      : TEE_Malloc_With_TEE_MALLOC_NO_SHARE
 * @testcase.desc      : test TA call TEE_Malloc to alloc buffer 16 bytes with hint is TEE_MALLOC_NO_SHARE
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2Test, TEE_Malloc_With_TEE_MALLOC_NO_SHARE, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    char *buffer = reinterpret_cast<char *>(malloc(MAX_SHARE_SIZE));
    ASSERT_STRNE(buffer, NULL);
    (void)memset_s(buffer, TESTSIZE, 0x41, TESTSIZE); // 0x41 = 'A'

    TestMemData value = { 0 };
    value.inMemSize = TESTSIZE;
    value.inHint = TEE_MALLOC_NO_SHARE;
    value.testBuffer = buffer;
    ret = Invoke_Malloc(GetSession(), CMD_TEE_Malloc, &value, &origin);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_STRNE(buffer, EXPECTBUFFER_A);
    free(buffer);
}

/**
 * @testcase.name      : TEE_Malloc_With_TEE_MALLOC_NO_FILL_And_NO_SHARE
 * @testcase.desc      : test TA call TEE_Malloc to alloc 16 bytes with hint is TEE_MALLOC_NO_FILL|TEE_MALLOC_NO_SHARE
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2Test, TEE_Malloc_With_TEE_MALLOC_NO_FILL_And_NO_SHARE, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    char *buffer = reinterpret_cast<char *>(malloc(MAX_SHARE_SIZE));
    ASSERT_STRNE(buffer, NULL);
    (void)memset_s(buffer, TESTSIZE, 0x41, TESTSIZE); // 0x41 = 'A'

    TestMemData value = { 0 };
    value.inMemSize = TESTSIZE;
    value.inHint = TEE_MALLOC_NO_FILL | TEE_MALLOC_NO_SHARE;
    value.testBuffer = buffer;
    ret = Invoke_Malloc(GetSession(), CMD_TEE_Malloc, &value, &origin);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_STRNE(buffer, EXPECTBUFFER_A);
    free(buffer);
}

/**
 * @testcase.name      : TEE_Malloc_With_HINT_RESERVE
 * @testcase.desc      : test TA call TEE_Malloc to alloc buffer 16 bytes with hint is HINT_RESERVE
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2Test, TEE_Malloc_With_HINT_RESERVE, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    char *buffer = reinterpret_cast<char *>(malloc(MAX_SHARE_SIZE));
    ASSERT_STRNE(buffer, NULL);
    (void)memset_s(buffer, TESTSIZE, 0x41, TESTSIZE); // 0x41 = 'A'

    TestMemData value = { 0 };
    value.inMemSize = TESTSIZE;
    value.inHint = HINT_RESERVE;
    value.testBuffer = buffer;
    ret = Invoke_Malloc(GetSession(), CMD_TEE_Malloc, &value, &origin);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_STRNE(buffer, EXPECTBUFFER_A);
    free(buffer);
}

/**
 * @testcase.name      : TEE_Malloc_With_SIZEIsZero
 * @testcase.desc      : test TA call TEE_Malloc to alloc buffer with size is zero
 * @testcase.expect    : return TEEC_ERROR_GENERIC
 */
TEE_TEST(TeeTCF2Test, TEE_Malloc_With_SizeIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    char *buffer = reinterpret_cast<char *>(malloc(MAX_SHARE_SIZE));
    ASSERT_STRNE(buffer, NULL);
    (void)memset_s(buffer, TESTSIZE, 0x0, TESTSIZE);

    TestMemData value = { 0 };
    value.inMemSize = 0;
    value.inHint = TEE_MALLOC_FILL_ZERO;
    value.testBuffer = buffer;
    ret = Invoke_Malloc(GetSession(), CMD_TEE_Malloc, &value, &origin);
    EXPECT_EQ(ret, TEEC_ERROR_GENERIC);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    free(buffer);
}

/**
 * @testcase.name      : TEE_Malloc_With_SizeExceedHeapLimit
 * @testcase.desc      : test TA call TEE_Malloc to alloc buffer with size exceed heaplimit
 * @testcase.expect    : return TEEC_ERROR_OUT_OF_MEMORY
 */
TEE_TEST(TeeTCF2Test, TEE_Malloc_With_SizeExceedHeapLimit, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    char *buffer = reinterpret_cast<char *>(malloc(MAX_SHARE_SIZE));
    ASSERT_STRNE(buffer, NULL);
    (void)memset_s(buffer, TESTSIZE, 0x0, TESTSIZE);

    uint32_t dateSize = get_ta_data_size(GetContext(), GetSession());
    EXPECT_GT(dateSize, 0);

    uint32_t stackSize = get_ta_stack_size(GetContext(), GetSession());
    EXPECT_GT(stackSize, 0);

    TestMemData value = { 0 };
    value.inMemSize = dateSize + stackSize;
    value.inHint = TEE_MALLOC_FILL_ZERO;
    value.testBuffer = buffer;
    ret = Invoke_Malloc(GetSession(), CMD_TEE_Malloc, &value, &origin);
    EXPECT_EQ(ret, TEEC_ERROR_OUT_OF_MEMORY);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    free(buffer);
}

/**
 * @testcase.name      : TEE_Malloc_With_MAXDataSize
 * @testcase.desc      : test TA call TEE_Malloc to alloc buffer with size is max data size
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF1Test, TEE_Malloc_With_MAXDataSize, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    char *buffer = reinterpret_cast<char *>(malloc(MAX_SHARE_SIZE));
    ASSERT_STRNE(buffer, NULL);
    (void)memset_s(buffer, TESTSIZE, 0x41, TESTSIZE); // 0x41 = 'A'

    uint32_t dateSize = get_ta_data_size(GetContext(), GetSession());
    EXPECT_GT(dateSize, 0);

    TestMemData value = { 0 };
    value.inMemSize = dateSize;
    value.inHint = TEE_MALLOC_FILL_ZERO;
    value.testBuffer = buffer;
    ret = Invoke_Malloc(GetSession(), CMD_TEE_Malloc, &value, &origin);
    EXPECT_EQ(ret, TEEC_SUCCESS);
    EXPECT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    EXPECT_STREQ(buffer, EXPECTBUFFER_ZERO);
    free(buffer);
}
