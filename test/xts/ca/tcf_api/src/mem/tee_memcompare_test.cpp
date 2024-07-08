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
 * @testcase.name      : TEE_MemCompare_With_Same
 * @testcase.desc      : test TA call TEE_MemCompare to compare buffer1 and buffer2
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2Test, TEE_MemCompare_With_Same, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t i;
    TestMemData value = { 0 };
    char buf1[TESTSIZE] = { 0 };
    char buf2[TESTSIZE] = { 0 };

    value.oldSize = TESTSIZE;
    for (i = 0; i < TESTSIZE; i++) {
        buf1[i] = (char)'A';
        buf2[i] = (char)'A';
    }
    ret = Invoke_MemCompare(GetSession(), CMD_TEE_MemCompare, &value, buf1, buf2);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_MemCompare_With_Buffer1LessBuffer2
 * @testcase.desc      : test TA call TEE_MemCompare to compare buffer1 and buffer2, buffer1 < buffer2
 * @testcase.expect    : return -1
 */
TEE_TEST(TeeTCF2Test, TEE_MemCompare_With_Buffer1LessBuffer2, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t i;
    TestMemData value = { 0 };
    char buf1[TESTSIZE] = { 0 };
    char buf2[TESTSIZE] = { 0 };

    value.oldSize = TESTSIZE;
    for (i = 0; i < TESTSIZE - 1; i++) {
        buf1[i] = (char)'A';
        buf2[i] = (char)'A';
    }
    buf1[TESTSIZE - 1] = (char)'A';
    buf2[TESTSIZE - 1] = (char)'B';

    ret = Invoke_MemCompare(GetSession(), CMD_TEE_MemCompare, &value, buf1, buf2);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_MemCompare_With_Buffer1GreaterBuffer2
 * @testcase.desc      : test TA call TEE_MemCompare to compare buffer1 and buffer2, buffer1 > buffer2
 * @testcase.expect    : return -1
 */
TEE_TEST(TeeTCF2Test, TEE_MemCompare_With_Buffer1GreaterBuffer2, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t i;
    TestMemData value = { 0 };
    char buf1[TESTSIZE] = { 0 };
    char buf2[TESTSIZE] = { 0 };

    value.oldSize = TESTSIZE;
    for (i = 0; i < TESTSIZE - 1; i++) {
        buf1[i] = (char)'A';
        buf2[i] = (char)'A';
    }
    buf1[TESTSIZE - 1] = (char)'B';
    buf2[TESTSIZE - 1] = (char)'A';

    ret = Invoke_MemCompare(GetSession(), CMD_TEE_MemCompare, &value, buf1, buf2);
    ASSERT_EQ(ret, 1);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_MemCompare_With_Buffer1IsNull
 * @testcase.desc      : test TA call TEE_MemCompare compare while buffer1 is null
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2Test, TEE_MemCompare_With_Buffer1IsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t i;
    TestMemData value = { 0 };
    char buf1[TESTSIZE] = { 0 };
    char buf2[TESTSIZE] = { 0 };

    value.oldSize = TESTSIZE;
    for (i = 0; i < TESTSIZE; i++) {
        buf1[i] = (char)'A';
        buf2[i] = (char)'A';
    }
    value.caseId = INPUT_ISNULL;
    ret = Invoke_MemCompare(GetSession(), CMD_TEE_MemCompare, &value, buf1, buf2);
    ASSERT_EQ(ret, -1);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_MemCompare_With_Buffer2IsNull
 * @testcase.desc      : test TA call TEE_MemCompare compare while buffer2 is null
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2Test, TEE_MemCompare_With_Buffer2IsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t i;
    TestMemData value = { 0 };
    char buf1[TESTSIZE] = { 0 };
    char buf2[TESTSIZE] = { 0 };

    value.oldSize = TESTSIZE;
    for (i = 0; i < TESTSIZE; i++) {
        buf1[i] = (char)'A';
        buf2[i] = (char)'A';
    }
    value.caseId = OUTPUT_ISNULL;
    ret = Invoke_MemCompare(GetSession(), CMD_TEE_MemCompare, &value, buf1, buf2);
    ASSERT_EQ(ret, 1);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_MemCompare_With_SizeIsZero
 * @testcase.desc      : test TA call TEE_MemCompare compare while size is zero
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2Test, TEE_MemCompare_With_SizeIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t i;
    TestMemData value = { 0 };
    char buf1[TESTSIZE] = { 0 };
    char buf2[TESTSIZE] = { 0 };

    value.oldSize = 0;
    for (i = 0; i < TESTSIZE; i++) {
        buf1[i] = (char)'A';
        buf2[i] = (char)'B';
    }

    ret = Invoke_MemCompare(GetSession(), CMD_TEE_MemCompare, &value, buf1, buf2);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
}
