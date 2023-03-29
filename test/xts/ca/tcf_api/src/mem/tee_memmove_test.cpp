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
 * @testcase.name      : TEE_MemMove_With_Success
 * @testcase.desc      : test TA call TEE_MemMove to move buffer from src to dest
 * @testcase.expect    : return TEEC_SUCCESS, dest buffer is same as src buffer
 */
TEE_TEST(TCF2Test, TEE_MemMove_With_Success, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };
    char outBuf[TESTSIZE + 1] = {0};

    value.oldSize = TESTSIZE;
    ret = Invoke_MemMove_Or_Fill(GetSession(), CMD_TEE_MemMove, &value, outBuf);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(outBuf, EXPECTBUFFER_A);
}

/**
 * @testcase.name      : TEE_MemMove_With_SrcBufferIsNull
 * @testcase.desc      : test TA call TEE_MemMove to move buffer while srcbuffer is null
 * @testcase.expect    : return TEEC_SUCCESS, dest buffer is not same as src buffer
 */
TEE_TEST(TCF2Test, TEE_MemMove_With_SrcBufferIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };
    char outBuf[TESTSIZE + 1] = { 0 };

    value.oldSize = TESTSIZE;
    value.caseId = INPUT_ISNULL;
    ret = Invoke_MemMove_Or_Fill(GetSession(), CMD_TEE_MemMove, &value, outBuf);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(outBuf, EXPECTBUFFER_B);
}

/**
 * @testcase.name      : TEE_MemMove_With_DestBufferIsNull
 * @testcase.desc      : test TA call TEE_MemMove to move buffer while destbuffer is null
 * @testcase.expect    : return TEEC_SUCCESS, dest buffer is not same as src buffer
 */
TEE_TEST(TCF2Test, TEE_MemMove_With_DestBufferIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };
    char outBuf[TESTSIZE + 1] = { 0 };

    value.oldSize = TESTSIZE;
    value.caseId = OUTPUT_ISNULL;
    ret = Invoke_MemMove_Or_Fill(GetSession(), CMD_TEE_MemMove, &value, outBuf);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(outBuf, EXPECTBUFFER_B);
}

/**
 * @testcase.name      : TEE_MemMove_With_SizeIsZero
 * @testcase.desc      : test TA call TEE_MemMove to move buffer while size is zero
 * @testcase.expect    : return TEEC_SUCCESS, dest buffer is not same as src buffer
 */
TEE_TEST(TCF2Test, TEE_MemMove_With_SizeIsZero, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };
    char outBuf[TESTSIZE + 1] = { 0 };

    value.oldSize = TESTSIZE;
    value.caseId = OUTPUTBUFFERSIZE_ISZERO;
    ret = Invoke_MemMove_Or_Fill(GetSession(), CMD_TEE_MemMove, &value, outBuf);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(outBuf, EXPECTBUFFER_B);
}

/**
 * @testcase.name      : TEE_MemMove_With_DestIsSameAsSrc
 * @testcase.desc      : test TA call TEE_MemMove to move buffer while destbuffer addr is same as srcbuffer addr
 * @testcase.expect    : return TEEC_SUCCESS, dest buffer is not same as src buffer
 */
TEE_TEST(TCF2Test, TEE_MemMove_With_DestIsSameAsSrc, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };
    char outBuf[TESTSIZE + 1] = { 0 };

    value.oldSize = TESTSIZE;
    value.caseId = DESTANDSRC_ISSAME;
    ret = Invoke_MemMove_Or_Fill(GetSession(), CMD_TEE_MemMove, &value, outBuf);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(outBuf, EXPECTBUFFER_B);
}

/**
 * @testcase.name      : TEE_MemMove_With_Overlap
 * @testcase.desc      : test TA call TEE_MemMove to move buffer while src buffer and dest buffer is overlap
 * @testcase.expect    : return TEEC_SUCCESS, dest buffer is same as src buffer
 */
TEE_TEST(TCF2Test, TEE_MemMove_With_Overlap, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    TestMemData value = { 0 };
    char outBuf[TESTSIZE + 1] = { 0 };

    value.oldSize = TESTSIZE;
    value.caseId = DESTANDSRC_OVERLAP;
    ret = Invoke_MemMove_Or_Fill(GetSession(), CMD_TEE_MemMove, &value, outBuf);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(value.origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(outBuf, EXPECTBUFFER_OVERLAP);
}