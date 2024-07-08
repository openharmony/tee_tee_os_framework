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

using namespace std;
using namespace testing::ext;

/**
 * @testcase.name      : TEE_Panic_With_Normal
 * @testcase.desc      : test TA call TEE_Panic to make ta panic
 * @testcase.expect    : return TEEC_ERROR_TARGET_DEAD
 */
TEE_TEST(TeeTCF1Test, TEE_Panic_With_Normal, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    TEEC_Result panicCode = TEEC_ERROR_GENERIC;

    ret = Invoke_Panic(GetSession(), CMD_TEE_Panic, panicCode, &origin);
#ifndef TEST_STUB   
    ASSERT_EQ(ret, TEEC_ERROR_TARGET_DEAD);
    ASSERT_EQ(origin, TEEC_ORIGIN_TEE);
#else
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
#endif
}

/**
 * @testcase.name      : TEE_Panic_With_MultiSession
 * @testcase.desc      : test TA call TEE_Panic to make a multisession ta panic
 * @testcase.expect    : return TEEC_ERROR_TARGET_DEAD,invoke other tasession will return TEEC_ERROR_ITEM_NOT_FOUND
 */
TEE_TEST(TeeTCF2TA2TATest, TEE_Panic_With_MultiSession, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t ta2taSession[8] = { 0 };
    uint32_t origin = 0;
    int i;
    TestData value = { 0 };
    value.caseId = 0;
    value.uuid = TCF_API_UUID_1; // this uuid is for ta2
    value.inBufferLen = BIG_SIZE;
    value.outBufferLen = BIG_SIZE;

    for (i = 0; i <= 6; i++) {
        ret = Invoke_OpenTASession(GetSession(), CMD_TEE_OpenTASession, &ta2taSession[i], &value, &origin);
        ASSERT_EQ(ret, TEEC_SUCCESS);
        ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
        ASSERT_EQ(value.origin, TEEC_ORIGIN_TEE);
        ASSERT_NE(ta2taSession[i], 0);
        if (i >= 1)
            ASSERT_NE(ta2taSession[i], ta2taSession[i - 1]);
    }
#ifndef TEST_STUB
    // make ta2 one session panic
    TEEC_Result panicCode = TEEC_ERROR_GENERIC;
    ret = Invoke_Panic(GetSession2(), CMD_TEE_Panic, panicCode, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_TARGET_DEAD);
    ASSERT_EQ(origin, TEEC_ORIGIN_TEE);

    for (i = 0; i <= 6; i++) {
        ret = Invoke_InvokeTACommand(GetSession(), CMD_TEE_InvokeTACommand, ta2taSession[i], &value, &origin);
        ASSERT_EQ(ret, TEEC_ERROR_ITEM_NOT_FOUND);
        ASSERT_EQ(origin, TEEC_ORIGIN_TEE);
    }
#endif
}
