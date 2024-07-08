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
 * @testcase.name      : TEE_Set_And_GetInstanceData_With_Success
 * @testcase.desc      : test TA call TEE_SetInstanceData and TEE_GetInstanceData to use instance data
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2Test, TEE_Set_And_GetInstanceData_With_Success, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    char inBuf[] = { 'T', 'E', 'E', 'A', '\0', };
    char outBuf[BIG_SIZE] = { 0 };
    uint32_t caseId = 0;
    uint32_t outLen = sizeof(outBuf);

    ret = Invoke_SetInstanceData(GetSession(), CMD_TEE_SetInstanceData, inBuf, caseId, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);

    ret = Invoke_GetInstanceData(GetSession(), CMD_TEE_GetInstanceData, outBuf, &outLen, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_STREQ(inBuf, outBuf);
    ASSERT_EQ(outLen, strlen(inBuf) + 1);
}

/**
 * @testcase.name      : TEE_Set_And_GetInstanceData_With_InstanceDataIsNull
 * @testcase.desc      : test TA call TEE_SetInstanceData and TEE_GetInstanceData to use instance data is null
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2Test, TEE_Set_And_GetInstanceData_With_InstanceDataIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    char inBuf[] = { 'T', 'E', 'E', 'A', '\0', };
    char outBuf[BIG_SIZE] = { 0 };
    uint32_t caseId = INPUT_ISNULL;
    uint32_t outLen = sizeof(outBuf);

    ret = Invoke_SetInstanceData(GetSession(), CMD_TEE_SetInstanceData, inBuf, caseId, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);

    ret = Invoke_GetInstanceData(GetSession(), CMD_TEE_GetInstanceData, outBuf, &outLen, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_GENERIC);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_Set_And_GetInstanceData_With_GetSizeTooShort
 * @testcase.desc      : test TA call TEE_SetInstanceData and TEE_GetInstanceData to use instancedata while get size
 * too short
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(TeeTCF2Test, TEE_Set_And_GetInstanceData_With_GetSizeTooShort, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    char inBuf[] = { 'T', 'E', 'E', 'A', '\0', };
    char outBuf[BIG_SIZE] = { 0 };
    uint32_t caseId = 0;
    uint32_t outLen = strlen(inBuf) - 1;

    ret = Invoke_SetInstanceData(GetSession(), CMD_TEE_SetInstanceData, inBuf, caseId, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);

    ret = Invoke_GetInstanceData(GetSession(), CMD_TEE_GetInstanceData, outBuf, &outLen, &origin);
    ASSERT_EQ(ret, TEEC_ERROR_SHORT_BUFFER);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
    ASSERT_EQ(outLen, strlen(inBuf) + 1);
}
