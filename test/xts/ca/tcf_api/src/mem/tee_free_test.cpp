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
 * @testcase.name      : TEE_Free_With_BufferIsNull
 * @testcase.desc      : test TA call TEE_Free to while buff is null
 * @testcase.expect    : return TEEC_SUCCESS
*/
TEE_TEST(TCF2Test, TEE_Free_With_BufferIsNull, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    uint32_t caseId = INPUT_ISNULL;

    ret = Invoke_Free(GetSession(), CMD_TEE_Free, caseId, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : TEE_Free_With_Normal
 * @testcase.desc      : test TA call TEE_Free after normal TEE_Malloc
 * @testcase.expect    : return TEEC_SUCCESS
*/
TEE_TEST(TCF2Test, TEE_Free_With_Normal, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    uint32_t caseId = 0;

    ret = Invoke_Free(GetSession(), CMD_TEE_Free, caseId, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}
