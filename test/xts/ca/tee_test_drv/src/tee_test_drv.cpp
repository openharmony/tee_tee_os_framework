/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <gtest/gtest.h>

#include <public_test.h>
#include <test_log.h>
#include <securec.h>

#include "tee_test_drv.h"
#include <session_mgr/client_session_mgr.h>
#include <test_drv_cmdid.h>

using namespace std;
using namespace testing::ext;
/**
 * @testcase.name      : DrvAPITest_Drv_Virt_To_Phys
 * @testcase.desc      : test drv call drv_virt_to_phys api
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, DrvAPITest_Drv_Virt_To_Phys, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = DRVCALLER_UUID;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, DRVTEST_COMMAND_DRVVIRTTOPHYS, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : DrvAPITest_Copy_From_Client
 * @testcase.desc      : test drv call copy_from_client api
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, DrvAPITest_Copy_From_Client, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = DRVCALLER_UUID;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, DRVTEST_COMMAND_COPYFROMCLIENT, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}

/**
 * @testcase.name      : DrvAPITest_Copy_To_Client
 * @testcase.desc      : test drv call copy_to_client api
 * @testcase.expect    : return TEEC_SUCCESS
 */
TEE_TEST(EmptyTest, DrvAPITest_Copy_To_Client, Function | MediumTest | Level0)
{
    TEEC_Result ret;
    uint32_t origin;
    ClientSessionMgr sess;
    TEEC_UUID testId = DRVCALLER_UUID;
    ret = sess.Start(&testId);
    EXPECT_EQ(ret, TEEC_SUCCESS);

    ret = TEEC_InvokeCommand(&sess.session, DRVTEST_COMMAND_COPYTOCLIENT, NULL, &origin);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    ASSERT_EQ(origin, TEEC_ORIGIN_TRUSTED_APP);
}