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

#include <session_mgr/client_session_mgr.h>

using namespace std;
using namespace testing::ext;

TEE_TEST(PublicTest, MyTest_001, Function | MediumTest | Level0)
{
    TEEC_UUID testId = TEST_UUID;

    TEEC_Result ret;
    ClientSessionMgr sess;
    ret = sess.Start(&testId);

    EXPECT_EQ(ret, TEEC_SUCCESS);
    if (ret != TEEC_SUCCESS)
        TEST_PRINT_ERROR("StartGlobalSession fail ,retcode: 0x%x", ret);

    sess.Destroy();
    TEST_PRINT_INFO("DestroyGlobalSession succeed");
}
