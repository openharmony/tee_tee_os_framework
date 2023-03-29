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

#ifndef __TRUSTED_STORAGE_COMMON_TEST_H__
#define __TRUSTED_STORAGE_COMMON_TEST_H__

#include <public_test.h>
#include <session_mgr/client_session_mgr.h>

#define TRUSTED_STORAGE_API_UUID                           \
    {                                                      \
        0x09090909, 0x0808, 0x0707,                        \
        {                                                  \
            0x03, 0x03, 0x03, 0x03, 0x05, 0x07, 0x09, 0x01 \
        }                                                  \
    }

#define FUN_NAME_LEN 64
enum TEST_TRUSTED_STORAGE_API_CMD_ID {
    CMD_RUN_BY_FUN_SEQ = 0,
};

class TrustedStorageTest : public EmptyTest {
protected:
    ClientSessionMgr session;
    TEEC_Operation operation = { 0 };
    uint32_t origin;
    ClientShareMemMgr testMem;

public:
    void SetUp();
    void TearDown();
    TEEC_Result InvokeTest(const char *casename);
};

#define TRUSTED_STORAGE_TEST_EQ(casename)                                   \
    TEE_TEST(TrustedStorageTest, casename, Function | MediumTest | Level0)  \
    {                                                                       \
        TEEC_Result ret = InvokeTest(#casename);                            \
        ASSERT_EQ(ret, TEEC_SUCCESS);                                       \
    }

#define TRUSTED_STORAGE_TEST_NE(casename)                                   \
    TEE_TEST(TrustedStorageTest, casename, Function | MediumTest | Level0)  \
    {                                                                       \
        TEEC_Result ret = InvokeTest(#casename);                            \
        ASSERT_NE(ret, TEEC_SUCCESS);                                       \
    }
#endif
