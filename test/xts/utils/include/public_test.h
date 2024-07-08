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

#ifndef __PUBLIC_TEST_H__
#define __PUBLIC_TEST_H__

#include "empty_test.h"

#include <securec.h>
#include <tee_client_api.h>
#include <tee_client_type.h>

#define TEST_UUID                                          \
    {                                                      \
        0x11111111, 0x0000, 0x0000,                        \
        {                                                  \
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 \
        }                                                  \
    }

class PublicTest : public TeeBasicTestFram {
private:
    static TEEC_Context context;
    static TEEC_Session session;
    static TEEC_UUID uuid;

public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    static void SetUuid(const TEEC_UUID &uuid);

    TEEC_Session *GetSession()
    {
        return &PublicTest::session;
    }
    void SetUp() {}
    void TearDown() {}
};

class TeeBasicTestFramWithInitContext : public ::testing::Test {
private:
    static TEEC_Context context;
    static TEEC_Session session;
    static TEEC_SharedMemory sharedMem;

public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};

    TEEC_Context *GetContext()
    {
        return &TeeBasicTestFramWithInitContext::context;
    }
    TEEC_Session *GetSession()
    {
        return &TeeBasicTestFramWithInitContext::session;
    }
    TEEC_SharedMemory *GetSharedMem()
    {
        return &TeeBasicTestFramWithInitContext::sharedMem;
    }
    void SetUp();

    void TearDown();
};

#endif
