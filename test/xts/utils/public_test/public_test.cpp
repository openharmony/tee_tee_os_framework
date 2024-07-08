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

#include "public_test.h"
#include "test_defines.h"

using namespace std;

TEEC_Context PublicTest::context = { 0 };
TEEC_Session PublicTest::session = { 0 };
TEEC_UUID PublicTest::uuid = TEST_UUID;

void PublicTest::SetUpTestCase()
{
    TEEC_Operation operation = { 0 };

    TEEC_Result ret = TEEC_InitializeContext(NULL, &context);
    ABORT_UNLESS(ret != TEEC_SUCCESS);

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, NULL);
    ABORT_UNLESS(ret != TEEC_SUCCESS);
}

void PublicTest::TearDownTestCase()
{
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
}

void PublicTest::SetUuid(const TEEC_UUID &uuid)
{
    PublicTest::uuid = uuid;
}

TEEC_Context TeeBasicTestFramWithInitContext::context = { 0 };
TEEC_Session TeeBasicTestFramWithInitContext::session = { 0 };
TEEC_SharedMemory TeeBasicTestFramWithInitContext::sharedMem = { 0 };

void TeeBasicTestFramWithInitContext::SetUp()
{
    TEEC_Result ret;
    ret = TEEC_InitializeContext(NULL, &context);
    ABORT_UNLESS(ret != TEEC_SUCCESS);
}

void TeeBasicTestFramWithInitContext::TearDown()
{
    TEEC_CloseSession(&session);
    TEEC_ReleaseSharedMemory(&sharedMem);
    TEEC_FinalizeContext(&context);
}