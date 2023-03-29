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
#include <securec.h>

void CryptoTest::SetUp()
{
    TEEC_Result ret;
    TEEC_UUID testId = CRYPTO_API_UUID;
    ret = session.Start(&testId);
    ASSERT_EQ(ret, TEEC_SUCCESS);
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    (void)memset_s(&testMem.sharedMem, FUN_NAME_LEN, 0, FUN_NAME_LEN);
    testMem.sharedMem.size = FUN_NAME_LEN;
    testMem.sharedMem.flags = TEEC_MEM_OUTPUT | TEEC_MEM_INPUT;
    ret = TEEC_AllocateSharedMemory(&session.context, &testMem.sharedMem);
    ASSERT_EQ(ret, TEEC_SUCCESS);
}

void CryptoTest::TearDown()
{
    TEEC_ReleaseSharedMemory(&testMem.sharedMem);
    session.Destroy();
}

TEEC_Result CryptoTest::InvokeTest(const char *casename)
{
    int rc;
    rc = strcpy_s(reinterpret_cast<char*>(testMem.sharedMem.buffer), FUN_NAME_LEN, casename);
    if (rc != 0) {
        return TEEC_FAIL;
    }
    operation.params[0].memref.parent = &testMem.sharedMem;
    operation.params[0].memref.offset = 0;
    operation.params[0].memref.size = testMem.sharedMem.size;
    return TEEC_InvokeCommand(&session.session, CMD_RUN_BY_FUN_SEQ, &operation, &origin);
}
