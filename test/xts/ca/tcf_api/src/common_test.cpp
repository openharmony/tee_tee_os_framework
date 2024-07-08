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

#include <gtest/gtest.h>
#include <test_defines.h>
#include <common_test.h>
#include <securec.h>
#include <tee_client_api.h>
#include <tee_client_type.h>
#include <test_log.h>
#include <test_tcf_cmdid.h>

using namespace testing::ext;

TEEC_Context TeeTCF1Test::context = { 0 };
TEEC_Session TeeTCF1Test::session = { 0 };

void TeeTCF1Test::SetUp()
{
    TEEC_Operation operation = { 0 };
    TEEC_Result ret = TEEC_InitializeContext(NULL, &context);
    if (ret != TEEC_SUCCESS) {
        TEST_PRINT_ERROR("TEEC_InitializeContext failed\n");
        return;
    }
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    TEEC_UUID uuid = TCF_API_UUID_1;
    char str[64] = { 0 };
    sprintf(str,"/data/local/tmp/%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x.sec", uuid.timeLow, uuid.timeMid,
        uuid.timeHiAndVersion, uuid.clockSeqAndNode[0], uuid.clockSeqAndNode[1], uuid.clockSeqAndNode[2],
        uuid.clockSeqAndNode[3], uuid.clockSeqAndNode[4], uuid.clockSeqAndNode[5], uuid.clockSeqAndNode[6],
        uuid.clockSeqAndNode[7]);
    context.ta_path = (uint8_t *)str;
    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
        TEEC_FinalizeContext(&context);
        TEST_PRINT_ERROR("TEEC_OpenSession failed\n");
        return;
    }
}

void TeeTCF1Test::TearDown()
{
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
}

TEEC_Context TeeTCF2Test::context = { 0 };
TEEC_Session TeeTCF2Test::session = { 0 };

void TeeTCF2Test::SetUp()
{
    TEEC_Operation operation = { 0 };

    TEEC_Result ret = TEEC_InitializeContext(NULL, &context);
    if (ret != TEEC_SUCCESS) {
        TEST_PRINT_ERROR("TEEC_InitializeContext failed\n");
        return;
    }

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    TEEC_UUID uuid = TCF_API_UUID_2;
    char str[64] = { 0 };
    sprintf(str,"/data/local/tmp/%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x.sec", uuid.timeLow, uuid.timeMid,
        uuid.timeHiAndVersion, uuid.clockSeqAndNode[0], uuid.clockSeqAndNode[1], uuid.clockSeqAndNode[2],
        uuid.clockSeqAndNode[3], uuid.clockSeqAndNode[4], uuid.clockSeqAndNode[5], uuid.clockSeqAndNode[6],
        uuid.clockSeqAndNode[7]);
    context.ta_path = (uint8_t *)str;
    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
        TEEC_FinalizeContext(&context);
        TEST_PRINT_ERROR("TEEC_OpenSession failed\n");
        return;
    }
}

void TeeTCF2Test::TearDown()
{
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
}

TEEC_Context TeeTCF2TA2TATest::context = { 0 };
TEEC_Session TeeTCF2TA2TATest::session = { 0 };
TEEC_Session TeeTCF2TA2TATest::session2 = { 0 };

void TeeTCF2TA2TATest::SetUp()
{
    TEEC_Operation operation = { 0 };

    TEEC_Result ret = TEEC_InitializeContext(NULL, &context);
    if (ret != TEEC_SUCCESS) {
        TEST_PRINT_ERROR("TEEC_InitializeContext failed\n");
        return;
    }

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    TEEC_UUID uuid2 = TCF_API_UUID_1; // this is TA2 UUID
    char str[64] = { 0 };
    sprintf(str,"/data/local/tmp/%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x.sec", uuid2.timeLow, uuid2.timeMid,
        uuid2.timeHiAndVersion, uuid2.clockSeqAndNode[0], uuid2.clockSeqAndNode[1], uuid2.clockSeqAndNode[2],
        uuid2.clockSeqAndNode[3], uuid2.clockSeqAndNode[4], uuid2.clockSeqAndNode[5], uuid2.clockSeqAndNode[6],
        uuid2.clockSeqAndNode[7]);
    context.ta_path = (uint8_t *)str;
    ret = TEEC_OpenSession(&context, &session2, &uuid2, TEEC_LOGIN_IDENTIFY, NULL, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
        TEST_PRINT_ERROR("TEEC_OpenSession ta2 failed\n");
        return;
    }

    TEEC_UUID uuid = TCF_API_UUID_2; // this is TA1 UUID
    memset(str, 0, 64);
    sprintf(str,"/data/local/tmp/%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x.sec", uuid.timeLow, uuid.timeMid,
        uuid.timeHiAndVersion, uuid.clockSeqAndNode[0], uuid.clockSeqAndNode[1], uuid.clockSeqAndNode[2],
        uuid.clockSeqAndNode[3], uuid.clockSeqAndNode[4], uuid.clockSeqAndNode[5], uuid.clockSeqAndNode[6],
        uuid.clockSeqAndNode[7]);
    context.ta_path = (uint8_t *)str;    
    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
        TEEC_FinalizeContext(&context);
        TEST_PRINT_ERROR("TEEC_OpenSession ta1 failed\n");
        return;
    }
}

void TeeTCF2TA2TATest::TearDown()
{
    TEEC_CloseSession(&session);
    TEEC_CloseSession(&session2);
    TEEC_FinalizeContext(&context);
}

TEEC_Context TeeTCF1EnumTest::context = { 0 };
TEEC_Session TeeTCF1EnumTest::session = { 0 };

void TeeTCF1EnumTest::SetUpTestCase()
{
    TEEC_Operation operation = { 0 };

    TEEC_Result ret = TEEC_InitializeContext(NULL, &context);
    if (ret != TEEC_SUCCESS) {
        TEST_PRINT_ERROR("TEEC_InitializeContext failed\n");
        return;
    }

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    TEEC_UUID uuid = TCF_API_UUID_1;
    char str[64] = { 0 };
    sprintf(str,"/data/local/tmp/%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x.sec", uuid.timeLow, uuid.timeMid,
        uuid.timeHiAndVersion, uuid.clockSeqAndNode[0], uuid.clockSeqAndNode[1], uuid.clockSeqAndNode[2],
        uuid.clockSeqAndNode[3], uuid.clockSeqAndNode[4], uuid.clockSeqAndNode[5], uuid.clockSeqAndNode[6],
        uuid.clockSeqAndNode[7]);
    context.ta_path = (uint8_t *)str;
    ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, NULL);
    if (ret != TEEC_SUCCESS) {
        TEEC_FinalizeContext(&context);
        TEST_PRINT_ERROR("TEEC_OpenSession failed\n");
        return;
    }
}

void TeeTCF1EnumTest::TearDownTestCase()
{
    TEEC_CloseSession(&session);
    TEEC_FinalizeContext(&context);
}

void TeeTCF1EnumTest::SetUp()
{
    TEEC_Result ret;

    // alloc PropertyEnumerator
    value.cmd = CMD_TEE_AllocatePropertyEnumerator;
    ret = Invoke_AllocatePropertyEnumerator(GetSession(), &value);
    ABORT_UNLESS(ret != TEEC_SUCCESS);
}

void TeeTCF1EnumTest::TearDown()
{
    value.cmd = CMD_TEE_FreePropertyEnumerator;
    Invoke_Operate_PropertyEnumerator(GetSession(), &value);
}

TEEC_Result Invoke_GetPropertyAsX(TEEC_Context *context, TEEC_Session *session, TestData *testData)
{
    if (session->session_id == 0)
        return TEEC_ERROR_SESSION_NOT_EXIST;
    
    TEEC_Result result = TEEC_FAIL;
    int rc;
    TEEC_Operation operation = { 0 };
    TEEC_SharedMemory shareMemInput, shareMemOutput;

    // allocate the share memorys
    shareMemInput.size = BIG_SIZE;
    shareMemInput.flags = TEEC_MEM_INOUT;
    result = TEEC_AllocateSharedMemory(context, &shareMemInput);
    if (result != TEEC_SUCCESS) {
        TEST_PRINT_ERROR("alloc shareMemInput fail!\n");
        return TEEC_FAIL;
    }

    shareMemOutput.size = BIG_SIZE;
    shareMemOutput.flags = TEEC_MEM_INOUT;
    result = TEEC_AllocateSharedMemory(context, &shareMemOutput);
    if (result != TEEC_SUCCESS) {
        TEST_PRINT_ERROR("alloc shareMemOutput fail!\n");
        TEEC_ReleaseSharedMemory(&shareMemInput);
        return TEEC_FAIL;
    }

    // Invoke command
    operation.started = 1;
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE);
    if (testData->enumerator != 0)
        operation.params[0].value.a = testData->enumerator;
    else
        operation.params[0].value.a = testData->propSet;

    operation.params[0].value.b = testData->caseId;
    (void)memset_s(shareMemInput.buffer, BIG_SIZE, 0, BIG_SIZE);
    rc = memcpy_s(shareMemInput.buffer, shareMemInput.size, testData->inBuffer, testData->inBufferLen);
    if (rc != TEEC_SUCCESS) {
        TEST_PRINT_ERROR("memcpy_s inBuffer to shareMemInput fail!\n");
        goto clean;
    }

    operation.params[1].memref.parent = &shareMemInput;
    operation.params[1].memref.size = shareMemInput.size;
    operation.params[1].memref.offset = 0;
    operation.params[2].memref.parent = &shareMemOutput;
    operation.params[2].memref.size = shareMemOutput.size;
    operation.params[2].memref.offset = 0;

    result = TEEC_InvokeCommand(session, testData->cmd, &operation, &testData->origin);
    testData->outBufferLen = operation.params[2].memref.size;
    rc = memcpy_s(testData->outBuffer, BIG_SIZE, shareMemOutput.buffer, testData->outBufferLen);
    if (rc != TEEC_SUCCESS) {
        TEST_PRINT_ERROR("memcpy_s shareMemOutput to outBuffer fail! rc = 0x%x\n", rc);
    }

clean:
    TEEC_ReleaseSharedMemory(&shareMemInput);
    TEEC_ReleaseSharedMemory(&shareMemOutput);
    return result;
}

TEEC_Result Invoke_AllocatePropertyEnumerator(TEEC_Session *session, TestData *testData)
{
    if (session->session_id == 0)
        return TEEC_ERROR_SESSION_NOT_EXIST;

    TEEC_Result result;
    TEEC_Operation operation = { 0 };

    // Invoke command
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].value.a = 0;
    operation.params[0].value.b = testData->caseId;
    result = TEEC_InvokeCommand(session, testData->cmd, &operation, &testData->origin);

    testData->enumerator = operation.params[0].value.a;
    return result;
}

TEEC_Result Invoke_Operate_PropertyEnumerator(TEEC_Session *session, TestData *testData)
{
    if (session->session_id == 0)
        return TEEC_ERROR_SESSION_NOT_EXIST;

    TEEC_Result result;
    TEEC_Operation operation = { 0 };
    // Invoke command
    operation.started = 1;
    switch (testData->cmd) {
        case CMD_TEE_FreePropertyEnumerator:
        case CMD_TEE_ResetPropertyEnumerator:
        case CMD_TEE_GetNextPropertyEnumerator:
            operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
            operation.params[0].value.a = testData->enumerator;
            operation.params[0].value.b = testData->cmd;
            break;
        case CMD_TEE_StartPropertyEnumerator:
            operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
            operation.params[0].value.a = testData->enumerator;
            operation.params[1].value.a = testData->propSet;
            break;
        case CMD_TEE_GetPropertyNameEnumerator:
            operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
            operation.params[0].value.a = testData->enumerator;
            operation.params[0].value.b = testData->caseId;
            operation.params[1].tmpref.buffer = testData->outBuffer;
            operation.params[1].tmpref.size = testData->outBufferLen;
            break;
        default:
            TEST_PRINT_ERROR("not support this test command! cmdId: 0x%x", testData->cmd);
            return TEEC_FAIL;
    }

    result = TEEC_InvokeCommand(session, testData->cmd, &operation, &testData->origin);
    if (testData->cmd == CMD_TEE_GetPropertyNameEnumerator)
        testData->outBufferLen = operation.params[1].tmpref.size;

    return result;
}

TEEC_Result Invoke_Malloc(TEEC_Session *session, uint32_t commandID, TestMemData *testData, uint32_t *origin)
{
    if (session->session_id == 0)
        return TEEC_ERROR_SESSION_NOT_EXIST;

    TEEC_Result result;
    TEEC_Operation operation = { 0 };

    // Invoke command
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
    operation.params[0].value.a = testData->inMemSize;
    operation.params[0].value.b = testData->inHint;
    operation.params[1].tmpref.buffer = testData->testBuffer;
    operation.params[1].tmpref.size = MAX_SHARE_SIZE;

    result = TEEC_InvokeCommand(session, commandID, &operation, origin);
    return result;
}

TEEC_Result Invoke_Realloc(TEEC_Session *session, uint32_t commandID, TestMemData *testData, char *output)
{
    if (session->session_id == 0)
        return TEEC_ERROR_SESSION_NOT_EXIST;

    TEEC_Result result;
    TEEC_Operation operation = { 0 };
    char *buffer = NULL;
    uint32_t bufSize = testData->oldSize > testData->newSize ? testData->oldSize : testData->newSize;

    if (bufSize > MAX_SHARE_SIZE)
        bufSize = TESTSIZE;

    buffer = reinterpret_cast<char *>(malloc(bufSize));
    if (buffer == NULL) {
        TEST_PRINT_ERROR("malloc buffer fail!\n");
        return TEEC_FAIL;
    }

    // Invoke command
    operation.started = 1;
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_OUTPUT, TEEC_VALUE_INPUT);
    operation.params[0].value.a = testData->oldSize;
    operation.params[0].value.b = testData->newSize;
    operation.params[1].tmpref.buffer = buffer;
    operation.params[1].tmpref.size = bufSize;
    operation.params[3].value.a = testData->caseId;

    result = TEEC_InvokeCommand(session, commandID, &operation, &testData->origin);
    testData->oldAddr = operation.params[2].value.a;
    testData->newAddr = operation.params[2].value.b;
    int rc = memcpy_s(output, bufSize, buffer, operation.params[1].tmpref.size);
    if (rc != 0) {
        TEST_PRINT_ERROR("memcpy_s output failed, rc=0x%x\n", rc);
        return TEEC_FAIL;
    }

    free(buffer);
    return result;
}

TEEC_Result Invoke_MemMove_Or_Fill(TEEC_Session *session, uint32_t commandID, TestMemData *testData, char *output)
{
    if (session->session_id == 0)
        return TEEC_ERROR_SESSION_NOT_EXIST;

    TEEC_Result result;
    TEEC_Operation operation = { 0 };
    char *buffer = NULL;
    uint32_t bufSize = testData->oldSize;
    buffer = reinterpret_cast<char*>(malloc(bufSize));
    if (buffer == NULL) {
        TEST_PRINT_ERROR("malloc buffer fail!\n");
        return TEEC_FAIL;
    }

    // Invoke command
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
    operation.params[0].value.a = testData->oldSize;
    operation.params[0].value.b = testData->caseId;
    operation.params[1].tmpref.buffer = buffer;
    operation.params[1].tmpref.size = bufSize;

    result = TEEC_InvokeCommand(session, commandID, &operation, &testData->origin);
    int rc = memcpy_s(output, testData->oldSize, buffer, operation.params[1].tmpref.size);
    if (rc != 0) {
        TEST_PRINT_ERROR("memcpy_s uuid to tee failed, rc=0x%x\n", rc);
        return TEEC_FAIL;
    }
    free(buffer);
    return result;
}

TEEC_Result Invoke_Free(TEEC_Session *session, uint32_t commandID, uint32_t caseNum, uint32_t *origin)
{
    if (session->session_id == 0)
        return TEEC_ERROR_SESSION_NOT_EXIST;

    TEEC_Result result;
    TEEC_Operation operation = { 0 };

    // Invoke command
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].value.a = caseNum;

    result = TEEC_InvokeCommand(session, commandID, &operation, origin);
    return result;
}

TEEC_Result Invoke_MemCompare(TEEC_Session *session, uint32_t commandID, TestMemData *testData, char *buffer1,
    char *buffer2)
{
    if (session->session_id == 0)
        return TEEC_ERROR_SESSION_NOT_EXIST;

    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation = { 0 };

    // Invoke command
    operation.started = 1;
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
    operation.params[0].value.a = testData->oldSize;
    operation.params[0].value.b = testData->caseId;
    operation.params[1].tmpref.buffer = buffer1;
    operation.params[1].tmpref.size = testData->oldSize > 0 ? testData->oldSize : TESTSIZE;
    operation.params[2].tmpref.buffer = buffer2;
    operation.params[2].tmpref.size = testData->oldSize > 0 ? testData->oldSize : TESTSIZE;

    result = TEEC_InvokeCommand(session, commandID, &operation, &testData->origin);
    return result;
}

TEEC_Result Invoke_CheckMemoryAccessRights(TEEC_Session *session, uint32_t commandID, TestMemData *testData)
{
    if (session->session_id == 0)
        return TEEC_ERROR_SESSION_NOT_EXIST;

    TEEC_Result result;
    TEEC_Operation operation = { 0 };
    char *buffer = NULL;
    uint32_t bufSize = testData->oldSize;
    buffer = reinterpret_cast<char*>(malloc(bufSize));
    if (buffer == NULL) {
        TEST_PRINT_ERROR("malloc buffer fail!\n");
        return TEEC_FAIL;
    }
    // Invoke command
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INPUT, TEEC_NONE);
    operation.params[0].value.a = testData->accessFlags;
    operation.params[0].value.b = testData->oldSize;
    operation.params[1].tmpref.buffer = buffer;
    operation.params[1].tmpref.size = bufSize;
    operation.params[2].value.a = testData->caseId;

    result = TEEC_InvokeCommand(session, commandID, &operation, &testData->origin);
    free(buffer);
    return result;
}

TEEC_Result Invoke_SetInstanceData(TEEC_Session *session, uint32_t commandID, char *buffer, uint32_t caseNum,
    uint32_t *origin)
{
    if (session->session_id == 0)
        return TEEC_ERROR_SESSION_NOT_EXIST;

    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation = { 0 };

    // Invoke command
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
    operation.params[0].value.a = caseNum;
    operation.params[1].tmpref.buffer = buffer;
    operation.params[1].tmpref.size = strlen(buffer) + 1;

    result = TEEC_InvokeCommand(session, commandID, &operation, origin);
    return result;
}

TEEC_Result Invoke_GetInstanceData(TEEC_Session *session, uint32_t commandID, char *buffer, uint32_t *bufSize,
    uint32_t *origin)
{
    if (session->session_id == 0)
        return TEEC_ERROR_SESSION_NOT_EXIST;

    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation = { 0 };

    // Invoke command
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].tmpref.buffer = buffer;
    operation.params[0].tmpref.size = *bufSize;

    result = TEEC_InvokeCommand(session, commandID, &operation, origin);
    *bufSize = operation.params[0].tmpref.size;
    return result;
}

static void retrieveUint32toBuffer(uint8_t *buffer, uint32_t i)
{
    buffer[3] = i & 0xff;
    buffer[2] = (i >> 8) & 0xff;
    buffer[1] = (i >> 16) & 0xff;
    buffer[0] = (i >> 24) & 0xff;
}

static void retrieveUint16toBuffer(uint8_t *buffer, uint16_t i)
{
    buffer[1] = i & 0xff;
    buffer[0] = (i >> 8) & 0xff;
}

TEEC_Result Invoke_OpenTASession(TEEC_Session *session, uint32_t commandID, uint32_t *ta2taSession, TestData *testData,
    uint32_t *origin)
{
    if (session->session_id == 0)
        return TEEC_ERROR_SESSION_NOT_EXIST;

    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation = { 0 };
    uint8_t tempBuffer[16];
    int rc;

    retrieveUint32toBuffer(tempBuffer, testData->uuid.timeLow);
    retrieveUint16toBuffer(tempBuffer + 4, testData->uuid.timeMid);
    retrieveUint16toBuffer(tempBuffer + 6, testData->uuid.timeHiAndVersion);
    rc = memcpy_s(tempBuffer + 8, 8, &(testData->uuid.clockSeqAndNode), 8);
    if (rc != 0) {
        TEST_PRINT_ERROR("memcpy_s uuid to tee failed, rc=0x%x\n", rc);
        return TEEC_ERROR_GENERIC;
    }

    // Invoke command
    operation.started = 1;
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_INOUT);
    operation.params[0].value.a = testData->caseId;
    operation.params[1].tmpref.buffer = tempBuffer;
    operation.params[1].tmpref.size = sizeof(tempBuffer);
    operation.params[3].tmpref.buffer = testData->inBuffer;
    operation.params[3].tmpref.size = testData->inBufferLen;

    result = TEEC_InvokeCommand(session, commandID, &operation, origin);
    *ta2taSession = operation.params[2].value.a;
    testData->origin = operation.params[2].value.b;
    testData->inBufferLen = operation.params[3].tmpref.size;

    return result;
}

TEEC_Result Invoke_CloseTASession(TEEC_Session *session, uint32_t commandID, uint32_t ta2taSession, uint32_t *origin)
{
    if (session->session_id == 0)
        return TEEC_ERROR_SESSION_NOT_EXIST;

    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation = { 0 };

    // Invoke command
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].value.a = ta2taSession;

    result = TEEC_InvokeCommand(session, commandID, &operation, origin);
    return result;
}

TEEC_Result Invoke_InvokeTACommand(TEEC_Session *session, uint32_t commandID, uint32_t ta2taSession, TestData *testData,
    uint32_t *origin)
{
    if (session->session_id == 0)
        return TEEC_ERROR_SESSION_NOT_EXIST;

    TEEC_Result result = TEEC_SUCCESS;
    TEEC_Operation operation = { 0 };

    // Invoke command
    operation.started = 1;
    operation.paramTypes =
        TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT);
    operation.params[0].value.a = testData->caseId;
    operation.params[0].value.b = ta2taSession;
    operation.params[1].tmpref.buffer = testData->inBuffer;
    operation.params[1].tmpref.size = testData->inBufferLen;
    operation.params[3].tmpref.buffer = testData->outBuffer;
    operation.params[3].tmpref.size = testData->outBufferLen;
    result = TEEC_InvokeCommand(session, commandID, &operation, origin);
    testData->origin = operation.params[2].value.a;
    testData->inBufferLen = operation.params[1].tmpref.size;
    testData->outBufferLen = operation.params[3].tmpref.size;
    return result;
}

uint32_t get_ta_data_size(TEEC_Context *context, TEEC_Session *session)
{
    if (session->session_id == 0)
        return TEEC_ERROR_SESSION_NOT_EXIST;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_DATASIZE, sizeof(GPD_TA_DATASIZE));
    if (rc != 0) {
        TEST_PRINT_ERROR("memcpy_s for GPD_TA_DATASIZE fail,rc=0x%x\n", rc);
        return -1;
    }
    value.inBufferLen = sizeof(GPD_TA_DATASIZE);
    Invoke_GetPropertyAsX(context, session, &value);

    return atoi(value.outBuffer);
}

uint32_t get_ta_stack_size(TEEC_Context *context, TEEC_Session *session)
{
    if (session->session_id == 0)
        return TEEC_ERROR_SESSION_NOT_EXIST;

    int rc;
    TestData value = { 0 };
    value.cmd = CMD_TEE_GetPropertyAsU32;
    value.propSet = TEE_PROPSET_CURRENT_TA;
    rc = memcpy_s(value.inBuffer, BIG_SIZE, GPD_TA_STACKSIZE, sizeof(GPD_TA_STACKSIZE));
    if (rc != 0) {
        TEST_PRINT_ERROR("memcpy_s for GPD_TA_STACKSIZE fail,rc=0x%x\n", rc);
        return -1;
    }
    value.inBufferLen = sizeof(GPD_TA_STACKSIZE);

    Invoke_GetPropertyAsX(context, session, &value);
    return atoi(value.outBuffer);
}

TEEC_Result Invoke_Panic(TEEC_Session *session, uint32_t commandID, TEEC_Result panicCode, uint32_t *origin)
{
    if (session->session_id == 0)
        return TEEC_ERROR_SESSION_NOT_EXIST;

    TEEC_Result result;
    TEEC_Operation operation = { 0 };

    // Invoke command
    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    operation.params[0].value.a = panicCode;

    result = TEEC_InvokeCommand(session, commandID, &operation, origin);
    return result;
}