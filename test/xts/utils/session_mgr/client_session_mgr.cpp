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

#include "client_session_mgr.h"
#include <test_log.h>

ClientSessionMgr::ClientSessionMgr()
{
    initTag = false;
}

TEEC_Result ClientSessionMgr::Start(TEEC_UUID *uuid)
{
    TEEC_Result result;
    TEEC_Operation operation = { 0 };

    result = TEEC_InitializeContext(NULL, &context);
    if (result != TEEC_SUCCESS) {
        TEST_PRINT_ERROR("TEEC_InitializeContext failed\n");
        return result;
    }

    operation.started = 1;
    operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

    result = TEEC_OpenSession(&context, &session, uuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, NULL);
    if (result != TEEC_SUCCESS) {
        TEEC_FinalizeContext(&context);
        TEST_PRINT_INFO("TEEC_OpenSession failed\n");
    } else {
        initTag = true;
    }

    return result;
}

void ClientSessionMgr::Destroy()
{
    if (initTag) {
        TEEC_CloseSession(&session);
        TEEC_FinalizeContext(&context);

        session = { 0 };
        context = { 0 };
        initTag = false;
    }
}

ClientSessionMgr::~ClientSessionMgr()
{
    Destroy();
}

ClientShareMemMgr::ClientShareMemMgr()
{
}

void ClientShareMemMgr::Destroy()
{
    if (sharedMem.buffer != NULL) {
        TEEC_ReleaseSharedMemory(&sharedMem);
        sharedMem = { 0 };
    }
}

ClientShareMemMgr::~ClientShareMemMgr()
{
    Destroy();
}