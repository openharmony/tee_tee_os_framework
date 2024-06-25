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

#include <string.h>
#include <tee_ext_api.h>
#include <tee_log.h>
#include <test_comm_cmdid.h>
#include <tee_mem_mgmt_api.h>
#include <securec.h>

#define CA_PKGN_VENDOR "/vendor/bin/tee_test_client_api_vendor"
#define CA_PKGN_SYSTEM "/system/bin/tee_test_client_api_system"
#define CA_UID 0

// The test case uses the same string to pass the input and output test of buffer during REE and tee communication
char *g_teeOutput = "TEEMEM_OUTPUT";
char *g_teeInout = "the param is TEEMEM_INOUT";
uint32_t g_teeOutputLen;
uint32_t g_teeInoutLen;

static TEE_Result TestTypeValue(uint32_t paramTypes, TEE_Param params[4])
{
    TEE_Result ret = TEE_SUCCESS;

    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_VALUE_OUTPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_VALUE_INOUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_VALUE_INOUT)) {
        tloge("%s: Bad expected parameter types\n", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    for (uint32_t i = 0; i < 4; i++) {
        uint32_t param_type = TEE_PARAM_TYPE_GET(paramTypes, i);
        switch (param_type) {
            case TEE_PARAM_TYPE_VALUE_INPUT:
            case TEE_PARAM_TYPE_VALUE_OUTPUT:
                tlogd("param %d is TEE_PARAM_TYPE_VALUE_INPUT or TEE_PARAM_TYPE_VALUE_OUTPUT\n", i);
                tlogd("before modify,param %d: value.a=0x%x, value.b=0x%x\n", i, params[i].value.a, params[i].value.b);
                params[i].value.a = params[i].value.a + 1;
                params[i].value.b = params[i].value.b + 1;
                tlogd("after modify,param %d: value.a=0x%x, value.b=0x%x\n", i, params[i].value.a, params[i].value.b);
                break;
            case TEE_PARAM_TYPE_VALUE_INOUT:
                tlogd("param %d is TEE_PARAM_TYPE_VALUE_INOUT\n", i);
                tlogd("before modify,param %d: value.a=0x%x, value.b=0x%x\n", i, params[i].value.a, params[i].value.b);
                params[i].value.a = params[i].value.a - 1;
                params[i].value.b = params[i].value.b - 1;
                tlogd("after modify,param %d: value.a=0x%x, value.b=0x%x\n", i, params[i].value.a, params[i].value.b);
                break;
            case TEE_PARAM_TYPE_MEMREF_INPUT:
            case TEE_PARAM_TYPE_MEMREF_OUTPUT:
            case TEE_PARAM_TYPE_MEMREF_INOUT:
            case TEE_PARAM_TYPE_NONE:
                break;
            default:
                break;
        }
    }

    return ret;
}

static TEE_Result TestTypeBuffer(uint32_t paramTypes, TEE_Param params[4])
{
    TEE_Result ret = TEE_SUCCESS;

    if ((TEE_PARAM_TYPE_GET(paramTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 2) != TEE_PARAM_TYPE_MEMREF_INOUT) ||
        (TEE_PARAM_TYPE_GET(paramTypes, 3) != TEE_PARAM_TYPE_MEMREF_INOUT)) {
        tloge("%s: Bad expected parameter types\n", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    g_teeOutputLen = strlen(g_teeOutput) + 1;
    g_teeInoutLen = strlen(g_teeInout) + 1;

    for (uint32_t i = 0; i < 4; i++) {
        uint32_t param_type = TEE_PARAM_TYPE_GET(paramTypes, i);
        switch (param_type) {
            case TEE_PARAM_TYPE_MEMREF_INPUT:
            case TEE_PARAM_TYPE_MEMREF_OUTPUT:
                tlogd("param %d is TEE_PARAM_TYPE_MEMREF_INPUT or TEE_PARAM_TYPE_MEMREF_OUTPUT\n", i);
                tlogd("before modify,param %d size=%d, val=%s\n", i, params[i].memref.size, params[i].memref.buffer);
                TEE_MemMove(params[i].memref.buffer, g_teeOutput, g_teeOutputLen);
                params[i].memref.size = g_teeOutputLen;
                tlogd("after modify,param %d size=%d, val=%s\n", i, params[i].memref.size, params[i].memref.buffer);
                break;
            case TEE_PARAM_TYPE_MEMREF_INOUT:
                tlogd("param %d is TEE_PARAM_TYPE_MEMREF_INOUT\n", i);
                tlogd("before modify,param %d size=%d, val=%s\n", i, params[i].memref.size, params[i].memref.buffer);
                TEE_MemMove(params[i].memref.buffer, g_teeInout, g_teeInoutLen);
                params[i].memref.size = g_teeInoutLen;
                tlogd("after modify,param %d size=%d, val=%s\n", i, params[i].memref.size, params[i].memref.buffer);
                break;
            case TEE_PARAM_TYPE_VALUE_INPUT:
            case TEE_PARAM_TYPE_VALUE_OUTPUT:
            case TEE_PARAM_TYPE_VALUE_INOUT:
            case TEE_PARAM_TYPE_NONE:
                break;
            default:
                break;
        }
    }

    return ret;
}

static TEE_Result TestAllType(uint32_t paramTypes, TEE_Param params[4])
{
    TEE_Result ret = TEE_SUCCESS;

    g_teeOutputLen = strlen(g_teeOutput) + 1;
    g_teeInoutLen = strlen(g_teeInout) + 1;

    for (uint32_t i = 0; i < 4; i++) {
        uint32_t param_type = TEE_PARAM_TYPE_GET(paramTypes, i);
        switch (param_type) {
            case TEE_PARAM_TYPE_MEMREF_INPUT:
            case TEE_PARAM_TYPE_MEMREF_OUTPUT:
                tloge("param %d is TEE_PARAM_TYPE_MEMREF_INPUT or TEE_PARAM_TYPE_MEMREF_OUTPUT\n", i);
                tloge("before modify, param %d size=%d, val=%s\n", i, params[i].memref.size, params[i].memref.buffer);
                TEE_MemMove(params[i].memref.buffer, g_teeOutput, g_teeOutputLen);
                params[i].memref.size = g_teeOutputLen;
                tloge("after modify, param %d size=%d, val=%s\n", i, params[i].memref.size, params[i].memref.buffer);
                break;
            case TEE_PARAM_TYPE_MEMREF_INOUT:
                tloge("param %d is TEE_PARAM_TYPE_MEMREF_INOUT\n", i);
                tloge("before modify, param %d size=%d, val=%s\n", i, params[i].memref.size, params[i].memref.buffer);
                TEE_MemMove(params[i].memref.buffer, g_teeInout, g_teeInoutLen);
                params[i].memref.size = g_teeInoutLen;
                tloge("after modify,param %d size=%d, val=%s\n", i, params[i].memref.size, params[i].memref.buffer);
                break;
            case TEE_PARAM_TYPE_VALUE_INPUT:
            case TEE_PARAM_TYPE_VALUE_OUTPUT:
                tloge("param %d is TEE_PARAM_TYPE_VALUE_INPUT or TEE_PARAM_TYPE_VALUE_OUTPUT\n", i);
                tloge("before modify, param %d: value.a=0x%x, value.b=0x%x\n", i, params[i].value.a, params[i].value.b);
                params[i].value.a = params[i].value.a + 1;
                params[i].value.b = params[i].value.b + 1;
                tloge("after modify, param %d: value.a=0x%x, value.b=0x%x\n", i, params[i].value.a, params[i].value.b);
                break;
            case TEE_PARAM_TYPE_VALUE_INOUT:
                tloge("param %d is TEE_PARAM_TYPE_VALUE_INOUT\n", i);
                tloge("before modify, param %d: value.a=0x%x, value.b=0x%x\n", i, params[i].value.a, params[i].value.b);
                params[i].value.a = params[i].value.a - 1;
                params[i].value.b = params[i].value.b - 1;
                tloge("after modify, param %d: value.a=0x%x, value.b=0x%x\n", i, params[i].value.a, params[i].value.b);
                break;
            case TEE_PARAM_TYPE_NONE:
                break;
            default:
                break;
        }
    }

    return ret;
}


TEE_Result TA_CreateEntryPoint(void)
{
    tlogd("---- TA_CreateEntryPoint --------- \n");
    TEE_Result ret;

    ret = AddCaller_CA_exec(CA_PKGN_VENDOR, CA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("add caller failed, ret: 0x%x", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(CA_PKGN_SYSTEM, CA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("add caller failed, ret: 0x%x", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t parmType, TEE_Param params[4], void **sessionContext)
{
    (void)parmType;
    (void)sessionContext;
    tlogi("---- TA_OpenSessionEntryPoint -------- \n");
    if (params[0].value.b == 0xFFFFFFFE)
        return TEE_ERROR_GENERIC;
    else
        return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t cmd, uint32_t parmType, TEE_Param params[4])
{
    TEE_Result ret = TEE_SUCCESS;
    (void)sessionContext;

    tlogi("---- TA invoke command ----------- command id: %u\n", cmd);

    switch (cmd) {
        case 0:
            tlogi("this special invoke command is only for communication test! cmdId: 0x%x\n", cmd);
            break;
        case TEE_TEST_VALUE:
            ret = TestTypeValue(parmType, params);
            if (ret != TEE_SUCCESS)
                tloge("invoke command for value failed! cmdId: 0x%x, ret: 0x%x\n", cmd, ret);
            break;
        case TEE_TEST_BUFFER:
            ret = TestTypeBuffer(parmType, params);
            if (ret != TEE_SUCCESS)
                tloge("invoke command for buffer failed! cmdId: 0x%x, ret: 0x%x\n", cmd, ret);
            break;
        case TEE_TEST_ALLTYPE:
            ret = TestAllType(parmType, params);
            if (ret != TEE_SUCCESS)
                tloge("invoke command for all type failed! cmdId: 0x%x, ret: 0x%x\n", cmd, ret);
            break;
        default:
            tloge("not support this invoke command! cmdId: 0x%x\n", cmd);
            ret = TEE_ERROR_GENERIC;
            break;
    }

    return ret;
}

void TA_CloseSessionEntryPoint(void *sessionContext)
{
    (void)sessionContext;
    tlogd("---- TA_CloseSessionEntryPoint ----- \n");
}

void TA_DestroyEntryPoint(void)
{
    tlogd("---- TA_DestroyEntryPoint ---- \n");
}
