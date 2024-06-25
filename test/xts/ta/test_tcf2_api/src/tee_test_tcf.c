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

#include <securec.h>
#include <unistd.h>
#include "tee_core_api.h"
#include "tee_ext_api.h"
#include "tee_log.h"
#include "tee_mem_mgmt_api.h"
#include "tee_property_api.h"
#include "test_comm_cmdid.h"
#include "test_tcf_cmdid.h"
#include "tee_sharemem_ops.h"

#define CA_PKGN_VENDOR "/vendor/bin/tee_test_tcf_api"
#define CA_PKGN_SYSTEM "/system/bin/tee_test_tcf_api"
#define CA_UID 0

#define SMC_TA_TESTIDENTITY_LOGIN 0xF0000000
#define SMC_TA_TESTIDENTITY_TIMELOW 0x01010101
#define SMC_TA_TESTIDENTITY_TIMEMID 0x2020
#define SMC_TA_TESTIDENTITY_TIMEHIANDVERSION 0x0303
#define SMC_TA_TESTIDENTITY_CLOCKSEQANDNODE            \
    {                                                  \
        0x40, 0x40, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05 \
    }

#define TESTSIZE 16
#define DEFAULT_BUFFER_SIZE 1024
#define MAX_TA2TA_SIZE 0x800000

#define MAXLEN_U32 11
#define ENUMERATOR1 1
#define MAX_ENUMERATOR 1023

static char g_testVar[] = "this is test for non-const variable";
static const char g_testVar2[] = "this is test for const variable";

static TEE_Result CmdTEEGetPropertyAsIdentity_withoutEnum(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_PropSetHandle nPropSet;
    char *pPropName = NULL;
    char nClockSeqAndNode[8] = SMC_TA_TESTIDENTITY_CLOCKSEQANDNODE;
    TEE_Identity nResultIdentity;
    TEE_Result cmdResult;
    uint32_t caseId;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||   // the property set
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT) ||  // the property name
        (TEE_PARAM_TYPE_GET(nParamTypes, 2) != TEE_PARAM_TYPE_MEMREF_OUTPUT)) { // the output value
        tloge("%s: Bad expected parameter types\n", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    nPropSet = (TEE_PropSetHandle)pParams[0].value.a;
    caseId = pParams[0].value.b;
    pPropName = pParams[1].memref.buffer;

    switch (caseId) {
        case INPUT_ISNULL:
            cmdResult = TEE_GetPropertyAsIdentity(nPropSet, NULL, &nResultIdentity);
            break;
        case OUTPUT_ISNULL:
            cmdResult = TEE_GetPropertyAsIdentity(nPropSet, pPropName, NULL);
            break;
        default:
            cmdResult = TEE_GetPropertyAsIdentity(nPropSet, pPropName, &nResultIdentity);
            break;
    }

    if (cmdResult == TEE_SUCCESS) {
        if ((nResultIdentity.login == (uint32_t)SMC_TA_TESTIDENTITY_LOGIN) &&
            (nResultIdentity.uuid.timeLow == (uint32_t)SMC_TA_TESTIDENTITY_TIMELOW) &&
            (nResultIdentity.uuid.timeMid == (uint16_t)SMC_TA_TESTIDENTITY_TIMEMID) &&
            (nResultIdentity.uuid.timeHiAndVersion == (uint16_t)SMC_TA_TESTIDENTITY_TIMEHIANDVERSION) &&
            (TEE_MemCompare(&nResultIdentity.uuid.clockSeqAndNode, nClockSeqAndNode, 8) == 0)) {
            tlogi("TEE_GetPropertyAsIdentity success and get identity is correct!\n");
        } else {
            tloge("TEE_GetPropertyAsUUID get identity is wrong!\n");
            cmdResult = TEE_ERROR_GENERIC;
        }
    }

    return cmdResult;
}

static TEE_Result CmdTEEGetPropertyAsU32(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_PropSetHandle nPropSet;
    char *pPropName = NULL;
    char outStr[MAXLEN_U32] = { 0 };
    uint32_t caseId;
    TEE_Result cmdResult;
    uint32_t nIntResult = 0;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||   // the property set
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT) ||  // the property name
        (TEE_PARAM_TYPE_GET(nParamTypes, 2) != TEE_PARAM_TYPE_MEMREF_OUTPUT)) { // the output value
        tloge("%s: Bad expected parameter types\n", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    caseId = pParams[0].value.b;
    nPropSet = (TEE_PropSetHandle)pParams[0].value.a;
    pPropName = pParams[1].memref.buffer;

    switch (caseId) {
        case OUTPUT_ISNULL:
            cmdResult = TEE_GetPropertyAsU32(nPropSet, pPropName, NULL);
            break;
        case INPUT_ISNULL:
            cmdResult = TEE_GetPropertyAsU32(nPropSet, NULL, &nIntResult);
            break;
        default:
            if (nPropSet >= ENUMERATOR1 && nPropSet <= MAX_ENUMERATOR)
                cmdResult = TEE_GetPropertyAsU32(nPropSet, NULL, &nIntResult);
            else
                cmdResult = TEE_GetPropertyAsU32(nPropSet, pPropName, &nIntResult);
            break;
    }

    (void)snprintf_s(outStr, MAXLEN_U32, MAXLEN_U32 - 1, "%lu", nIntResult);
    TEE_MemMove(pParams[2].memref.buffer, outStr, strlen(outStr) + 1);
    pParams[2].memref.size = strlen(outStr) + 1;

    return cmdResult;
}

static TEE_Result CmdTEEMalloc(uint32_t nParamTypes, TEE_Param pParams[4])
{
    size_t nSize;
    uint32_t nHint;
    char *pBuffer = NULL;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT)) {
        tloge("%s: Bad expected parameter types\n", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    nSize = pParams[0].value.a;
    nHint = pParams[0].value.b;

    tlogi("before TEE_Malloc nSize=%d, nHint=%d\n", nSize, nHint);
    pBuffer = (char *)TEE_Malloc(nSize, nHint);
    if (pBuffer == NULL) {
        tloge("TEE_Malloc is failed!\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    } else {
        TEE_MemMove(pParams[1].memref.buffer, pBuffer, nSize);
        TEE_Free((void *)pBuffer); // free the allocated buffer
        tlogi("TEE_Free is finish!\n");
        return TEE_SUCCESS;
    }
}

static TEE_Result CmdTEERealloc(uint32_t nParamTypes, TEE_Param pParams[4])
{
    (void)nParamTypes;
    size_t nOldSize, nNewSize;
    char *pBufferMalloc = NULL;
    char *pBufferRealloc = NULL;
    char buf[DEFAULT_BUFFER_SIZE] = { 0 };

    uint32_t caseId = pParams[3].value.a;
    nOldSize = pParams[0].value.a;
    nNewSize = pParams[0].value.b;

    pBufferMalloc = (char *)TEE_Malloc(nOldSize, 0);
    if (pBufferMalloc == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    (void)memset_s(pBufferMalloc, nOldSize, 0x41, nOldSize); // 'A' is 0x41

    if (caseId == INPUT_ISNULL) {
        pBufferRealloc = (char *)TEE_Realloc(NULL, nNewSize);
    } else if (caseId == BUFFER_ISNOT_MALLOC) {
        pBufferRealloc = (char *)TEE_Realloc(buf, nNewSize);
    } else {
        pBufferRealloc = (char *)TEE_Realloc((void *)pBufferMalloc, nNewSize);
    }
    if ((pBufferRealloc == NULL) && (pBufferMalloc == NULL)) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    if ((pBufferRealloc == NULL) && (pBufferMalloc != NULL)) {
        for (uint32_t i = 0; i < nOldSize; i++) {
            if (pBufferMalloc[i] != (char)'A') { // checks that the data has not been changed after realloc
                tloge("%d th bytes of pBufferMalloc is not correct, it is %c \n", i + 1, pBufferMalloc[i]);
                TEE_Free((void *)pBufferMalloc); // free the allocated buffer
                return TEE_ERROR_GENERIC;
            }
        }
        TEE_Free((void *)pBufferMalloc); // free the allocated buffer
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    if (pBufferRealloc != NULL) {
        pParams[2].value.a = (uint32_t)pBufferMalloc;
        pParams[2].value.b = (uint32_t)pBufferRealloc;
        if (caseId == INPUT_ISNULL)
            TEE_MemMove(pParams[1].memref.buffer, pBufferMalloc, nOldSize);
        else
            TEE_MemMove(pParams[1].memref.buffer, pBufferRealloc, (nOldSize < nNewSize ? nOldSize : nNewSize));

        TEE_Free((void *)pBufferRealloc); // free the reallocated buffer
    }
    return TEE_SUCCESS;
}

static TEE_Result CmdTEEMemMove(uint32_t nParamTypes, TEE_Param pParams[4])
{
    uint32_t caseId;
    char *pBufferSrc = NULL;
    char *pBufferDest = NULL;
    uint32_t i;
    size_t nSize;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT)) {
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    nSize = pParams[0].value.a;
    caseId = pParams[0].value.b;

    pBufferSrc = (char *)TEE_Malloc(nSize, 0);
    if (pBufferSrc == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    pBufferDest = (char *)TEE_Malloc(nSize, 0);
    if (pBufferDest == NULL) {
        TEE_Free((void *)pBufferSrc);
        return TEE_ERROR_OUT_OF_MEMORY;
    } else {
        (void)memset_s(pBufferDest, nSize, 0x42, nSize); // 0x42 is 'B'
        for (i = 0; i < nSize; i++)
            pBufferSrc[i] = (char)'A'; // writes data into the buffer
        if (caseId == INPUT_ISNULL) {
            TEE_MemMove((void *)pBufferDest, NULL, nSize);
        } else if (caseId == OUTPUT_ISNULL) {
            TEE_MemMove(NULL, (void *)pBufferSrc, nSize);
        } else if (caseId == OUTPUTBUFFERSIZE_ISZERO) {
            TEE_MemMove((void *)pBufferDest, (void *)pBufferSrc, 0);
        } else if (caseId == DESTANDSRC_ISSAME) {
            TEE_MemMove((void *)pBufferSrc, (void *)pBufferSrc, nSize);
        } else if (caseId == DESTANDSRC_OVERLAP) {
            TEE_MemMove((void *)pBufferDest, (void *)pBufferSrc, nSize >> 1);
            TEE_MemMove((void *)(pBufferDest + 1), (void *)pBufferDest, nSize >> 1); // is overlap
        } else {
            TEE_MemMove((void *)pBufferDest, (void *)pBufferSrc, nSize);
        }
        TEE_MemMove(pParams[1].memref.buffer, pBufferDest, nSize);

        TEE_Free((void *)pBufferSrc);
        TEE_Free((void *)pBufferDest);
        return TEE_SUCCESS;
    }
}

static TEE_Result CmdTEEMemCompare(uint32_t nParamTypes, TEE_Param pParams[4])
{
    uint32_t caseId;
    char *pBuffer1 = NULL;
    char *pBuffer2 = NULL;
    TEE_Result ret;
    size_t nSize;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
        (TEE_PARAM_TYPE_GET(nParamTypes, 2) != TEE_PARAM_TYPE_MEMREF_INPUT)) {
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    nSize = pParams[0].value.a;
    caseId = pParams[0].value.b;

    pBuffer1 = pParams[1].memref.buffer;
    pBuffer2 = pParams[2].memref.buffer;

    if (caseId == INPUT_ISNULL)
        ret = (TEE_Result)TEE_MemCompare(NULL, pBuffer2, nSize);
    else if (caseId == OUTPUT_ISNULL)
        ret = (TEE_Result)TEE_MemCompare(pBuffer1, NULL, nSize);
    else
        ret = (TEE_Result)TEE_MemCompare(pBuffer1, pBuffer2, nSize);

    return ret;
}

static TEE_Result CmdTEEMemFill(uint32_t nParamTypes, TEE_Param pParams[4])
{
    uint32_t caseId;
    char *pBuffer = NULL;
    char nCharFill = 'A';
    size_t nMemoryFillSize;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT)) {
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    nMemoryFillSize = pParams[0].value.a;
    caseId = pParams[0].value.b;

    pBuffer = (char *)TEE_Malloc(nMemoryFillSize, 0); // buffer is filled with 0
    if (pBuffer == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    if (caseId == INPUT_ISNULL) {
        TEE_MemFill(NULL, nCharFill, nMemoryFillSize);
    } else if (caseId == OUTPUTBUFFERSIZE_ISZERO) {
        TEE_MemFill(pBuffer, nCharFill, 0);
    } else {
        TEE_MemFill(pBuffer, nCharFill, nMemoryFillSize);
    }
    TEE_MemMove(pParams[1].memref.buffer, pBuffer, nMemoryFillSize);
    TEE_Free((void *)pBuffer);
    return TEE_SUCCESS;
}

static TEE_Result CmdTEEFree(uint32_t nParamTypes, TEE_Param pParams[4])
{
    void *pBufferMalloc = NULL;
    uint32_t caseId;
    char buf[DEFAULT_BUFFER_SIZE] = { 0 };

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT)) {
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    caseId = pParams[0].value.a;
    if (caseId == INPUT_ISNULL) {
        TEE_Free(NULL);
        return TEE_SUCCESS;
    } else if (caseId == BUFFER_ISNOT_MALLOC) {
        TEE_Free(buf);
        return TEE_SUCCESS;
    } else {
        pBufferMalloc = TEE_Malloc(DEFAULT_BUFFER_SIZE, 0);
        if (pBufferMalloc == NULL)
            return TEE_ERROR_OUT_OF_MEMORY;
        TEE_Free(pBufferMalloc);
        return TEE_SUCCESS;
    }
}

static TEE_Result CmdTEECheckMemoryAccessRights(uint32_t nParamTypes, TEE_Param pParams[4])
{
    uint32_t caseId;
    uint32_t accessFlags;
    char *pBuffer = NULL;
    char buf[DEFAULT_BUFFER_SIZE] = { 0 };
    size_t nSize;
    TEE_Result ret;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_OUTPUT) ||
        (TEE_PARAM_TYPE_GET(nParamTypes, 2) != TEE_PARAM_TYPE_VALUE_INPUT)) {
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    accessFlags = pParams[0].value.a;
    nSize = pParams[0].value.b;
    caseId = pParams[2].value.a;

    pBuffer = (char *)TEE_Malloc(nSize, 0);
    if (pBuffer == NULL) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    if (caseId == BUFFER_IS_FREE) {
        TEE_Free((void *)pBuffer); // free the allocated buffer
    }
    if (caseId == INPUT_ISNULL)
        ret = TEE_CheckMemoryAccessRights(accessFlags, NULL, nSize);
    else if (caseId == BUFFER_ISNOT_MALLOC)
        ret = TEE_CheckMemoryAccessRights(accessFlags, buf, nSize);
    else if (caseId == OUTPUTBUFFERSIZE_ISZERO)
        ret = TEE_CheckMemoryAccessRights(accessFlags, pBuffer, 0);
    else if (caseId == BUFFERSIZE_ISTOOBIG)
        ret = TEE_CheckMemoryAccessRights(accessFlags, pBuffer, nSize << 6);
    else if (caseId == BUFFER_IS_PARAM)
        ret = TEE_CheckMemoryAccessRights(accessFlags, pParams[1].memref.buffer, pParams[1].memref.size);
    else if (caseId == BUFFER_IS_GLOBALVAR)
        ret = TEE_CheckMemoryAccessRights(accessFlags, g_testVar, strlen(g_testVar));
    else if (caseId == BUFFER_IS_GLOBALCONSTVAR)
        ret = TEE_CheckMemoryAccessRights(accessFlags, g_testVar2, strlen(g_testVar2));
    else
        ret = TEE_CheckMemoryAccessRights(accessFlags, pBuffer, nSize);

    if (caseId != BUFFER_IS_FREE) {
        TEE_Free((void *)pBuffer);
    }
    return ret;
}

static TEE_Result CmdTEESetInstanceData(uint32_t nParamTypes, TEE_Param pParams[4])
{
    char *pDataBuffer = NULL;
    uint32_t nStringSize;
    uint32_t caseId;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||
        // the input string to copy inside the char[] buffer created
        (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_MEMREF_INPUT)) {
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }
    caseId = pParams[0].value.a;
    nStringSize = pParams[1].memref.size;     // retrieve the length of the string
    pDataBuffer = TEE_Malloc(nStringSize, 0); // allocates the necessary space for the instance data
    if (pDataBuffer == NULL)
        return TEE_ERROR_OUT_OF_MEMORY; // TA returns if not possible to allocate the instance data size

    // recopies the input string into the instance data
    TEE_MemMove((void *)pDataBuffer, (void *)pParams[1].memref.buffer, nStringSize);

    if (caseId == INPUT_ISNULL) {
        TEE_SetInstanceData(NULL);
    } else {
        TEE_SetInstanceData((void *)pDataBuffer); // calls the SetInstanceData function to store the string address
    }
    return TEE_SUCCESS;
}

static TEE_Result CmdTEEGetInstanceData(uint32_t nParamTypes, TEE_Param pParams[4])
{
    char *pDataBuffer = NULL;
    uint32_t nStringSize;
    TEE_Result ret;

    // the input string to copy inside the char[] buffer created
    if (TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_MEMREF_OUTPUT) {
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    pDataBuffer = (char *)TEE_GetInstanceData(); // retrieve the pointer
    if (pDataBuffer == NULL)
        return TEE_ERROR_GENERIC; // if pointer is NULL, it is because the function SetInstanceData has not been called

    nStringSize = strlen(pDataBuffer) + 1; // retrieve the length of the string stored
    if (pParams[0].memref.size < nStringSize) {
        ret = TEE_ERROR_SHORT_BUFFER;
    } else {
        TEE_MemMove((void *)pParams[0].memref.buffer, (void *)pDataBuffer, nStringSize);
        ret = TEE_SUCCESS;
    }

    pParams[0].memref.size = nStringSize;
    TEE_Free(pDataBuffer);
    return ret;
}

static void getUUIDFromBuffer(TEE_UUID *pTargetUUID, char uuidvalue[16])
{
    pTargetUUID->timeLow = (uint32_t)(uuidvalue[0] << 24) + (uint32_t)(uuidvalue[1] << 16) +
        (uint32_t)(uuidvalue[2] << 8) + (uint32_t)(uuidvalue[3]);
    pTargetUUID->timeMid = (uint32_t)(uuidvalue[4] << 8) + (uint32_t)(uuidvalue[5]);
    pTargetUUID->timeHiAndVersion = (uint32_t)(uuidvalue[6] << 8) + (uint32_t)(uuidvalue[7]);
    pTargetUUID->clockSeqAndNode[0] = (uint8_t)(uuidvalue[8]);
    pTargetUUID->clockSeqAndNode[1] = (uint8_t)(uuidvalue[9]);
    pTargetUUID->clockSeqAndNode[2] = (uint8_t)(uuidvalue[10]);
    pTargetUUID->clockSeqAndNode[3] = (uint8_t)(uuidvalue[11]);
    pTargetUUID->clockSeqAndNode[4] = (uint8_t)(uuidvalue[12]);
    pTargetUUID->clockSeqAndNode[5] = (uint8_t)(uuidvalue[13]);
    pTargetUUID->clockSeqAndNode[6] = (uint8_t)(uuidvalue[14]);
    pTargetUUID->clockSeqAndNode[7] = (uint8_t)(uuidvalue[15]);
}

static TEE_Result CmdTEEOpenTASession(uint32_t nParamTypes, TEE_Param pParams[4])
{
    (void)nParamTypes;
    TEE_UUID pTargetUUID;
    TEE_Param pTargetParams[4];
    uint32_t caseId;
    uint32_t nLocalParamTypes;
    uint32_t nReturnOrigin = 0;
    uint32_t hint = TEE_MALLOC_FILL_ZERO;
    uint32_t nSize = DEFAULT_BUFFER_SIZE;
    TEE_TASessionHandle nsession = 0;
    TEE_Result nTmpResult;
    char *pBufferIn = NULL;

    if (pParams[1].memref.size != 16) {
        tloge("UUID size not correct");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    caseId = pParams[0].value.a;
    getUUIDFromBuffer(&pTargetUUID, (char *)pParams[1].memref.buffer);

    nLocalParamTypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_MEMREF_INOUT, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);
    pTargetParams[0].value.a = caseId;

    if (caseId == BUFFER_NOFILLNOSHARE)
        hint = TEE_MALLOC_NO_FILL | TEE_MALLOC_NO_SHARE;

    pBufferIn = (char *)TEE_Malloc(nSize, hint);
    if (pBufferIn == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    TEE_MemMove(pBufferIn, pParams[3].memref.buffer, pParams[3].memref.size);
    pTargetParams[1].memref.buffer = pBufferIn;
    pTargetParams[1].memref.size = nSize;

    /* Open the session */
    if (caseId == INPUT_ISNULL)
        nTmpResult =
            TEE_OpenTASession(NULL, TEE_TIMEOUT_INFINITE, nLocalParamTypes, pTargetParams, &nsession, &nReturnOrigin);
    else if (caseId == OUTPUT_ISNULL)
        nTmpResult = TEE_OpenTASession(&pTargetUUID, TEE_TIMEOUT_INFINITE, nLocalParamTypes, pTargetParams, NULL,
            &nReturnOrigin);
    else if (caseId == RETURNORIGIN_ISNULL)
        nTmpResult =
            TEE_OpenTASession(&pTargetUUID, TEE_TIMEOUT_INFINITE, nLocalParamTypes, pTargetParams, &nsession, NULL);
    else
        nTmpResult = TEE_OpenTASession(&pTargetUUID, TEE_TIMEOUT_INFINITE, nLocalParamTypes, pTargetParams, &nsession,
            &nReturnOrigin);

    pParams[2].value.a = nsession;
    pParams[2].value.b = nReturnOrigin;

    TEE_MemMove(pParams[3].memref.buffer, pBufferIn, pTargetParams[1].memref.size);
    pParams[3].memref.size = pTargetParams[1].memref.size;
    tlogi("test TEE_OpenTASession is finish! nsession=%d, nReturnOrigin=%d\n", nsession, nReturnOrigin);
    return nTmpResult;
}

static TEE_Result CmdTEECloseTASession(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_TASessionHandle nsession;

    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT)) { /* return origin of the OpenTASession */
        tloge("%s: Bad expected parameter types", __func__);
        return TEE_ERROR_COMMUNICATION;
    }

    nsession = pParams[0].value.a;
    TEE_CloseTASession(nsession);

    return TEE_SUCCESS;
}

static TEE_Result CmdTEEInvokeTACommand(uint32_t nParamTypes, TEE_Param pParams[4])
{
    (void)nParamTypes;
    TEE_Result nTmpResult;
    char *pBufferIn = NULL;

    /* For the final TAInvoke */
    uint32_t nReturnOrigin = 0;
    uint32_t hint = TEE_MALLOC_FILL_ZERO;
    uint32_t nSize = MAX_TA2TA_SIZE;
    uint32_t cmd = TEE_TEST_BUFFER;
    TEE_Param pTargetParams[4];

    uint32_t caseId = pParams[0].value.a;
    TEE_TASessionHandle nsession = pParams[0].value.b;
    uint32_t npType = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if (caseId == TA_CRASH_FLAG)
        cmd = CMD_TEE_Panic;

    if ((caseId == BUFFERSIZE_ISTOOBIG) || (caseId == BUFFER_NOFILLNOSHARE)) {
        if (caseId == BUFFER_NOFILLNOSHARE) {
            nSize = DEFAULT_BUFFER_SIZE;
            hint = TEE_MALLOC_NO_FILL | TEE_MALLOC_NO_SHARE;
        }

        pBufferIn = (char *)TEE_Malloc(nSize, hint);
        if (pBufferIn == NULL)
            return TEE_ERROR_OUT_OF_MEMORY;

        (void)memset_s(pBufferIn, nSize, 0x41, nSize);
        npType =
            TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
        pTargetParams[0].memref.buffer = pBufferIn;
        pTargetParams[0].memref.size = nSize;
    } else {
        pTargetParams[0].memref.buffer = pParams[1].memref.buffer;
        pTargetParams[0].memref.size = pParams[1].memref.size;
        pTargetParams[1].memref.buffer = pParams[3].memref.buffer;
        pTargetParams[1].memref.size = pParams[3].memref.size;
    }

    if (caseId == INPUT_ISNULL)
        nTmpResult = TEE_InvokeTACommand(0, TEE_TIMEOUT_INFINITE, cmd, npType, pTargetParams, &nReturnOrigin);
    else if (caseId == OUTPUT_ISNULL)
        nTmpResult = TEE_InvokeTACommand(nsession, TEE_TIMEOUT_INFINITE, cmd, npType, pTargetParams, NULL);
    else
        nTmpResult = TEE_InvokeTACommand(nsession, TEE_TIMEOUT_INFINITE, cmd, npType, pTargetParams, &nReturnOrigin);

    pParams[2].value.a = nReturnOrigin;

    if (nTmpResult == TEE_SUCCESS) {
        TEE_MemMove(pParams[1].memref.buffer, pTargetParams[0].memref.buffer, pTargetParams[0].memref.size);
        pParams[1].memref.size = pTargetParams[0].memref.size;
        if (caseId != BUFFER_NOFILLNOSHARE) {
            pParams[3].memref.size = pTargetParams[1].memref.size;
            TEE_MemMove(pParams[3].memref.buffer, pTargetParams[1].memref.buffer, pTargetParams[1].memref.size);
        }
    }

    tlogi("test TEE_InvokeTACommand is finish! nTmpResult=0x%x, nReturnOrigin=%d\n", nTmpResult, nReturnOrigin);

    if (!pBufferIn) {
        TEE_Free((void *)pBufferIn);
    }
    return nTmpResult;
}

#define TCF_API_UUID_1                                     \
    {                                                      \
        0x534d4152, 0x542d, 0x4353,                        \
        {                                                  \
            0x4c, 0x54, 0xd3, 0x01, 0x6a, 0x17, 0x1f, 0x01 \
        }                                                  \
    }
static TEE_Result CmdTEEShareMemTest(uint32_t nParamTypes, TEE_Param pParams[4])
{
    (void)nParamTypes;

    (void)pParams;
    return 0;
#if 0
    TEE_Result nTmpResult = TEE_SUCCESS;
    uint32_t nReturnOrigin = 0;
    uint32_t size = DEFAULT_BUFFER_SIZE;
    uint32_t cmd = TEE_TEST_SHAREMEM;
    TEE_Param pTargetParams[4];
    struct tee_uuid uuid = TCF_API_UUID_1;
    TEE_TASessionHandle nsession = pParams[0].value.b;
    uint32_t npType = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE);

    uint32_t *temp_buffer = tee_alloc_sharemem_aux(&uuid, size);
    if (temp_buffer == NULL) {
        tloge("tee_alloc_sharemem_aux failed!\n");
        return TEE_ERROR_GENERIC;
    }
    tlogi("tee_alloc_sharemem_aux success!\n");
    (void)memset_s(temp_buffer, size, 0x41, size);

    pTargetParams[0].value.a = (uint64_t)(uintptr_t)temp_buffer >> 32;
    pTargetParams[0].value.b = (uint64_t)(uintptr_t)temp_buffer;
    pTargetParams[1].value.a = getpid();
    pTargetParams[1].value.b = size;
    nTmpResult = TEE_InvokeTACommand(nsession, TEE_TIMEOUT_INFINITE, cmd, npType, pTargetParams, &nReturnOrigin);
    pParams[2].value.a = nReturnOrigin;
    if (nTmpResult != TEE_SUCCESS) {
        tloge("%s: test TEE_InvokeTACommand failed! ret =0x%x, origin =%d\n", __func__, nTmpResult, nReturnOrigin);
        goto out;
    }
    if (pTargetParams[2].value.a == 1) {
        tloge("sender ta receiver sharemem failed!\n");
        nTmpResult = TEE_ERROR_GENERIC;
        goto out;
    }

    for (uint32_t i = 0; i < size / sizeof(uint32_t); i++)
    {
        if (temp_buffer[i] != 0x42) {  // modified by ta2
            tloge("temp_buffer[%d] should be 0x42, not 0x%x\n", i, temp_buffer[i]);
            nTmpResult = TEE_ERROR_GENERIC;
            goto out;
        }
    }
    tlogi("test sharemem between ta2ta is success!\n");

    tee_free_sharemem(temp_buffer, size);
    uint32_t *buffer = tee_alloc_coherent_sharemem_aux(&uuid, size);
    if (buffer == NULL) {
        tloge("tee_alloc_coherent_sharemem_aux failed!\n");
        return TEE_ERROR_GENERIC;
    }
    tlogi("tee_alloc_coherent_sharemem_aux success!\n");
    (void)memset_s(buffer, size, 0x43, size);

    if (tee_free_sharemem(buffer, size) != 0) {
        tloge("tee_free_sharemem after tee_alloc_coherent_sharemem_aux failed!\n");
        nTmpResult = TEE_ERROR_GENERIC;
    }

    return nTmpResult;
out:
    if (tee_free_sharemem(temp_buffer, size) != 0) {
        tloge("tee_free_sharemem failed!\n");
        nTmpResult = TEE_ERROR_GENERIC;
    }
    return nTmpResult;
#endif
}

TEE_Result TA_CreateEntryPoint(void)
{
    tlogi("---- TA_CreateEntryPoint ---------");
    TEE_Result ret;

    ret = AddCaller_CA_exec(CA_PKGN_VENDOR, CA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("tcf2 ta add caller failed, ret: 0x%x", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(CA_PKGN_SYSTEM, CA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("tcf2 ta add caller failed, ret: 0x%x", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t parmType, TEE_Param params[4], void **sessionContext)
{
    (void)parmType;
    (void)params;
    (void)sessionContext;
    tlogi("---- TA_OpenSessionEntryPoint --------");

    return TEE_SUCCESS;
}

typedef TEE_Result (*func)(uint32_t nParamTypes, TEE_Param pParams[4]);

struct testFunc {
    uint32_t cmdId;
    func funcName;
};

struct testFunc g_testTable[] = {
    { CMD_TEE_GetPropertyAsIdentity, CmdTEEGetPropertyAsIdentity_withoutEnum },
    { CMD_TEE_GetPropertyAsU32, CmdTEEGetPropertyAsU32 },
    { CMD_TEE_Malloc, CmdTEEMalloc },
    { CMD_TEE_Realloc, CmdTEERealloc },
    { CMD_TEE_MemMove, CmdTEEMemMove },
    { CMD_TEE_MemCompare, CmdTEEMemCompare },
    { CMD_TEE_MemFill, CmdTEEMemFill },
    { CMD_TEE_Free, CmdTEEFree },
    { CMD_TEE_CheckMemoryAccessRights, CmdTEECheckMemoryAccessRights },
    { CMD_TEE_GetInstanceData, CmdTEEGetInstanceData },
    { CMD_TEE_SetInstanceData, CmdTEESetInstanceData },
    { CMD_TEE_OpenTASession, CmdTEEOpenTASession },
    { CMD_TEE_InvokeTACommand, CmdTEEInvokeTACommand },
    { CMD_TEE_CloseTASession, CmdTEECloseTASession },
    { CMD_TEE_ShareMemAPI, CmdTEEShareMemTest },
};

uint32_t g_testTableSize = sizeof(g_testTable) / sizeof(g_testTable[0]);

TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t cmd, uint32_t parmType, TEE_Param params[4])
{
    TEE_Result ret = TEE_SUCCESS;
    (void)sessionContext;
    uint32_t i;
    tlogi("---- TA invoke command ----------- command id: 0x%x", cmd);

    for (i = 0; i < g_testTableSize; i++) {
        if (cmd == g_testTable[i].cmdId) {
            ret = g_testTable[i].funcName(parmType, params);
            if (ret != TEE_SUCCESS) {
                tloge("invoke command with cmdId: 0x%x failed! ret: 0x%x", cmd, ret);
            } else {
                tlogi("invoke command with cmdId: 0x%x success! ret: 0x%x", cmd, ret);
            }
            return ret;
        }
    }

    tloge("not support this invoke command! cmdId: 0x%x", cmd);
    return TEE_ERROR_GENERIC;
}

void TA_CloseSessionEntryPoint(void *sessionContext)
{
    (void)sessionContext;
    tlogi("---- TA_CloseSessionEntryPoint -----");
}

void TA_DestroyEntryPoint(void)
{
    tlogi("---- TA_DestroyEntryPoint ----");
}
