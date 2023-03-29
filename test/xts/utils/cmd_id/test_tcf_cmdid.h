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
#ifndef __TEST_TCF_CMDID_H__
#define __TEST_TCF_CMDID_H__

typedef enum {
    CMD_TEE_GetPropertyAsString = 0,
    CMD_TEE_GetPropertyAsBool,
    CMD_TEE_GetPropertyAsU32,
    CMD_TEE_GetPropertyAsU64,
    CMD_TEE_GetPropertyAsBinaryBlock,
    CMD_TEE_GetPropertyAsUUID,
    CMD_TEE_GetPropertyAsIdentity,
    CMD_TEE_AllocatePropertyEnumerator,
    CMD_TEE_FreePropertyEnumerator,
    CMD_TEE_StartPropertyEnumerator,
    CMD_TEE_ResetPropertyEnumerator,
    CMD_TEE_GetPropertyNameEnumerator,
    CMD_TEE_GetNextPropertyEnumerator,
    CMD_TEE_Malloc,
    CMD_TEE_Free,
    CMD_TEE_Realloc,
    CMD_TEE_MemMove,
    CMD_TEE_MemCompare,
    CMD_TEE_MemFill,
    CMD_TEE_CheckMemoryAccessRights,
    CMD_TEE_GetInstanceData,
    CMD_TEE_SetInstanceData,
    CMD_TEE_OpenTASession,
    CMD_TEE_InvokeTACommand,
    CMD_TEE_CloseTASession,
    CMD_TEE_Panic,
} TCFCmdId;

#define INPUT_ISNULL 1
#define OUTPUT_ISNULL 2
#define OUTPUTBUFFERSIZE_ISNULL 3
#define OUTPUTBUFFERSIZE_ISZERO 4
#define OUTPUTBUFFERSIZE_TOOSHORT 5
#define BUFFER_ISNOT_MALLOC 6
#define BUFFERSIZE_ISTOOBIG 7
#define BUFFER_IS_FREE 8
#define BUFFER_IS_PARAM 9
#define DESTANDSRC_ISSAME 10
#define DESTANDSRC_OVERLAP 11
#define BUFFER_IS_GLOBALVAR 12
#define BUFFER_IS_GLOBALCONSTVAR 13
#define RETURNORIGIN_ISNULL 14
#define TA_CRASH_FLAG 15
#define BUFFER_NOFILLNOSHARE 16
#endif