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

#include <tee_ext_api.h>
#include <tee_log.h>
#include <securec.h>
#include "test_converter_function.h"
#include "test_arithmetic_api_base.h"
#include "test_basic_arithmetic_operation.h"
#include "test_modular_arithmetic_operation.h"
#include "test_logical_operation.h"
#include "test_other_arithmetic_operation.h"
#include "test_fast_modular_multiplication_operation.h"

#define CA_VENDOR "/vendor/bin/tee_test_arithmetic_api"
#define CA_SYSTEM "/system/bin/tee_test_arithmetic_api"
#define CA_UID 0

typedef TEE_Result (* TestArithmeticApiFunc)(void);

typedef struct {
    uint32_t cmdId;
    TestArithmeticApiFunc func;
} TestFunctionWithCmd;

static TestFunctionWithCmd g_CmdList[] = {
    {CMD_ID_TEST_BIG_INT_COMPUTE_FMM, TestBigIntComputeFMM}, // 0
    {CMD_ID_TEST_BIG_INT_INIT_FMM_CONTEXT, TestBigIntInitFMMContext},
    {CMD_ID_TEST_CONVERTER_BETWEEN_BIG_INT_AND_FMM, TestConverterBigIntAndFMM},
    {CMD_ID_TEST_BIG_INT_EXP_MOD, TestBigIntExpMod},
    {CMD_ID_TEST_CONVERTER_BETWEEN_BIG_INT_AND_OCTET_STRING, TestConverterBetweenBitInAndOctetString},
    {CMD_ID_TEST_CONVERTER_BETWEEN_BIG_INT_AND_S32, TestConverterBetweenBitInAndS32}, // 5
    {CMD_ID_TEST_BIG_INT_ADD_AND_SUB_MOD, TestBigIntAddAndSubMod},
    {CMD_ID_TEST_BIG_INT_MUL_AND_INV_MOD, TestBigIntMulAndInvMod},
    {CMD_ID_TEST_BIG_INT_MOD, TestBigIntMod},
    {CMD_ID_TEST_BIG_INT_ADD_AND_SUB, TestBigIntAddAndSub},
    {CMD_ID_TEST_BIG_INT_NEG, TestBigIntNeg}, // 10
    {CMD_ID_TEST_BIG_INT_MUL_AND_SQUARE, TestBigIntMulAndSquare},
    {CMD_ID_TEST_BIG_INT_DIV, TestBigIntDiv},
    {CMD_ID_TEST_BIG_INT_SHIFT_RIGHT, TestBigIntShiftRight},
    {CMD_ID_TEST_BIG_INT_GET_BIT, TestBigIntGetBit},
    {CMD_ID_TEST_BIG_INT_GET_BIT_COUNT, TestBigIntGetBitCount}, // 15
    {CMD_ID_TEST_BIG_INT_SET_BIT, TestBigIntSetBit},
    {CMD_ID_TEST_BIG_INT_ASSIGN, TestBigIntAssign},
    {CMD_ID_TEST_BIG_INT_ABS, TestBigIntAbs},
    {CMD_ID_TEST_BIG_INT_RELATIVE_PRIME, TestBigIntRelativePrime},
    {CMD_ID_TEST_BIG_INT_COMPUTE_EXTENTED_GCD, TestBigIntComputeExtentedGcd}, // 20
    {CMD_ID_TEST_BIG_INT_IS_PROBABLE_PRIME, TestBigIntIsProbablePrime},
    {CMD_ID_TEST_BIG_INT_CMP, TestBigIntCmp},
    {CMD_ID_TEST_BIG_INT_CMP_S32, TestBigIntCmpS32},
    {CMD_ID_TEST_BIG_INT_INIT_FMM, TestBigIntInitFMM},
    {CMD_ID_TEST_BIG_INT_INIT, TestBigIntInit},
};

static TEE_Result TestArithmeticApi(uint32_t cmdId)
{
    uint32_t count = sizeof(g_CmdList) / sizeof(g_CmdList[0]);
    tlogi("[TestArithmeticApi]: g_CmdList count = %d, cmdId = %d\n", count, cmdId);
    for (uint32_t i = 0; i < count; i++) {
        if (g_CmdList[i].cmdId == cmdId) {
            return g_CmdList[i].func();
        }
    }

    tlogi("unknown command id, cmdId: %u\n", cmdId);
    return TEE_ERROR_INVALID_CMD;
}


TEE_Result TA_CreateEntryPoint(void)
{
    tlogi("---- TA_CreateEntryPoint ---------");
    TEE_Result ret = AddCaller_CA_exec(CA_VENDOR, CA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("Arithmetic TA Add caller failed, ret = 0x%x", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(CA_SYSTEM, CA_UID);
    if (ret != TEE_SUCCESS) {
        tloge("Arithmetic TA Add caller failed, ret = 0x%x", ret);
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

TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t cmdId, uint32_t parmType, TEE_Param params[4])
{
    TEE_Result ret = TEE_SUCCESS;
    (void)sessionContext;
    (void)params;
    (void)parmType;

    ret = TestArithmeticApi(cmdId);
    if (ret != TEE_SUCCESS)
        tloge("Arithmetic TA invoke command for value failed! cmdId: %u, ret: 0x%x", cmdId, ret);

    return ret;
}

void TA_CloseSessionEntryPoint(void *sessionContext)
{
    (void)sessionContext;
    tlogi("------ TA_CloseSessionEntryPoint -----");
}

void TA_DestroyEntryPoint(void)
{
    tlogi("------ TA_DestroyEntryPoint ----");
}