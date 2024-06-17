/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain longVal1 copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include <tee_ext_api.h>
#include <tee_log.h>
#include <securec.h>
#include <tee_arith_api.h>
#include <tee_mem_mgmt_api.h>
#include "test_arithmetic_api_base.h"

static uint8_t g_modValue[] = {
    0x40, 0x84, 0xB4, 0xAF, 0xF9, 0x13, 0xE0, 0x2B, 0xFF, 0x2D, 0x30, 0x21, 0x7C, 0x94, 0xD2, 0x8F,
    0x89, 0x47, 0x9F, 0x7E, 0x14, 0xC1, 0xB4, 0xD7, 0x64, 0x97, 0x33, 0x65, 0x26, 0x62, 0x86, 0xED
};
static uint8_t g_bigIntValue[] = {
    0x1C, 0xE1, 0x0C, 0xAE, 0x61, 0xBE, 0xE9, 0xD5, 0x5D, 0xB0, 0xC0, 0x93, 0x5F, 0x78, 0x8C, 0x3C,
    0xA1, 0x44, 0x3B, 0x6F, 0x08, 0xC6, 0x6A, 0x7E, 0x87, 0x32, 0xE9, 0x37, 0xB5, 0xE6, 0x87, 0x6E,
};

static TEE_BigIntFMM* AllocateAndInitializeFMM(uint32_t modulusSizeInBits)
{
    uint32_t length = TEE_BigIntFMMSizeInU32(modulusSizeInBits);
    TEE_BigIntFMM *bigIntFMM = (TEE_BigIntFMM *)TEE_Malloc(length * sizeof(TEE_BigIntFMM), 0);
    if (bigIntFMM == NULL) {
        tloge("AllocateAndInitializeFMM : TEE_Malloc returned NULL.");
        return NULL;
    }

    TEE_BigIntInitFMM(bigIntFMM, length);
    return bigIntFMM;
}

TEE_Result TestBigIntInitFMM()
{
    tlogi("[%s] begin:", __FUNCTION__);
    uint32_t length = TEE_BigIntFMMSizeInU32(SIZE_256);
    const uint32_t checkLength = 10;
    if (length != checkLength) {
        tloge("BigIntFMMSizeInU32 fail. length = %d", length);
        return TEE_ERROR_GENERIC;
    }

    TEE_BigIntFMM *bigIntFMM = (TEE_BigIntFMM *)TEE_Malloc(length * sizeof(TEE_BigIntFMM), 0);
    if (bigIntFMM == NULL) {
        tloge("AllocateAndInitializeFMM : TEE_Malloc returned NULL.");
        return TEE_ERROR_GENERIC;
    }

    TEE_BigIntInitFMM(bigIntFMM, length);
    TEE_Free(bigIntFMM);
    tlogi("[%s] end. ret = 0x%x.", __FUNCTION__, TEE_SUCCESS);
    return TEE_SUCCESS;
}

TEE_Result TestBigIntInitFMMContext()
{
    tlogi("[%s] begin:", __FUNCTION__);
    uint32_t length = TEE_BigIntFMMContextSizeInU32(SIZE_256);
    const uint32_t checkLength = 10;
    if (length != checkLength) {
        tloge("BigIntFMMContextSizeInU32 fail. length = %d", length);
        return TEE_ERROR_GENERIC;
    }

    TEE_BigIntFMMContext *bigIntFMMContext = TEE_Malloc(length * sizeof(TEE_BigIntFMMContext), 0);
    if (bigIntFMMContext == NULL) {
        tloge("CmdTEEBigIntInitFMMContext: TEE_Malloc returned NULL.");
        return TEE_ERROR_GENERIC;
    }
    TEE_BigIntFMMContext *bigIntFMMContext1 = TEE_Malloc(length * sizeof(TEE_BigIntFMMContext), 0);
    if (bigIntFMMContext1 == NULL) {
        tloge("CmdTEEBigIntInitFMMContext: TEE_Malloc returned NULL.");
        TEE_Free(bigIntFMMContext);
        return TEE_ERROR_GENERIC;
    }

    const uint8_t p1Value[] = {
        0x40, 0x84, 0xB4, 0xAF, 0xF9, 0x13, 0xE0, 0x2B, 0xFF, 0x2D, 0x30, 0x21, 0x7C, 0x94, 0xD2, 0x8F,
        0x89, 0x47, 0x9F, 0x7E, 0x14, 0xC1, 0xB4, 0xD7, 0x64, 0x97, 0x33, 0x65, 0x26, 0x62, 0x86, 0xED
    };
    TEE_BigInt *bigInt = CreateBigInt(sizeof(p1Value), (uint8_t *)p1Value);
    TEE_BigIntInitFMMContext(bigIntFMMContext, length, bigInt);

    TEE_Result ret = TEE_BigIntInitFMMContext1(bigIntFMMContext1, length, bigInt);
    if (ret != TEE_SUCCESS) {
        tloge("TEE_BigIntInitFMMContext1 test failed. ret = 0x%x", ret);
    }
    TEE_Free(bigIntFMMContext);
    TEE_Free(bigIntFMMContext1);
    TEE_Free(bigInt);

    tlogi("[%s] end. ret = 0x%x.", __FUNCTION__, ret);
    return ret;
}

TEE_Result TestConverterBigIntAndFMM()
{
    tlogi("[%s] begin:", __FUNCTION__);
    TEE_Result ret = TEE_SUCCESS;

    TEE_BigInt *bigInt = CreateBigInt(sizeof(g_bigIntValue), g_bigIntValue);
    if (bigInt == NULL) {
        return TEE_ERROR_GENERIC;
    }
    TEE_BigInt *modulus = CreateBigInt(sizeof(g_modValue), g_modValue);
    if (modulus == NULL) {
        TEE_Free(bigInt);
        return TEE_ERROR_GENERIC;
    }
    TEE_BigInt *bigIntFMM = AllocateAndInitializeFMM(SIZE_256);
    if (bigIntFMM == NULL) {
        TEE_Free(modulus);
        TEE_Free(bigInt);
        return TEE_ERROR_GENERIC;
    }
    uint32_t length = TEE_BigIntFMMContextSizeInU32(SIZE_256);
    TEE_BigIntFMMContext *bigIntFMMContext = TEE_Malloc(length * sizeof(TEE_BigIntFMMContext), 0);
    if (bigIntFMMContext == NULL) {
        tloge("CmdTEEBigIntInitFMMContext: TEE_Malloc returned NULL.");
        TEE_Free(bigInt);
        TEE_Free(modulus);
        TEE_Free(bigIntFMM);
        return TEE_ERROR_GENERIC;
    }

    TEE_BigIntInitFMMContext(bigIntFMMContext, length, modulus);
    TEE_BigIntConvertToFMM(bigIntFMM, bigInt, modulus, bigIntFMMContext);

    TEE_BigInt *convertedBigInt = CreateBigInt(RESULT_SIZE, 0);
    if (convertedBigInt == NULL) {
        ret = TEE_ERROR_GENERIC;
        goto CLEAN_UP;
    }
    TEE_BigIntConvertFromFMM(convertedBigInt, bigIntFMM, modulus, bigIntFMMContext);
    int32_t isSame = TEE_BigIntCmp(convertedBigInt, bigInt);
    if (isSame != 0) {
        ret = TEE_ERROR_GENERIC;
    }
    TEE_Free(convertedBigInt);

CLEAN_UP:
    TEE_Free(bigIntFMMContext);
    TEE_Free(bigIntFMM);
    TEE_Free(bigInt);
    TEE_Free(modulus);

    tlogi("[%s] end. ret = 0x%x.", __FUNCTION__, ret);
    return ret;
}

TEE_Result TestBigIntComputeFMM()
{
    tlogi("[%s] begin:", __FUNCTION__);
    TEE_Result ret = TEE_SUCCESS;
    TEE_BigInt *bigInt = AllocateAndInitialize(SIZE_256);
    if (bigInt == NULL)
        return TEE_ERROR_GENERIC;

    TEE_BigIntFMM *destBigIntFMM = AllocateAndInitializeFMM(SIZE_256);
    if (destBigIntFMM == NULL) {
        TEE_Free(bigInt);
        return TEE_ERROR_GENERIC;
    }

    TEE_BigIntFMM *op1BigIntFMM = AllocateAndInitializeFMM(SIZE_256);
    if (op1BigIntFMM == NULL) {
        TEE_Free(bigInt);
        TEE_Free(destBigIntFMM);
        return TEE_ERROR_GENERIC;
    }

    TEE_BigIntFMM *op2BigIntFMM = AllocateAndInitializeFMM(SIZE_256);
    if (op2BigIntFMM == NULL) {
        TEE_Free(bigInt);
        TEE_Free(destBigIntFMM);
        TEE_Free(op1BigIntFMM);
        return TEE_ERROR_GENERIC;
    }

    uint32_t length = TEE_BigIntFMMContextSizeInU32(SIZE_256);
    TEE_BigIntFMMContext *bigIntFMMContext = TEE_Malloc(length * sizeof(TEE_BigIntFMMContext), 0);
    if (bigIntFMMContext == NULL) {
        tloge("CmdTEEBigIntInitFMMContext: TEE_Malloc returned NULL.");
        ret = TEE_ERROR_GENERIC;
        goto CLEAN_UP;
    }

    tlogi("after TEE_BigIntFMMContextSizeInU32, length = %u", length);
    TEE_BigIntComputeFMM(destBigIntFMM, op1BigIntFMM, op2BigIntFMM, bigInt, bigIntFMMContext);
    TEE_Free(bigIntFMMContext);

CLEAN_UP:
    TEE_Free(bigInt);
    TEE_Free(destBigIntFMM);
    TEE_Free(op1BigIntFMM);
    TEE_Free(op2BigIntFMM);

    tlogi("[%s] end. ret = 0x%x.", __FUNCTION__, ret);
    return ret;
}