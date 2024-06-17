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

TEE_Result TestBigIntCmp()
{
    tlogi("[%s] begin:", __FUNCTION__);
    TEE_Result ret = TEE_SUCCESS;
    const uint8_t op1Value[] = {
        0x6A, 0xA2, 0xC3, 0xD4, 0x94, 0xFD, 0xB7, 0xE2, 0xF0, 0xFC, 0x91, 0x72, 0xC1, 0x50, 0x2A, 0x2C
    };
    const uint8_t op2Value[] = {
        0x35, 0x51, 0x61, 0xEA, 0x4A, 0x7E, 0xDB, 0xF1, 0x78, 0x7E, 0x48, 0xB9, 0x60, 0xA8, 0x15, 0x16
    };

    TEE_BigInt *op1 = CreateBigInt(sizeof(op1Value), (uint8_t *)op1Value);
    TEE_BigInt *op2 = CreateBigInt(sizeof(op2Value), (uint8_t *)op2Value);
    int32_t result = TEE_BigIntCmp(op1, op2);
    if (result < 0) {
        tloge("BigIntCmp fail.");
        ret = TEE_ERROR_GENERIC;
    }

    TEE_Free(op1);
    TEE_Free(op2);
    tlogi("[%s] end. ret = 0x%x.", __FUNCTION__, ret);
    return ret;
}

TEE_Result TestBigIntCmpS32()
{
    tlogi("[%s] begin:", __FUNCTION__);
    TEE_Result ret = TEE_SUCCESS;
    const uint8_t opValue[] = {
        0x6A, 0xA2, 0xC3, 0xD4, 0x94, 0xFD, 0xB7, 0xE2, 0xF0, 0xFC, 0x91, 0x72, 0xC1, 0x50, 0x2A, 0x2C
    };

    TEE_BigInt *op = CreateBigInt(sizeof(opValue), (uint8_t *)opValue);
    int32_t result = TEE_BigIntCmpS32(op, 0);
    if (result < 0) {
        tloge("BigIntCmpS32 fail.");
        ret = TEE_ERROR_GENERIC;
    }

    TEE_Free(op);
    tlogi("[%s] end. ret = 0x%x.", __FUNCTION__, ret);
    return ret;
}

TEE_Result TestBigIntShiftRight()
{
    tlogi("[%s] begin:", __FUNCTION__);
    TEE_Result ret = TEE_SUCCESS;
    const uint8_t opValue[] = {
        0x6A, 0xA2, 0xC3, 0xD4, 0x94, 0xFD, 0xB7, 0xE2, 0xF0, 0xFC, 0x91, 0x72, 0xC1, 0x50, 0x2A, 0x2C
    };
    const uint8_t checkValue[] = {
        0x35, 0x51, 0x61, 0xEA, 0x4A, 0x7E, 0xDB, 0xF1, 0x78, 0x7E, 0x48, 0xB9, 0x60, 0xA8, 0x15, 0x16
    };
    TEE_BigInt *dest = CreateBigInt(RESULT_SIZE, 0);
    TEE_BigInt *op = CreateBigInt(sizeof(opValue), (uint8_t *)opValue);
    TEE_BigInt *check = CreateBigInt(sizeof(checkValue), (uint8_t *)checkValue);
    TEE_BigIntShiftRight(dest, op, 1);
    if (TEE_BigIntCmp(dest, check) != 0) {
        tloge("BigIntShiftRight fail.");
        ret = TEE_ERROR_GENERIC;
    }

    TEE_Free(dest);
    TEE_Free(op);
    TEE_Free(check);
    tlogi("[%s] end. ret = 0x%x.", __FUNCTION__, ret);
    return ret;
}

TEE_Result TestBigIntGetBit()
{
    tlogi("[%s] begin:", __FUNCTION__);
    const uint8_t opValue[] = {0x01, 0x11, 0x01, 0x11};
    const uint32_t bitIndex = 2;

    TEE_BigInt *src = CreateBigInt(sizeof(opValue), (uint8_t *)opValue);
    bool bitValue = TEE_BigIntGetBit(src, bitIndex);
    if (bitValue) { // expect bitValue is 0.
        tloge("BigIntGetBit failed.");
        return TEE_ERROR_GENERIC;
    }
    TEE_Free(src);
    return TEE_SUCCESS;
}

TEE_Result TestBigIntGetBitCount()
{
    tlogi("[%s] begin:", __FUNCTION__);
    const uint8_t opValue[] = {0x01, 0x11, 0x11, 0x10};
    const uint32_t check = 25;
    TEE_BigInt *src = CreateBigInt(sizeof(opValue), (uint8_t *)opValue);
    uint32_t count = TEE_BigIntGetBitCount(src);
    if (count != check) {
        tloge("BigIntGetBitCount fail. count = %d.", count);
        return TEE_ERROR_GENERIC;
    }
    TEE_Free(src);
    return TEE_SUCCESS;
}

#if defined(API_LEVEL) && (API_LEVEL >= API_LEVEL1_2)
TEE_Result TestBigIntSetBit()
{
    tlogi("[%s] begin:", __FUNCTION__);
    const uint8_t opValue[] = {0x01, 0x11, 0x01, 0x11};
    const uint32_t bitIndex = 4;
    TEE_BigInt *src = CreateBigInt(sizeof(opValue), (uint8_t *)opValue);

    uint32_t value = TEE_BigIntGetBit(src, bitIndex);
    value = (value == 1 ? 0 : 1);
    TEE_Result ret = TEE_BigIntSetBit(src, bitIndex, value); // action return overflow
    if (ret != TEE_SUCCESS) {
        tloge("error occurs in set bit operation. ret = 0x%x", ret);
        TEE_Free(src);
        return ret;
    }

    if (value != TEE_BigIntGetBit(src, bitIndex)) {
        tloge("BigIntSetBit test failed.");
        ret = TEE_ERROR_GENERIC;
    }

    TEE_Free(src);
    tlogi("[%s] end. ret = 0x%x.", __FUNCTION__, ret);
    return ret;
}

TEE_Result TestBigIntAssign()
{
    tlogi("[%s] begin:", __FUNCTION__);
    TEE_Result ret = TEE_SUCCESS;
    uint8_t srcValue[] = "srcValue";
    uint8_t destValue[] = "destValue";
    TEE_BigInt *src = CreateBigInt(sizeof(srcValue), srcValue);
    TEE_BigInt *dest = CreateBigInt(sizeof(destValue), destValue);
    if (TEE_BigIntAssign(dest, src) != TEE_SUCCESS) {
        tloge("TEE_BigIntAssign test failed.\n");
        ret = TEE_ERROR_GENERIC;
        goto CLEANUP;
    }

    if (TEE_BigIntCmp(dest, src) != 0) {
        tloge("TEE_BigIntAssign test failed after cmp...\n");
        ret = TEE_ERROR_GENERIC;
    }

CLEANUP:
    TEE_Free(src);
    TEE_Free(dest);
    tlogi("[%s] end. ret = 0x%x.", __FUNCTION__, ret);
    return ret;
}

TEE_Result TestBigIntAbs()
{
    tlogi("[%s] begin:", __FUNCTION__);
    uint8_t absValue[] = "absValue";
    int32_t value = -99;
    int32_t adsValue = 0 - value;
    TEE_BigInt *src = CreateBigInt(sizeof(absValue), 0);
    TEE_BigIntConvertFromS32(src, value);

    TEE_BigInt *absDest = CreateBigInt(sizeof(absValue), absValue);
    TEE_BigIntAbs(absDest, src);
    if (TEE_BigIntCmpS32(absDest, adsValue) != 0) {
        tloge("BigIntAbs fail.");
        TEE_Free(src);
        TEE_Free(absDest);
        return TEE_ERROR_GENERIC;
    }

    TEE_Free(src);
    TEE_Free(absDest);
    tlogi("[%s] end. ret = 0x%x.", __FUNCTION__, TEE_SUCCESS);
    return TEE_SUCCESS;
}
#else
TEE_Result TestBigIntSetBit()
{
    tlogi("API_LEVEL is %d, [%s] is not supported. Return success.", API_LEVEL, __FUNCTION__);
    return TEE_SUCCESS;
}

TEE_Result TestBigIntAssign()
{
    tlogi("API_LEVEL is %d, [%s] is not supported. Return success.", API_LEVEL, __FUNCTION__);
    return TEE_SUCCESS;
}

TEE_Result TestBigIntAbs()
{
    tlogi("API_LEVEL is %d, [%s] is not supported. Return success.", API_LEVEL, __FUNCTION__);
    return TEE_SUCCESS;
}
#endif
