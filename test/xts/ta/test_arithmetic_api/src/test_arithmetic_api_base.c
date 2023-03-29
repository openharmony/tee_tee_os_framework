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
#include <tee_arith_api.h>
#include <tee_mem_mgmt_api.h>
#include "test_arithmetic_api_base.h"

TEE_BigInt* AllocateAndInitialize(uint32_t bitSize)
{
    uint32_t length = TEE_BigIntSizeInU32(bitSize);
    TEE_BigInt *bigInt = (TEE_BigInt *)TEE_Malloc(length * sizeof(TEE_BigInt), 0);
    if (bigInt == NULL) {
        tloge("AllocateAndInitialize : TEE_Malloc returned NULL.");
        return NULL;
    }

    TEE_BigIntInit(bigInt, length);
    return bigInt;
}

TEE_BigInt *CreateBigInt(uint32_t size, uint8_t *buffer)
{
    TEE_BigInt *bigInt = (TEE_BigInt *)TEE_Malloc(TEE_BigIntSizeInU32(size * BIT_OF_CHAR) * sizeof(uint32_t), 0);
    if (bigInt == NULL) {
        return 0;
    }

    TEE_BigIntInit(bigInt, TEE_BigIntSizeInU32(size * BIT_OF_CHAR));
    if (buffer != NULL) {
        TEE_BigIntConvertFromOctetString(bigInt, buffer, size, 0);
    }
    return bigInt;
}

TEE_Result TestBigIntInit()
{
    tlogi("[%s] begin:", __FUNCTION__);
    TEE_Result ret = TEE_SUCCESS;
    uint32_t length = TEE_BigIntSizeInU32(SIZE_256);
    TEE_BigInt *bigInt = (TEE_BigInt *)TEE_Malloc(length * sizeof(TEE_BigInt), 0);
    if (bigInt == NULL) {
        tloge("AllocateAndInitializeFMM : TEE_Malloc returned NULL.");
        return TEE_ERROR_GENERIC;
    }

    TEE_BigIntInit(bigInt, length);
    if (TEE_BigIntCmpS32(bigInt, 0) != 0) {
        tloge("BigIntInit fail.");
        ret = TEE_ERROR_GENERIC;
    }

    TEE_Free(bigInt);
    tlogi("[%s] end. ret = 0x%x.", __FUNCTION__, ret);
    return ret;
}