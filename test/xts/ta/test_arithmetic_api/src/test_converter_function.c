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

TEE_Result TestConverterBetweenBitInAndOctetString()
{
    tlogi("[%s] begin:", __FUNCTION__);
    TEE_BigInt *bigInt = AllocateAndInitialize(SIZE_256);
    if (bigInt == NULL) {
        return TEE_ERROR_GENERIC;
    }

    const uint8_t string[] = "tempString";
    TEE_Result ret = TEE_BigIntConvertFromOctetString((TEE_BigInt *)bigInt, string, sizeof(string), -1);
    if (ret != TEE_SUCCESS) {
        tloge("BigIntConvertFromOctetString failed, ret = 0x%x", ret);
        goto CLEANUP;
    }

    uint8_t buffer[SIZE_256] = {0};
    size_t bufferLen = sizeof(buffer);
    ret = TEE_BigIntConvertToOctetString(buffer, &bufferLen, bigInt);
    if (ret != TEE_SUCCESS) {
        tloge("BigIntConvertToOctetString failed, ret = 0x%x", ret);
        goto CLEANUP;
    }
    if (strcmp((const char *)buffer, (const char *)string) != 0) {
        tloge("convert failed. string is %s; buffer is %s;", string, buffer);
        ret = TEE_ERROR_GENERIC;
    }
    tlogi("after convert buffer is %s", buffer);

CLEANUP:
    TEE_Free(bigInt);
    tlogi("[%s] end. ret = 0x%x.", __FUNCTION__, ret);
    return ret;
}

TEE_Result TestConverterBetweenBitInAndS32()
{
    tlogi("[%s] begin:", __FUNCTION__);
    TEE_BigInt *bigInt = AllocateAndInitialize(SIZE_256);
    if (bigInt == NULL) {
        return TEE_ERROR_GENERIC;
    }

    const int32_t shortVal = 1234;
    TEE_BigIntConvertFromS32(bigInt, shortVal);

    int32_t value;
    TEE_Result ret = TEE_BigIntConvertToS32(&value, bigInt);
    if (ret != TEE_SUCCESS) {
        tloge("BigIntConvertToS32 failed, ret = 0x%x", ret);
        goto CLEANUP;
    }
    if (value != shortVal) {
        tloge("convert failed. value is %d; shortVal is %d", value, shortVal);
        ret = TEE_ERROR_GENERIC;
    }
    tlogi("after convert value is %d", value);

CLEANUP:
    TEE_Free(bigInt);
    tlogi("[%s] end. ret = 0x%x.", __FUNCTION__, ret);
    return ret;
}

