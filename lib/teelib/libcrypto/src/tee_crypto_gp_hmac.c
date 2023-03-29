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
#include "tee_crypto_api.h"
#include <string.h>
#include <tee_log.h>
#include <crypto_driver_adaptor.h>
#include <crypto_inner_defines.h>
#include <crypto_hal_hmac.h>
#include <tee_property_inner.h>
#include <tee_object_api.h>
#include "tee_operation.h"

TEE_Result TEE_MACCompareFinal(TEE_OperationHandle operation, const void *message, size_t messageLen,
        const void *mac, const size_t macLen)
{
    uint8_t hmac_result_buff_temp[MAX_HMAC_LEN] = { 0 };
    size_t size = macLen;

    TEE_Result ret = TEE_MACComputeFinal(operation, message, messageLen, hmac_result_buff_temp, &size);
    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    if (ret != TEE_SUCCESS) {
        tloge("MAC compute final failed\n");
        goto error;
    }

    bool check = (size != macLen || TEE_MemCompare((void *)hmac_result_buff_temp, mac, (uint32_t)size) != 0);
    if (check) {
        tloge("size 0x%x != macLen 0x%x or compare failed!\n", size, macLen);
        ret = TEE_ERROR_MAC_INVALID;
        goto error;
    }

    free_operation_ctx(operation);
    crypto_unlock_operation(operation);
    return ret;
error:
    free_operation_ctx(operation);
    crypto_unlock_operation(operation);
    if (ret != TEE_ERROR_MAC_INVALID)
        TEE_Panic(ret);
    return ret;
}
