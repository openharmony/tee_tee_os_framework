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
#include "tee_crypto_hal.h"
#include <tee_log.h>
#include <tee_defines.h>
#include <crypto_hal.h>
#include <tee_object_api.h>
#include <crypto_inner_defines.h>
#include "tee_crypto_api.h"

TEE_Result TEE_SetCryptoFlag(TEE_OperationHandle operation, uint32_t crypto)
{
    if (operation == NULL) {
        tloge("operation is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    crypto_hal_info *crypto_hal_data = (crypto_hal_info *)(operation->hal_info);
    if (crypto_hal_data == NULL) {
        tloge("Crypto hal info is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    bool check =
        (((operation->operationClass == TEE_OPERATION_DIGEST) && (crypto_hal_data->digestalloc_flag == 1)) ||
         ((operation->operationClass != TEE_OPERATION_DIGEST) &&
          ((operation->handleState & TEE_HANDLE_FLAG_INITIALIZED) ||
           (operation->handleState & TEE_HANDLE_FLAG_KEY_SET))));
    if (check) {
        tloge("operation state is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    crypto_hal_data->crypto_flag = crypto;
    return TEE_SUCCESS;
}
TEE_Result TEE_SetObjectFlag(TEE_ObjectHandle object, uint32_t crypto)
{
    if (object == NULL) {
        tloge("object is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (crypto >= CRYPTO_ENGINE_MAX) {
        tloge("flag is invalid!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    object->generate_flag = crypto;
    return TEE_SUCCESS;
}

TEE_Result TEE_IsHardWareSupportAlgorithm(uint32_t alg_type)
{
    TEE_Result ret;

    ret = (TEE_Result)tee_crypto_check_alg_support(alg_type);
    if (ret == 0)
        return TEE_SUCCESS;

    return TEE_ERROR_NOT_SUPPORTED;
}
