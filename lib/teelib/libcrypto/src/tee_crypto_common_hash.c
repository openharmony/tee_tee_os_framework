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
#include "tee_crypto_common_hash.h"
#include <string.h>
#include <tee_log.h>
#include <tee_property_inner.h>
#include <tee_object_api.h>
#include <crypto_inner_defines.h>
#include <crypto_hal_hash.h>
#include <crypto_driver_adaptor.h>
#include "tee_operation.h"

struct digest_op_config_s {
    uint32_t expect_class;
    uint32_t expect_mode;
    uint32_t algorithm;
};

static const struct digest_op_config_s g_digest_config[] = {
    { TEE_OPERATION_DIGEST, TEE_MODE_DIGEST, TEE_ALG_MD5 },
    { TEE_OPERATION_DIGEST, TEE_MODE_DIGEST, TEE_ALG_SHA1 },
    { TEE_OPERATION_DIGEST, TEE_MODE_DIGEST, TEE_ALG_SHA224 },
    { TEE_OPERATION_DIGEST, TEE_MODE_DIGEST, TEE_ALG_SHA256 },
    { TEE_OPERATION_DIGEST, TEE_MODE_DIGEST, TEE_ALG_SHA384 },
    { TEE_OPERATION_DIGEST, TEE_MODE_DIGEST, TEE_ALG_SHA512 },
    { TEE_OPERATION_DIGEST, TEE_MODE_DIGEST, TEE_ALG_SM3 },
};

TEE_Result digest_operation_state_check(const TEE_OperationHandle operation)
{
    const struct digest_op_config_s *config = NULL;
    uint32_t index;

    if (operation == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    uint32_t api_level = tee_get_ta_api_level();
    if (api_level >= API_LEVEL1_1_1) {
        if ((operation->handleState & TEE_HANDLE_FLAG_KEY_SET) != TEE_HANDLE_FLAG_KEY_SET) {
            tloge("Invalid operation key state for this operation\n");
            return TEE_ERROR_BAD_STATE;
        }

        if ((operation->handleState & TEE_HANDLE_FLAG_INITIALIZED) != TEE_HANDLE_FLAG_INITIALIZED) {
            tloge("Cipher is not initialized yet\n");
            return TEE_ERROR_BAD_STATE;
        }
    }

    for (index = 0; index < ELEM_NUM(g_digest_config); index++) {
        if (operation->algorithm == g_digest_config[index].algorithm) {
            config = &g_digest_config[index];
            break;
        }
    }

    bool check = (config == NULL || operation->operationClass != config->expect_class ||
        operation->mode != config->expect_mode);
    if (check) {
        tloge("This operation is Invalid!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

TEE_Result proc_hal_digest_init(TEE_OperationHandle operation)
{
    if (operation == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    crypto_hal_info *crypto_hal_data = operation->hal_info;
    if (crypto_hal_data == NULL) {
        tloge("crypto hal data is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (crypto_hal_data->digestalloc_flag == DIGEST_ALLOC_CTX)
        return TEE_SUCCESS;

    free_operation_ctx(operation);
    operation->crypto_ctxt = tee_crypto_hash_init(operation->algorithm, crypto_hal_data->crypto_flag);
    if (operation->crypto_ctxt == NULL)
        return TEE_ERROR_GENERIC;

    crypto_hal_data->digestalloc_flag = DIGEST_ALLOC_CTX;
    return TEE_SUCCESS;
}

TEE_Result proc_hal_digest_update(TEE_OperationHandle operation, const void *chunk, size_t chunk_size)
{
    struct memref_t data_in = {0};

    if (operation == NULL || chunk == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    data_in.buffer = (uint64_t)(uintptr_t)chunk;
    data_in.size = (uint32_t)chunk_size;

    TEE_Result result = proc_hal_digest_init(operation);
    if (result != TEE_SUCCESS)
        return result;

    int32_t ret = tee_crypto_hash_update(operation->crypto_ctxt, &data_in);
    if (ret != TEE_SUCCESS)
        return change_hal_ret_to_gp(ret);

    return TEE_SUCCESS;
}

