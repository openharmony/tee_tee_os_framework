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
#include <tee_property_inner.h>
#include <tee_object_api.h>
#include <crypto_inner_defines.h>
#include <crypto_hal_hash.h>
#include <crypto_driver_adaptor.h>
#include "tee_operation.h"
#include "tee_crypto_common_hash.h"

/* For GP compatible, we add some panic when there is some error, For common use, we need to disable this panic */
#ifndef GP_COMPATIBLE
#define TEE_Panic(x) \
    do {             \
    } while (0)
#endif

static TEE_Result digest_update_param_check(TEE_OperationHandle operation, const void *chunk, size_t chunk_size)
{
    bool check = (operation == NULL || chunk == NULL || chunk_size == 0 ||
        (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("operation handle or other param is Invalid!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (tee_get_ta_api_level() > API_LEVEL1_0 && chunk_size > MAX_SRC_SIZE) {
        tloge("The chunk size is invalid!");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

TEE_Result tee_digest_update100(TEE_OperationHandle operation, const void *chunk, size_t chunk_size)
{
    TEE_Result ret = digest_update_param_check(operation, chunk, chunk_size);
    if (ret != TEE_SUCCESS) {
        TEE_Panic(ret);
        return ret;
    }

    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    ret = digest_operation_state_check((const TEE_OperationHandle)operation);
    if (ret != TEE_SUCCESS) {
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return ret;
    }

    ret = proc_hal_digest_update(operation, chunk, chunk_size);
    crypto_unlock_operation(operation);
    if (ret != TEE_SUCCESS) {
        tloge("Do digest update failed, ret=0x%x\n", ret);
        TEE_Panic(ret);
        return ret;
    }

    return TEE_SUCCESS;
}

void tee_digest_update111(TEE_OperationHandle operation, const void *chunk, size_t chunk_size)
{
    if (tee_digest_update100(operation, chunk, chunk_size) != TEE_SUCCESS)
        tloge("Tee Digest Update failed!");
}

static TEE_Result crypto_output_buff_len_check(uint32_t algorithm, size_t output_len)
{
    for (uint32_t i = 0; i < ELEM_NUM(g_output_lower_limit); i++) {
        if (g_output_lower_limit[i].algorithm == algorithm) {
            if (output_len < g_output_lower_limit[i].output_lower_limit)
                return TEE_ERROR_SHORT_BUFFER;
            else
                return TEE_SUCCESS;
        }
    }

    return TEE_ERROR_NOT_SUPPORTED;
}

static TEE_Result proc_hal_digest_dofinal(TEE_OperationHandle operation, const void *chunk, size_t chunk_size,
        void *hash, size_t *hash_len)
{
    struct memref_t data_in = {0};
    struct memref_t data_out = {0};
    data_in.buffer = (uint64_t)(uintptr_t)chunk;
    data_in.size = (uint32_t)chunk_size;
    data_out.buffer = (uint64_t)(uintptr_t)hash;
    data_out.size = (uint32_t)(*hash_len);

    TEE_Result result = proc_hal_digest_init(operation);
    if (result != TEE_SUCCESS)
        return result;

    int32_t ret = tee_crypto_hash_dofinal(operation->crypto_ctxt, &data_in, &data_out);
    free_operation_ctx(operation);

    crypto_hal_info *crypto_hal_data = operation->hal_info;
    crypto_hal_data->digestalloc_flag = DIGEST_NO_ALLOC_CTX;
    if (ret != TEE_SUCCESS)
        return change_hal_ret_to_gp(ret);

    *hash_len = (size_t)data_out.size;

    return TEE_SUCCESS;
}

TEE_Result TEE_DigestDoFinal(TEE_OperationHandle operation, const void *chunk, size_t chunkLen, void *hash,
    size_t *hashLen)
{
    bool check = (operation == NULL || hash == NULL || hashLen == NULL || *hashLen == 0 ||
        (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("bad params");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return TEE_ERROR_GENERIC;

    TEE_Result ret = digest_operation_state_check((const TEE_OperationHandle)operation);
    if (ret != TEE_SUCCESS) {
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return ret;
    }

    if (crypto_output_buff_len_check(operation->algorithm, *hashLen) != TEE_SUCCESS) {
        tloge("Output buffer is too short\n");
        crypto_unlock_operation(operation);
        return TEE_ERROR_SHORT_BUFFER;
    }

    ret = proc_hal_digest_dofinal(operation, chunk, chunkLen, hash, hashLen);
    operation->digestLength = *hashLen;
    crypto_unlock_operation(operation);
    if (ret != TEE_SUCCESS) {
        tloge("tee proc digest failed, ret=0x%x\n", ret);
        TEE_Panic(ret);
        return ret;
    }

    return TEE_SUCCESS;
}

