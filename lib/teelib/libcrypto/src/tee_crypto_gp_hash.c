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

void TEE_DigestUpdate(TEE_OperationHandle operation, const void *chunk, size_t chunkSize)
{
    TEE_Result ret;
    bool check = (operation == NULL || chunk == NULL || chunkSize == 0 ||
        (check_operation((const TEE_OperationHandle)operation) != TEE_SUCCESS));
    if (check) {
        tloge("The params is invalid");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    if (crypto_lock_operation(operation) != TEE_SUCCESS)
        return;

    ret = digest_operation_state_check((const TEE_OperationHandle)operation);
    if (ret != TEE_SUCCESS) {
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return;
    }

    ret = proc_hal_digest_update(operation, chunk, chunkSize);
    if (ret != TEE_SUCCESS) {
        tloge("Do digest update failed, ret=0x%x\n", ret);
        operation->handleState &= ~TEE_HANDLE_FLAG_INITIALIZED;
        crypto_unlock_operation(operation);
        TEE_Panic(ret);
        return;
    }
    crypto_unlock_operation(operation);
}

