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

#ifndef TEE_CRYPTO_COMMON_HASH_H
#define TEE_CRYPTO_COMMON_HASH_H

#include "tee_crypto_api.h"
TEE_Result digest_operation_state_check(const TEE_OperationHandle operation);
TEE_Result proc_hal_digest_init(TEE_OperationHandle operation);
TEE_Result proc_hal_digest_update(TEE_OperationHandle operation, const void *chunk, size_t chunk_size);
#endif

