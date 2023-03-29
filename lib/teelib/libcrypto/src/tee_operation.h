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

#ifndef SRC_TEE_TEE_OPERATION_H
#define SRC_TEE_TEE_OPERATION_H

#include "tee_crypto_api.h"

TEE_Result add_operation(TEE_OperationHandle operation);
void delete_operation(const TEE_OperationHandle operation);
TEE_Result check_operation(const TEE_OperationHandle operation);

#endif
