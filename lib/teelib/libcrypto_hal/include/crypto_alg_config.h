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
#ifndef CRYPTO_ALG_CONFIG_H
#define CRYPTO_ALG_CONFIG_H

#include <tee_defines.h>

bool crypto_check_alg_valid(uint32_t alg, uint32_t mode);
uint32_t crypto_get_op_class(uint32_t alg);
TEE_Result crypto_check_keysize(uint32_t algorithm, uint32_t max_key_size);
bool crypto_check_keytype_valid(uint32_t algo, uint32_t type);
bool crypto_check_alg_supported(uint32_t alg, uint32_t element);
bool crypto_object_type_supported(uint32_t object_type);
TEE_Result check_if_unsafe_alg(uint32_t alg, uint32_t key_size);
TEE_Result check_if_unsafe_type(uint32_t obj_type, uint32_t key_size);
#endif
