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
#ifndef _SOFT_HASH_H
#define _SOFT_HASH_H

#include <crypto_driver_adaptor.h>

int32_t soft_crypto_hash_init(struct ctx_handle_t *ctx);

int32_t soft_crypto_hash_update(struct ctx_handle_t *ctx, const struct memref_t *data_in);

int32_t soft_crypto_hash_dofinal(struct ctx_handle_t *ctx, struct memref_t *data_out);

int32_t soft_crypto_hash(uint32_t alg_type, const struct memref_t *data_in, struct memref_t *data_out);

#endif
