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
#ifndef CRYPTO_SYSCALL_AE_H
#define CRYPTO_SYSCALL_AE_H

#include "crypto_syscall_common.h"

int32_t ae_init_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops);
int32_t ae_update_aad_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops);
int32_t ae_update_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops);
int32_t ae_enc_final_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops);
int32_t ae_dec_final_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops);

#endif
