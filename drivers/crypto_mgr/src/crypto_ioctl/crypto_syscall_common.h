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
#ifndef CRYPTO_SYSCALL_COMMON_H
#define CRYPTO_SYSCALL_COMMON_H

#include "crypto_driver_adaptor.h"
#include "crypto_mgr_syscall.h"
#include "crypto_driver_adaptor_ops.h"

bool check_hal_params_is_invalid(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops);
int32_t do_power_on(const struct crypto_drv_ops_t *ops);
void do_power_off(const struct crypto_drv_ops_t *ops);
uint32_t change_pkcs5_to_nopad(uint32_t alg_type);
int32_t fill_share_mem(uint8_t *shared_buf, const struct memref_t *fill_data, uint32_t fill_data_count);
void driver_free_share_mem_and_buf_arg(void *buf1, uint32_t buf1_size, void *buf2, uint32_t buf2_size);
int32_t prepare_hard_engine_params(uint32_t taskid, uint8_t **share_buf,
    struct memref_t **buf_arg, struct crypto_ioctl *ioctl_args);
int32_t restore_attrs(struct asymmetric_params_t *asymmetric_params, const struct memref_t *crypto_arg);
int32_t get_ctx_size_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops);
int32_t ctx_copy_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops);
int32_t get_driver_ability_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops);
int32_t check_alg_support_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops);
#endif
