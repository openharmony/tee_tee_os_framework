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

#include "rpmb_driver_rw_api.h"

TEE_Result tee_ext_rpmb_protect_cfg_blk_write(uint8_t lun, struct rpmb_protect_cfg_blk_entry *entries, uint32_t len)
{
    (void)lun;
    (void)entries;
    (void)len;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_rpmb_protect_cfg_blk_read(uint8_t lun, struct rpmb_protect_cfg_blk_entry *entries, uint32_t *len)
{
    (void)lun;
    (void)entries;
    (void)len;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_rpmb_driver_write(const uint8_t *buf, size_t size, uint32_t block, uint32_t offset)
{
    (void)buf;
    (void)size;
    (void)block;
    (void)offset;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_rpmb_driver_read(uint8_t *buf, size_t size, uint32_t block, uint32_t offset)
{
    (void)buf;
    (void)size;
    (void)block;
    (void)offset;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_rpmb_driver_remove(size_t size, uint32_t block, uint32_t offset)
{
    (void)size;
    (void)block;
    (void)offset;
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result tee_ext_rpmb_format()
{
    return TEE_ERROR_NOT_SUPPORTED;
}