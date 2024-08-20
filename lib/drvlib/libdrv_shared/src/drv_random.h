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
#ifndef DRVMGR_SRC_DRV_RANDOM_H
#define DRVMGR_SRC_DRV_RANDOM_H

#include <stdint.h>
#include <tee_defines.h>
#include <errno.h>
#include <ipclib.h>

typedef int32_t (*crypto_drv_init) (const void *ops, void *buf, uint32_t buf_len);
void register_crypto_rand_driver(crypto_drv_init fun, void *ops);
intptr_t rand_update(void *msg, cref_t *p_msg_hdl, struct src_msginfo *info);
#endif
