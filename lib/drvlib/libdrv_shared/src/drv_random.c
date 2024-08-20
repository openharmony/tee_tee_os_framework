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
#include "drv_random.h"
#include <priorities.h>
#include "tee_log.h"

static crypto_drv_init g_rand = 0;
static void *g_crypto_ops = NULL;

void register_crypto_rand_driver(crypto_drv_init fun, void *ops)
{
    g_rand = fun;
    g_crypto_ops = ops;
}

intptr_t rand_update(void *msg, cref_t *p_msg_hdl, struct src_msginfo *info)
{
    (void)msg;
    (void)p_msg_hdl;
    (void)info;
    return 0;
}
