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
#include <rnd_seed.h>
#include <priorities.h>
#include <fileio.h>
#include "tee_log.h"

static crypto_drv_init g_rand = 0;
static void *g_crypto_ops = NULL;

void register_crypto_rand_driver(crypto_drv_init fun, void *ops)
{
    g_rand = fun;
    g_crypto_ops = ops;
}

static int32_t drv_push_random(struct hmcap_message_info *info)
{
    int32_t ret;
    uint64_t rnd[PUSHED_RND_64_NUM] = { 0 };

    if (info == NULL || g_rand == 0 || g_crypto_ops == NULL) {
        tloge("invalid args or fun is not register\n");
        return -1;
    }

    ret = g_rand(g_crypto_ops, rnd, sizeof(rnd));
    if (ret != 0) {
        tloge("gen random failed\n");
        return ret;
    }

    return push_random(info, rnd, sizeof(rnd));
}

intptr_t rand_update(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info)
{
    int32_t ret;

    if (p_msg_hdl == NULL || msg == NULL || info == NULL)
        return -1;

    cref_t msg_hdl = *p_msg_hdl;
    msg_header *msg_hdr = (msg_header *)msg;

    switch (msg_hdr->send.msg_id) {
    case HM_MSG_ID_DRV_PUSHED_RANDOM:
        ret = drv_push_random(info);
        break;
    default:
        ret = reply_invalid_rand_request(msg_hdl);
        break;
    }

    return (intptr_t)ret;
}
