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
#include <cs.h>
#include <ipclib_hal.h>
#include <tee_log.h>
#include <securec.h>
#include <drv.h>

static int do_deal_with_msg(const dispatch_fn_t dispatch_fns[], unsigned n_dispatch_fns, void *msg_buff,
                            struct src_msginfo *info, cref_t *msg_hdl)
{
    msg_header *msg_hdr = (msg_header *)(uintptr_t)msg_buff;
    uint8_t class = msg_hdr->send.msg_class;
    struct reply_cs_msg rmsg;
    int32_t ret = 0;
    (void)memset_s(&rmsg, sizeof(rmsg), 0, sizeof(rmsg));
    
    bool flag = (class >= n_dispatch_fns) || (dispatch_fns[class] == NULL);
    if (flag) {
        rmsg.hdr.reply.ret_val = -EINVAL;
        if (info->msg_type == MSG_TYPE_CALL) {
            ret = ipc_msg_reply(*msg_hdl, &rmsg, sizeof(rmsg));
            if (ret != 0)
                tloge("cs reply msg error %d\n", ret);
        }
    } else {
        ret = dispatch_fns[class](msg_buff, msg_hdl, info);
    }
    return ret;
}

void cs_server_loop(cref_t channel, const dispatch_fn_t dispatch_fns[], unsigned n_dispatch_fns, int (*hook)(void), void *cur_thread)
{
    (void)hook;
    (void)cur_thread;
    int32_t ret;
    char msg_buf[SYSCAL_MSG_BUFFER_SIZE] = {0};
    struct cs_req_msg *msg = (struct cs_req_msg *)msg_buf;
    struct src_msginfo info = { 0 };
    for (;;) {
        cref_t msg_hdl = ipc_get_my_msghdl();

        ret = ipc_msg_receive(channel, msg, sizeof(msg_buf), msg_hdl, &info, -1);
        if (ret != 0) {
            tloge("message receive failed, %llx\n", ret);
            continue;
        }
        
        ret = do_deal_with_msg(dispatch_fns, n_dispatch_fns, msg, &info, &msg_hdl);
        if (ret != 0) {
            tloge("deal with msg error");
        }
    }
}