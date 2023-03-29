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
#ifndef DRIVER_SRE_MSG_H
#define DRIVER_SRE_MSG_H
#include <ipclib.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cpluscplus */
#endif /* __cpluscplus */

/*
 * legacy msg function, not support anymore
 * should use "__SRE_MsgQSend" instead
 */
uint32_t ipc_msg_qsend(uint32_t uw_msg_id, uint32_t uw_dst_pid, uint8_t uc_dst_qid);

/*
 * legacy msg function, not support anymore
 * should use "__SRE_MsgQRecv" instead
 */
uint32_t ipc_msg_q_recv(uint32_t *puw_msg_id, uint32_t *puw_sender_pid, uint8_t uc_recv_qid,
                        uint32_t uw_timeout);

/*
 * legacy msg function, not support anymore
 * should use "__SRE_MsgSnd" instead
 */
uint32_t ipc_msg_snd(uint32_t uw_msg_id, uint32_t uw_dst_pid, const void *msgp, uint16_t size);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#endif /* DRIVER_SRE_MSG_H */
