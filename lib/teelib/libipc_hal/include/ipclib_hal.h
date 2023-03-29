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
#ifndef IPC_LIB_HAL_H
#define IPC_LIB_HAL_H

#include <ipclib.h>

#define MSG_TYPE_INVALID         0
#define MSG_TYPE_NOTIF           1
#define MSG_TYPE_CALL            2

/* Create a IPC channel and register it to the mgr with path "$PID" */
int32_t ipc_create_single_channel(const char *name, cref_t *pch, bool reg_pid, bool reg_name, bool reg_tamgr);

int32_t ipc_create_channel_native(const char *name, cref_t *pch);

uint32_t ipc_send_msg_sync(uint32_t msg_id, uint32_t dest_pid, const void *msgp, uint32_t size);

/* send uw_msg_id use uc_dst_qid channel */
uint32_t ipc_msg_qsend(uint32_t uw_msg_id, taskid_t uw_dst_pid, uint8_t uc_dst_qid);

/* send msgp use 0 channel */
uint32_t ipc_msg_snd(uint32_t uw_msg_id, uint32_t uw_dst_pid, const void *msgp, uint16_t size);

uint32_t ipc_msg_rcv(uint32_t uw_timeout, uint32_t *puw_msg_id, void *msgp, uint16_t size);

uint32_t ipc_msg_rcv_safe(uint32_t uw_timeout, uint32_t *puw_msg_id, void *msgp, uint16_t size, taskid_t wait_sender);

uint32_t ipc_msg_rcv_a(uint32_t uw_timeout, uint32_t *puw_msg_id, void *msgp, uint16_t size, taskid_t *puw_sender_pid);

uint32_t ipc_msg_q_recv(uint32_t *puw_msg_id, taskid_t *puw_sender_pid,
                        uint8_t uc_recv_qid, uint32_t uw_timeout);

#endif
