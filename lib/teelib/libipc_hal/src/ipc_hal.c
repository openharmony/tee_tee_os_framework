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
#include <ipclib.h>
#include <ipclib_hal.h>
#include <tee_log.h>
#include <securec.h>

#define MSG_MAX_LEN     512 /* same as GT_MSG_REV_SIZE */
#define GLOBAL_HANDLE     0 /* defined in tee_init.h */
#define GLOBAL_SERVICE_NAME "TEEGlobalTask"

struct msg_st {
    uint32_t msg_id;
    char payload[MSG_MAX_LEN];
} __attribute__((__packed__));

struct msgsent_st {
    cref_t dst_ch;
    uint32_t uw_msg_id;
    taskid_t uw_dst_pid;
    const void *msgp;
    uint16_t size;
} __attribute__((__packed__));

struct msgrcv_st {
    cref_t ch;
    cref_t timer;
    int32_t timeout;
    uint32_t *puw_msg_id;
    void *msgp;
    uint16_t size;
    taskid_t *puw_sender_pid;
} __attribute__((__packed__));

struct notify_st {
    uint32_t msg_id;
    char payload[NOTIFY_MAX_LEN];
} __attribute__((__packed__));

struct reply_msg_st {
    uint32_t status;
} __attribute__((__packed__));

static taskid_t g_handle = SRE_PID_ERR;
static int32_t global_handle_check(taskid_t *puw_dst_pid)
{
    if (puw_dst_pid == NULL)
        return -EINVAL;

    if (*puw_dst_pid == GLOBAL_HANDLE) {
        if (g_handle == SRE_PID_ERR) {
            if (ipc_hunt_by_name(GLOBAL_SERVICE_NAME, &g_handle) != 0)
                return -1;
        }
        *puw_dst_pid = g_handle;
    }
    return 0;
}

int32_t ipc_create_single_channel(const char *name, cref_t *pch, bool reg_pid, bool reg_name, bool reg_tamgr)
{
    struct reg_items_st reg_items;
    reg_items.reg_pid   = reg_pid;
    reg_items.reg_name  = reg_name;
    reg_items.reg_tamgr = reg_tamgr;
    return ipc_create_channel(name, 1, &pch, reg_items);
}

int32_t ipc_create_channel_native(const char *name, cref_t *pch)
{
    return ipc_create_single_channel(name, pch, false, true, false);
}

static uint32_t ipc_msgsnd_core(struct msgsent_st msgsent)
{
    int32_t rc    = 0;
    struct msg_st msg = { 0 };

    msg.msg_id = msgsent.uw_msg_id;

    if (msgsent.msgp != NULL) {
        if (memcpy_s(msg.payload, sizeof(msg.payload), msgsent.msgp, msgsent.size) != 0)
            return SRE_IPC_ERR;
    }

    if (msgsent.size <= NOTIFY_MAX_LEN) {
        struct notify_st *ntf_p = (struct notify_st *)&msg;
        rc                         = ipc_msg_notification(msgsent.dst_ch, ntf_p, sizeof(struct notify_st));
    } else {
        tloge("msg_call failed, not support big msg in ipc_msg_snd/ipc_msg_qsnd, size = %u\n", msgsent.size);
        return SRE_IPC_ERR;
    }

    if (rc != 0) {
        tloge("notify failed to 0x%x, size=%u, ret=%d\n", msg.msg_id, msgsent.size, rc);
        return SRE_IPC_ERR;
    }

    return 0;
}

static uint32_t ipc_msgsnd_core_sync(struct msgsent_st msgsent)
{
    int32_t rc;
    struct msg_st msg     = { 0 };
    struct reply_msg_st rmsg = { 0 };

    msg.msg_id = msgsent.uw_msg_id;

    if (msgsent.msgp != NULL) {
        if (memcpy_s(msg.payload, sizeof(msg.payload), msgsent.msgp, msgsent.size) != 0)
            return SRE_IPC_ERR;
    }

    rc = ipc_msg_call(msgsent.dst_ch, &msg, sizeof(msg), &rmsg, sizeof(rmsg), -1);
    if (rc != 0) {
        tloge("msg_call to 0x%x failed, rc = %d\n", msgsent.uw_dst_pid, rc);
        return SRE_IPC_ERR;
    }

    return 0;
}

uint32_t ipc_msg_snd(uint32_t uw_msg_id, taskid_t uw_dst_pid, const void *msgp, uint16_t size)
{
    cref_t dst_ch;
    struct msgsent_st msgsent;
    int32_t rc;
    tlogd("MsgSend Start to 0x%x msgid = 0x%lx size = %u\n", uw_dst_pid, uw_msg_id, size);

    if (size > MSG_MAX_LEN) {
        tloge("msg too long!\n");
        return SRE_IPC_ERR;
    }

    if (global_handle_check(&uw_dst_pid) != 0) {
        tloge("check uwDstPID against global handle failed\n");
    }

    rc =  ipc_get_ch_from_taskid(uw_dst_pid, 0, &dst_ch);
    if (rc != 0) {
        tloge("Cannot get dest channel, MsgSnd abort to 0x%x\n", uw_dst_pid);
        return SRE_IPC_ERR;
    }

    msgsent.dst_ch     = dst_ch;
    msgsent.uw_msg_id  = uw_msg_id;
    msgsent.uw_dst_pid = uw_dst_pid;
    msgsent.msgp       = msgp;
    msgsent.size       = size;
    return ipc_msgsnd_core(msgsent);
}

uint32_t ipc_send_msg_sync(uint32_t msg_id, taskid_t dest_pid, const void *msgp, uint32_t size)
{
    cref_t dst_ch;
    struct msgsent_st msgsent;
    int32_t rc;

    if (global_handle_check(&dest_pid) != 0) {
        tloge("check uwDstPID against global handle failed\n");
    }

    rc = ipc_get_ch_from_taskid(dest_pid, 0, &dst_ch);
    if (rc != 0) {
        tloge("Cannot get dest channel of pid(0x%x)\n", dest_pid);
        return SRE_IPC_ERR;
    }

    msgsent.dst_ch     = dst_ch;
    msgsent.uw_msg_id  = msg_id;
    msgsent.uw_dst_pid = dest_pid;
    msgsent.msgp       = msgp;
    msgsent.size       = size;
    return ipc_msgsnd_core_sync(msgsent);
}

uint32_t ipc_msg_rcv(uint32_t uw_timeout, uint32_t *puw_msg_id, void *msgp, uint16_t size)
{
    taskid_t sender_pid;
    return ipc_msg_rcv_a(uw_timeout, puw_msg_id, msgp, size, &sender_pid);
}

uint32_t ipc_msg_rcv_safe(uint32_t uw_timeout, uint32_t *puw_msg_id, void *msgp, uint16_t size, taskid_t wait_sender)
{
    taskid_t sender = SRE_PID_ERR;
    uint32_t ret     = 0;

    while (wait_sender != sender) {
        ret = ipc_msg_rcv_a(uw_timeout, puw_msg_id, msgp, (uint16_t)(size), &sender);
        if (ret != 0) {
            tloge("ipc msg Rcv failed, ret = 0x%x\n", ret);
            return ret;
        }

        if (wait_sender != sender)
            tloge("recv msg from wrong sender %u/%u\n", sender, wait_sender);
    }

    return ret;
}

static uint32_t ipc_msgrcv_core(struct msgrcv_st msgrcv)
{
    struct msg_st msg;
    struct reply_msg_st rmsg;
    struct src_msginfo info = { 0 };
    int32_t msg_ret;

    /* ipc_msg_receive would handle wrong msg_hdl */
    cref_t msg_hdl = ipc_get_my_msghdl();

    msg_ret = ipc_msg_receive(msgrcv.ch, &msg, sizeof(msg), msg_hdl, &info, msgrcv.timeout);
    if (msg_ret != 0) {
        tloge("receive msg failed: %x\n", msg_ret);
        return msg_ret == E_EX_TIMER_TIMEOUT ? SRE_IPC_TIMEOUT_ERR : SRE_IPC_ERR;
    }

    if (msgrcv.puw_msg_id != NULL)
        *(msgrcv.puw_msg_id) = msg.msg_id;
    if (msgrcv.puw_sender_pid != NULL) {
        if (info.src_pid == GLOBAL_HANDLE)
            *(msgrcv.puw_sender_pid) = GLOBAL_HANDLE;
        else
            *(msgrcv.puw_sender_pid) = (uint32_t)pid_to_taskid(info.src_tid, info.src_pid);
    }
    if (msgrcv.msgp != NULL) {
        if (memcpy_s(msgrcv.msgp, msgrcv.size, msg.payload,
                     msgrcv.size < MSG_MAX_LEN ? msgrcv.size : MSG_MAX_LEN) != EOK) {
            tloge("memcpy_s failed\n");
            return SRE_IPC_ERR;
        }
    }

    if (info.msg_type == MSG_TYPE_CALL) {
        int32_t rc  = ipc_msg_reply(msg_hdl, &rmsg, sizeof(rmsg));
        if (rc < 0) {
            tloge("reply msg error %d\n", rc);
            return SRE_IPC_ERR;
        }
    } else if (info.msg_type == MSG_TYPE_NOTIF) {
        tlogd("Notification received, DONOT need to reply ch = 0x%llx\n", msg_hdl);
    } else {
        tloge("Unexpected msg_recv %u\n", info.msg_type);
        return SRE_IPC_ERR;
    }

    return 0;
}

uint32_t ipc_msg_rcv_a(uint32_t uw_timeout, uint32_t *puw_msg_id, void *msgp, uint16_t size, taskid_t *puw_sender_pid)
{
    cref_t ch;
    uint32_t ret;
    struct msgrcv_st msgrcv;
    if (size > MSG_MAX_LEN) {
        tloge(" msg too long!\n");
        return SRE_IPC_ERR;
    }

    ret = ipc_get_my_channel(0, &ch);
    if (ret != 0) {
        tloge("Cannot recv, channel haven't been created yet\n");
        return SRE_IPC_NO_CHANNEL_ERR;
    }

    msgrcv.ch             = ch;
    msgrcv.timeout        = (int32_t)uw_timeout;
    msgrcv.puw_msg_id     = puw_msg_id;
    msgrcv.msgp           = msgp;
    msgrcv.size           = size;
    msgrcv.puw_sender_pid = puw_sender_pid;
    ret = ipc_msgrcv_core(msgrcv);

    tlogd("MsgRcv OK: 0x%x <- 0x%x msgid = 0x%x, size = %u\n", get_self_taskid(), puw_sender_pid ? *puw_sender_pid : 0,
             puw_msg_id ? *puw_msg_id : DEAD_MSG_ID, (uint32_t)size);

    return ret;
}

uint32_t ipc_msg_qsend(uint32_t uw_msg_id, taskid_t uw_dst_pid, uint8_t uc_dst_qid)
{
    cref_t dst_ch;
    struct msgsent_st msgsent;
    int32_t rc;
    tlogd("MsgQSend to 0x%x ch = %u\n", uw_dst_pid, uc_dst_qid);

    if (uc_dst_qid >= CH_CNT_MAX) {
        tloge("Send channel Number overflow: %u\n", uc_dst_qid);
        return SRE_IPC_ERR;
    }

    if (global_handle_check(&uw_dst_pid) != 0) {
        tloge("check uwDstPID against global handle failed\n");
    }

    rc = ipc_get_ch_from_taskid(uw_dst_pid, uc_dst_qid, &dst_ch);
    if (rc != 0) {
        tloge("Cannot get dest channel, MsgSnd abort to 0x%x\n", uw_dst_pid);
        return SRE_IPC_ERR;
    }
    msgsent.dst_ch     = dst_ch;
    msgsent.uw_msg_id  = uw_msg_id;
    msgsent.uw_dst_pid = uw_dst_pid;
    msgsent.msgp       = NULL;
    msgsent.size       = 0;
    return ipc_msgsnd_core(msgsent);
}

uint32_t ipc_msg_q_recv(uint32_t *puw_msg_id, taskid_t *puw_sender_pid,
                        uint8_t uc_recv_qid, uint32_t uw_timeout)
{
    cref_t ch;
    uint32_t ret;
    struct msgrcv_st msgrcv;
    if (uc_recv_qid >= CH_CNT_MAX) {
        tloge("Recv channel Number overflow: %d\n", uc_recv_qid);
        return SRE_IPC_ERR;
    }

    ret = ipc_get_my_channel(uc_recv_qid, &ch);
    if (ret != 0) {
        tloge("Cannot recv, channel haven't been created yet\n");
        return SRE_IPC_NO_CHANNEL_ERR;
    }

    msgrcv.ch             = ch;
    msgrcv.timeout        = (int32_t)uw_timeout;
    msgrcv.puw_msg_id     = puw_msg_id;
    msgrcv.msgp           = NULL;
    msgrcv.size           = 0;
    msgrcv.puw_sender_pid = puw_sender_pid;
    ret = ipc_msgrcv_core(msgrcv);

    tlogd("MsgQRcv OK: 0x%x <- 0x%x msgid = 0x%x\n", get_self_taskid(), puw_sender_pid ? *puw_sender_pid : 0,
             puw_msg_id ? *puw_msg_id : DEAD_MSG_ID);

    return ret;
}
