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
#include <pthread.h>
#include <mem_ops.h>
#include "tee_defines.h"
#include "ta_framework.h"
#include "tee_log.h"
#include "securec.h"
#include "ipclib.h"
#include "permsrv_api_imp.h"
#include "tee_internal_task_pub.h"
#include "tee_inner_uuid.h"

#define PERM_PATH        "permservice"
static uint32_t g_init_state = INIT_STATE_NOT_READY;
static pthread_mutex_t g_msg_call_mutex = PTHREAD_MUTEX_INITIALIZER;
static TEE_UUID g_permsrv_uuid = TEE_SERVICE_PERM;

int perm_srv_msg_call(const char *path, perm_srv_req_msg_t *msg, perm_srv_reply_msg_t *rsp)
{
    errno_t rc;
    cref_t rslot = 0;

    if (path == NULL || msg == NULL) {
        tloge("path or msg is null\n");
        return -1;
    }

    if (pthread_mutex_lock(&g_msg_call_mutex) != 0) {
        tloge("perm msg call mutex lock failed\n");
        return -1;
    }
    rc = ipc_get_ch_from_path(path, &rslot);
    if (rc == -1) {
        tloge("permsrv: get channel from pathmgr failed\n");
        (void)pthread_mutex_unlock(&g_msg_call_mutex);
        return rc;
    }

    if (rsp == NULL)
        rc = ipc_msg_notification(rslot, msg, sizeof(*msg));
    else
        rc = ipc_msg_call(rslot, msg, sizeof(*msg), rsp, sizeof(*rsp), -1);
    if (rc < 0)
        tloge("msg send 0x%llx failed: 0x%x\n", rslot, rc);

    (void)ipc_release_from_path(path, rslot);
    (void)pthread_mutex_unlock(&g_msg_call_mutex);
    return rc;
}

void tee_perm_init_msg(perm_srv_req_msg_t *req_msg, perm_srv_reply_msg_t *reply_msg)
{
    if (req_msg != NULL)
        (void)memset_s(req_msg, sizeof(*req_msg), 0, sizeof(*req_msg));

    if (reply_msg != NULL)
        (void)memset_s(reply_msg, sizeof(*reply_msg), 0, sizeof(*reply_msg));
}

void permsrv_registerta(const TEE_UUID *uuid, uint32_t task_id, uint32_t user_id, uint32_t opt_type)
{
    perm_srv_req_msg_t req_msg;

    tee_perm_init_msg(&req_msg, NULL);
    if (uuid == NULL) {
        tloge("register TA with NULL uuid\n");
        return;
    }

    if (opt_type == REGISTER_TA) {
        req_msg.header.send.msg_id = TEE_TASK_OPEN_TA_SESSION;
    } else if (opt_type == UNREGISTER_TA) {
        req_msg.header.send.msg_id = TEE_TASK_CLOSE_TA_SESSION;
    } else {
        tloge("perm srv not support operation type!\n");
        return;
    }

    req_msg.req_msg.reg_ta.uuid   = *uuid;
    req_msg.req_msg.reg_ta.taskid = task_id;
    req_msg.req_msg.reg_ta.userid = user_id;

    if (perm_srv_msg_call(PERM_PATH, &req_msg, NULL) < 0)
        tloge("register ta msg send failed!\n");
}

void permsrv_notify_unload_ta(const TEE_UUID *uuid)
{
    perm_srv_req_msg_t req_msg;

    tee_perm_init_msg(&req_msg, NULL);
    if (uuid == NULL) {
        tloge("uuid is NULL\n");
        return;
    }

    req_msg.header.send.msg_id     = TEE_TASK_RELEASE_TA_SERVICE;
    req_msg.req_msg.ta_unload.uuid = *uuid;

    if (perm_srv_msg_call(PERM_PATH, &req_msg, NULL) < 0)
        tloge("ta unload msg send failed!\n");
}

TEE_Result rslot_file_msg_call(perm_srv_req_msg_t *req_msg, perm_srv_reply_msg_t *reply_msg)
{
    if (req_msg == NULL || reply_msg == NULL) {
        tloge("req_msg or reply_msg is null!\n");
        return TEE_ERROR_GENERIC;
    }

    if (perm_srv_msg_call(PERMSRV_FILE_OPT, req_msg, reply_msg) < 0) {
        tloge("msg send failed!\n");
        return TEE_ERROR_GENERIC;
    }

    tlogd("msg call ret is 0x%x\n", reply_msg->reply.ret);
    return reply_msg->reply.ret;
}

TEE_Result tee_crl_cert_process(const char *crl_cert, uint32_t crl_cert_size)
{
    perm_srv_req_msg_t req_msg;
    perm_srv_reply_msg_t reply_msg;

    uint8_t *crl_shared = NULL;
    uint32_t crl_size;

    tee_perm_init_msg(&req_msg, &reply_msg);
    errno_t rc;
    TEE_Result ret = TEE_ERROR_GENERIC;

    if (crl_cert == NULL) {
        tloge("bad parameter for points\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (crl_cert_size == 0 || crl_cert_size > MAX_PERM_SRV_BUFF_SIZE) {
        tloge("bad parameter for size!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    crl_size   = crl_cert_size;
    crl_shared = alloc_sharemem_aux(&g_permsrv_uuid, crl_size);
    if (crl_shared == NULL) {
        tloge("malloc sharedBuff failed, size=0x%x\n", crl_size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    rc = memmove_s(crl_shared, crl_size, crl_cert, crl_cert_size);
    if (rc != EOK) {
        tloge("copy the conf error, rc = 0x%x", rc);
        ret = TEE_ERROR_SECURITY;
        goto clean;
    }

    req_msg.header.send.msg_id             = PERMSRV_SET_CRL_CERT;
    req_msg.req_msg.crl_cert.crl_cert_buff = (uintptr_t)crl_shared;
    req_msg.req_msg.crl_cert.crl_cert_size = crl_size;
    reply_msg.reply.ret                    = TEE_ERROR_GENERIC;

    ret = rslot_file_msg_call(&req_msg, &reply_msg);

clean:
    if (crl_shared != NULL)
        (void)free_sharemem(crl_shared, crl_size);
    return ret;
}

void permsrv_load_file(void)
{
    perm_srv_req_msg_t req_msg;

    tee_perm_init_msg(&req_msg, NULL);
    req_msg.header.send.msg_id = TEE_TASK_LOAD_CRL_AND_CTRL_LIST;

    if (g_init_state == INIT_STATE_READY)
        return;

    if (perm_srv_msg_call(PERMSRV_FILE_OPT, &req_msg, NULL) < 0) {
        tloge("register ta msg failed!\n");
        return;
    }

    g_init_state = INIT_STATE_READY;
}

TEE_Result permsrv_elf_verify(const void *verify_req, uint32_t len)
{
    errno_t rc;
    perm_srv_req_msg_t req_msg;

    if (verify_req == NULL) {
        tloge("elf verify req is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (len != sizeof(req_msg.req_msg.verify_req)) {
        tloge("elf verify req len %u is invalid\n", len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tee_perm_init_msg(&req_msg, NULL);
    req_msg.header.send.msg_id = TEE_TASK_ELF_VERIFY;
    req_msg.header.send.msg_size = len;

    rc = memcpy_s(&(req_msg.req_msg.verify_req), sizeof(req_msg.req_msg.verify_req), verify_req, len);
    if (rc != EOK) {
        tloge("copy verify req msg failed: 0x%x\n", rc);
        return TEE_ERROR_GENERIC;
    }

    if (perm_srv_msg_call(PERMSRV_ASYNC_OPT, &req_msg, NULL) < 0) {
        tloge("elf verify msg failed!\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}
