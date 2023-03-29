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
#include "perm_srv_ta_crl_cmd.h"
#include <tee_log.h>
#include "tee_mem_mgmt_api.h" /* TEE_Malloc */
#include "perm_srv_ta_crl.h"
#include "perm_srv_common.h"

TEE_Result perm_srv_set_crl_cert(const perm_srv_req_msg_t *msg, uint32_t sndr_taskid,
                                 const TEE_UUID *sndr_uuid, perm_srv_reply_msg_t *rsp)
{
    uint32_t msg_size;
    TEE_Result ret;
    uint8_t *msg_buff = NULL;

    (void)sndr_uuid;

    if (rsp == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (msg == NULL) {
        rsp->reply.ret = TEE_ERROR_BAD_PARAMETERS;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (msg->req_msg.crl_cert.crl_cert_size > MAX_PERM_SRV_BUFF_SIZE) {
        rsp->reply.ret = TEE_ERROR_BAD_PARAMETERS;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    msg_size = msg->req_msg.crl_cert.crl_cert_size;
    msg_buff = TEE_Malloc(msg_size, 0);
    if (msg_buff == NULL) {
        tloge("Failed to malloc buffer for crl message\n");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto clean;
    }

    ret = perm_srv_get_buffer(msg->req_msg.crl_cert.crl_cert_buff, msg_size, sndr_taskid, msg_buff, msg_size);
    if (ret != TEE_SUCCESS)
        goto clean;

    ret = perm_srv_ta_crl_cert_process(msg_buff, msg_size);

clean:
    rsp->reply.ret = ret;
    TEE_Free(msg_buff);
    return ret;
}
